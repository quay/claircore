package distlock

import (
	"context"
	"log"
	"math/rand"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v4"
	"golang.org/x/sync/errgroup"
)

const (
	dsn = "host=localhost port=5434 user=distlock dbname=distlock sslmode=disable"
)

func stopDB(t testing.TB) {
	// a command to rip down postgres unexpectedly
	cmd := exec.Command(
		"/usr/bin/docker-compose",
		"down",
	)
	err := cmd.Run()
	if err != nil {
		t.Fatalf("could not rip database down: %v", err)
	}
	log.Printf("db down")
}

func startDB(t testing.TB) {
	// a command to start local postgres instance
	cmd := exec.Command(
		"/usr/bin/docker-compose",
		"up",
		"-d",
	)
	err := cmd.Run()
	if err != nil {
		t.Fatalf("failed to start the local postgres instance: %v", err)
	}
	log.Printf("db started")
}

func waitDB(t testing.TB) {
	up := false
	conf, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	for !up {
		tctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
		conn, err := pgx.ConnectConfig(tctx, conf)
		if err != nil {
			log.Printf("database not available yet")
			time.Sleep(2 * time.Second)
			continue
		}
		up = true
		conn.Close(tctx)
	}
	log.Printf("db up")
}

func pgLocksCount(t *testing.T) int {
	tctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, err := pgx.Connect(tctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	const (
		query = `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory';`
	)

	var i int
	row := conn.QueryRow(context.Background(), query)
	err = row.Scan(&i)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestManager(t *testing.T) {
	startDB(t)
	waitDB(t)

	// all tests start with database up. all tests should restore
	// db if they tear it down.

	// these use random counts, perform in a loop to maximize test effectiveness.
	for i := 0; i < 4; i++ {
		s := strconv.Itoa(i)
		t.Run("CtxParentCancelation", test_CtxParentCancelation)
		t.Run("CtxChildCancelation", test_CtxChildCancelation)
		t.Run("BasicUsage-Run-"+s, test_BasicUsage)
		t.Run("Counter-Run-"+s, test_Counter)
		t.Run("TryLockSingleSessionMutualExclusion-Run-"+s, test_TryLockSingleSessionMutualExclusion)
		t.Run("TryLockMultiSessionMutualExclusion-Run-"+s, test_TryLockMultiSessionMutualExclusion)
		t.Run("LockSingleSession-Run-"+s, test_LockSingleSession)
		t.Run("LockMultiSession-Run-"+s, test_LockMultiSession)
		t.Run("CTXCancelWhileReconnecting", test_CTXCancelWhileReconnecting)
		t.Run("DBFlap", test_DBFlap)
		t.Run("CTXCancelDBFailure", test_CTXCancelDBFailure)
	}

	stopDB(t)
}

func test_CtxParentCancelation(t *testing.T) {
	// create a manager
	mCtx, mCancel := context.WithCancel(context.Background())
	manager, err := NewManager(mCtx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	// create a parent context
	pCtx, pCancel := context.WithCancel(context.Background())

	// create lock with child ctx
	key := "test-key"
	cCtx, cancel := manager.TryLock(pCtx, key)
	if err := cCtx.Err(); err != nil {
		t.Fatal(err)
	}

	// launch go routine to cancel parent context after
	// some time
	go func() {
		time.Sleep(1 * time.Second)
		pCancel()
	}()
	// block on lock
	<-cCtx.Done()

	// call cancel to confirm its a no-op
	cancel()

	mCancel()
}

func test_CtxChildCancelation(t *testing.T) {
	// create a manager
	mCtx, mCancel := context.WithCancel(context.Background())
	manager, err := NewManager(mCtx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	// create parent ctx
	pCtx, pCancel := context.WithCancel(context.Background())

	// create lock
	lCtx, _ := manager.TryLock(pCtx, "test-key")

	// dervice two children
	ctx1, _ := context.WithCancel(lCtx)
	ctx2, _ := context.WithCancel(lCtx)

	go func() {
		time.Sleep(1 * time.Second)
		pCancel()
	}()

	// make sure none of these block
	<-lCtx.Done()
	<-ctx1.Done()
	<-ctx2.Done()

	mCancel()
}

func test_BasicUsage(t *testing.T) {
	// create a manager
	mCtx, mCancel := context.WithCancel(context.Background())
	manager, err := NewManager(mCtx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	// get a lock
	key := "test-key"
	ctx, cancel := manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}

	// launch a goroutine to return lock
	// in a bit
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	// block on ctx
	<-ctx.Done()

	// lock the same key
	ctx, cancel = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}

	// derive a ctx from new lock
	tctx, _ := context.WithTimeout(ctx, 1*time.Minute)

	// launch goroutine to cancel parent
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	// block on tctx, proves derived ctx's will work
	<-tctx.Done()

	// lock the same key
	ctx, cancel = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}

	// launch a goroutine to cancel the manager's ctx
	go func() {
		time.Sleep(500 * time.Millisecond)
		mCancel()
	}()
	// block on ctx. proves canceling manager's ctx kills locks
	<-ctx.Done()

	if i := pgLocksCount(t); i != 0 {
		t.Fatalf("%d locks still in locks table: %v", i, err)
	}
}

func test_Counter(t *testing.T) {
	// create a manager with a random limit
	max := uint64(rand.Intn(100))
	ctx, cancel := context.WithCancel(context.Background())
	manager, err := NewManager(ctx, dsn, WithMax(max))
	if err != nil {
		t.Fatal(err)
	}

	var i int
	for i = 0; i < int(max); i++ {
		key := "test-key-" + strconv.Itoa(i)
		ctx, _ := manager.TryLock(context.Background(), key)
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
	}

	i++
	key := "test-key-" + strconv.Itoa(i)
	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != ErrMaxLocks {
		t.Fatalf("got: %v want: %v", err, ErrMaxLocks)
	}
	cancel()
	// canceling ctx still takes some time to clear locks in the db,
	// sleep for a bit to make sure locks are removed.
	time.Sleep(50 * time.Millisecond)
}

func test_CTXCancelWhileReconnecting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	manager, err := NewManager(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	// tear down db
	stopDB(t)

	tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	// spin on guard reconnecting status
	for !manager.g.reconnecting.Load().(bool) {
		if tctx.Err() != nil {
			t.Fatalf("timed out waiting for reconnect loop to begin")
		}
	}

	key := "test-key"
	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != ErrDatabaseUnavailable {
		t.Fatalf("got: %v want: %v", err, ErrDatabaseUnavailable)
	}

	// cancel ctx
	cancel()

	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != ErrDatabaseUnavailable {
		t.Fatalf("got: %v want: %v", err, ErrDatabaseUnavailable)
	}

	startDB(t)
	waitDB(t)
}

func test_CTXCancelDBFailure(t *testing.T) {
	// create some locks
	keys := []string{"test-key0", "test-key1", "test-key2", "test-key3"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := NewManager(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for _, key := range keys {
		ctx, _ := manager.TryLock(context.Background(), key)
		if err := ctx.Err(); err != nil {
			t.Fatal(err)
		}
		// launch routines waiting on ctx, they should unblock when
		// we rip the database down.
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ctx.Done()
		}()
	}

	// rip database down
	stopDB(t)
	wg.Wait()

	// all routines returned from blockg on ctx.
	startDB(t)
	waitDB(t)
}

func test_DBFlap(t *testing.T) {
	// get a lock
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager, err := NewManager(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	key := "test-key"
	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}

	stopDB(t)

	// make sure we get an error trying to get a lock
	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err == nil {
		t.Fatal("expected error")
	}

	startDB(t)
	waitDB(t)

	time.Sleep(1 * time.Second)

	// make sure we dont get an error getting a lock
	ctx, _ = manager.TryLock(context.Background(), key)
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
}

func test_LockMultiSession(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	// key that will be used
	key := "test-key"

	// random goroutine count
	routines := rand.Intn(50)
	if routines <= 1 {
		routines = 2
	}
	t.Logf("testing with %d goroutines", routines)

	// keep track of which goroutines acquire a lock
	acquired := make([]bool, routines)

	// create a manager for each routine
	managers := make([]*Manager, routines)
	for i := 0; i < routines; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		mgr, err := NewManager(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		managers[i] = mgr
	}

	tctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var errGrp errgroup.Group
	for i := 0; i < routines; i++ {
		ii := i
		errGrp.Go(func() error {
			randomSleep := rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)

			ctx, cancel := managers[ii].Lock(tctx, key)
			if err := ctx.Err(); err != nil {
				return err
			}
			acquired[ii] = true

			randomSleep = rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)
			cancel()

			return nil
		})
	}
	if err := errGrp.Wait(); err != nil {
		t.Fatal(err)
	}

	acquireCount := 0
	for i, b := range acquired {
		if b {
			acquireCount++
			t.Logf("goroutine %d acquired lock", i)
		}
	}
	if acquireCount != routines {
		t.Fatalf("got: %d want: %d", acquireCount, routines)
	}

}

func test_LockSingleSession(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	// key that will be used
	key := "test-key"

	// random goroutine count
	routines := rand.Intn(50)
	if routines <= 1 {
		routines = 2
	}
	t.Logf("testing with %d goroutines", routines)

	// keep track of which goroutines acquire a lock
	acquired := make([]bool, routines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := NewManager(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	var errGrp errgroup.Group
	for i := 0; i < routines; i++ {
		ii := i
		errGrp.Go(func() error {
			randomSleep := rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)

			ctx, cancel := mgr.Lock(ctx, key)
			if err := ctx.Err(); err != nil {
				return err
			}
			acquired[ii] = true

			randomSleep = rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)
			cancel()

			return nil
		})
	}
	if err = errGrp.Wait(); err != nil {
		t.Fatal(err)
	}

	acquireCount := 0
	for i, b := range acquired {
		if b {
			acquireCount++
			t.Logf("goroutine %d acquired lock", i)
		}
	}
	if acquireCount != routines {
		t.Fatalf("got: %d want: %d", acquireCount, routines)
	}

}

func test_TryLockMultiSessionMutualExclusion(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	// key that will be used
	key := "test-key"

	// random goroutine count
	routines := rand.Intn(50)
	if routines <= 1 {
		routines = 2
	}
	t.Logf("testing with %d goroutines", routines)

	// keep track of which goroutines acquire a lock
	acquired := make([]bool, routines)

	// create a manager for each routine
	managers := make([]*Manager, routines)
	for i := 0; i < routines; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		mgr, err := NewManager(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		managers[i] = mgr
	}

	var errGrp errgroup.Group
	for i := 0; i < routines; i++ {
		ii := i
		errGrp.Go(func() error {

			randomSleep := rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)

			ctx, _ := managers[ii].TryLock(context.Background(), key)
			if err := ctx.Err(); err != nil {
				if err == ErrMutualExclusion {
					return nil
				}
				return err
			}
			acquired[ii] = true
			return nil
		})
	}
	if err := errGrp.Wait(); err != nil {
		t.Fatal(err)
	}

	acquireCount := 0
	for i, b := range acquired {
		if b {
			acquireCount++
			t.Logf("goroutine %d acquired lock", i)
		}
	}
	if acquireCount != 1 {
		t.Fatalf("got: %d want: %d", acquireCount, 1)
	}
}

func test_TryLockSingleSessionMutualExclusion(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	// key that will be used
	key := "test-key"

	// random goroutine count
	routines := rand.Intn(50)
	if routines <= 1 {
		routines = 2
	}
	t.Logf("testing with %d goroutines", routines)

	// keep track of which goroutines acquire a lock
	acquired := make([]bool, routines)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mgr, err := NewManager(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	var errGrp errgroup.Group
	for i := 0; i < routines; i++ {
		ii := i
		errGrp.Go(func() error {
			randomSleep := rand.Intn(500)
			time.Sleep(time.Duration(randomSleep) * time.Millisecond)

			ctx, _ := mgr.TryLock(context.Background(), key)
			if err := ctx.Err(); err != nil {
				if err == ErrMutualExclusion {
					return nil
				}
				return err
			}
			acquired[ii] = true
			return nil
		})
	}
	if err = errGrp.Wait(); err != nil {
		t.Fatal(err)
	}

	acquireCount := 0
	for i, b := range acquired {
		if b {
			acquireCount++
			t.Logf("goroutine %d acquired lock", i)
		}
	}
	if acquireCount != 1 {
		t.Fatalf("got: %d want: %d", acquireCount, 1)
	}
}
