package integration

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Engine is a helper for managing a postgres engine.
type Engine struct {
	DSN     string
	binroot string
	port    string
	dataDir string
}

func (e *Engine) init(t testing.TB) {
	embedDB.FetchArchive(t)
	d := embedDB.Realpath(t)
	if _, err := os.Stat(d); err != nil {
		t.Error(err)
	}
	e.binroot = filepath.Join(d, "bin")
	t.Logf("using binaries at %q", e.binroot)

	e.port = strconv.Itoa((os.Getpid() % 10000) + 30000)
	var dsn strings.Builder
	dsn.WriteString("host=localhost user=postgres password=securepassword sslmode=disable port=")
	dsn.WriteString(e.port)
	e.DSN = dsn.String()
	t.Logf("using port %q", e.port)

	e.dataDir = filepath.Join(PackageCacheDir(t), "pg"+embedDB.RealVersion)
	if _, err := os.Stat(e.dataDir); err == nil {
		t.Log("data directory exists, skipping initdb")
		// Should be set up already.
		return
	}
	t.Logf("using data directory %q", e.dataDir)
	pwfile := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(pwfile, []byte(`securepassword`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(e.dataDir), 0o755); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(e.dataDir + ".initdb")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	t.Logf("log at %q", log.Name())

	cmd := exec.Command(filepath.Join(e.binroot, "initdb"),
		"--encoding=UTF8",
		"--auth=password",
		"--username=postgres",
		"--pgdata="+e.dataDir,
		"--pwfile="+pwfile,
	)
	cmd.Stdout = log
	cmd.Stderr = log
	t.Logf("running %v", cmd.Args)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

// Start configures and starts the database engine.
//
// This should not be called multiple times.
func (e *Engine) Start(t testing.TB) error {
	e.init(t)
	logfile := filepath.Join(e.dataDir, "log")
	if err := os.Truncate(logfile, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	opts := []string{
		"-w",
		"-s",
		"-D", e.dataDir,
		"-l", logfile,
		"-o", fmt.Sprintf("-F -p %s", e.port),
	}
	if testing.Verbose() {
		t.Logf("enabling EXPLAIN output to: %s", logfile)
		opts = append(opts,
			"-o", "-c session_preload_libraries=auto_explain",
			"-o", "-c auto_explain.log_min_duration=0",
			"-o", "-c auto_explain.log_analyze=true",
			"-o", "-c auto_explain.log_buffers=true",
			"-o", "-c auto_explain.log_wal=true",
			"-o", "-c auto_explain.log_verbose=true",
			"-o", "-c auto_explain.log_nested_statements=true",
		)
		if f := os.Getenv("PGEXPLAIN_FORMAT"); f != "" {
			opts = append(opts, "-o", fmt.Sprintf("-c auto_explain.log_format=%s", f))
		}
	}
	opts = append(opts, "start")
	cmd := exec.Command(filepath.Join(e.binroot, "pg_ctl"), opts...)
	t.Logf("starting database engine: %v", cmd.Args)
	return cmd.Run()
}

// Stop stops the database engine.
//
// It's an error to call Stop before a successful Start.
func (e *Engine) Stop() error {
	cmd := exec.Command(filepath.Join(e.binroot, "pg_ctl"),
		"-w",
		"-s",
		"-D", e.dataDir,
		"-m", "fast",
		"stop",
	)
	return cmd.Run()
}
