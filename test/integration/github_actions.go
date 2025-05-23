package integration

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func startGithubActions(t testing.TB) func() {
	const config string = `# Installed by claircore's test harness.
fsync = off
`
	const debugConfig = `session_preload_libraries = 'auto_explain'
auto_explain.log_min_duration = 0
auto_explain.log_analyze = true
auto_explain.log_buffers = true
auto_explain.log_wal = true
`
	// GitHub Actions has Postgres installed, so we can just run some commands
	// to set it up:
	return func() {
		// On success, this function leaves [pkgDB] unset, so that the test
		// binary's teardown logic leaves it running as if it's an external
		// database. Which it is, just happening to be one that some test or
		// previous shell command started.
		defer func() {
			if t.Failed() {
				return
			}
			// Just fill out the config and it's all good to go.
			cfg, err := pgxpool.ParseConfig(`host=/var/run/postgresql user=postgres database=postgres sslmode=disable`)
			if err != nil {
				t.Fatal(err)
			}
			pkgConfig = cfg
		}()
		// See if a previous test binary already enabled the service:
		cmd := exec.Command("sudo", "systemctl", "--quiet", "is-active", "postgresql.service")
		// BUG(hank) If some other process starts "postgresql.service", it need
		// to ensure that local passwordless authentication is configured. If
		// processes after a test using this package needs any other
		// authentication setup, be aware that this package overwrites the
		// default "pg_hba.conf" with a minimal, local-only configuration.
		if err := cmd.Run(); err == nil {
			// Looking for exit 0 to indicate we don't need to do anything.
			return
		}

		// Figure out the destination path.
		ms, _ := filepath.Glob(`/etc/postgresql/*/main/conf.d`)
		sort.Strings(ms)
		confd := ms[0]
		// TODO(hank) This lock is too broad, it covers the entire test when it
		// really only needs to cover this function.
		if !lockDir(t, confd) {
			// If this process couldn't get an exclusive lock, then another
			// process configured everything and this one should be able to just
			// return here.
			return
		}

		// Lay down the config snippet into a temporary directory.
		f, err := os.Create(filepath.Join(t.TempDir(), "clair.conf"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := io.WriteString(f, config); err != nil {
			t.Fatal(err)
		}
		if testing.Verbose() {
			if _, err := io.WriteString(f, debugConfig); err != nil {
				t.Fatal(err)
			}
		}
		if exp, ok := os.LookupEnv("PGEXPLAIN_FORMAT"); ok {
			fmt.Fprintf(f, `auto_explain.log_format = %q\n`, exp)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}

		// Use sudo+install because that's just a much easier way to put a file
		// in a specific place with specific permissions.
		var buf bytes.Buffer
		cmd = exec.Command("sudo", "install", "-m", "0644", "-o", "postgres", f.Name(), confd)
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			t.Logf("running %+v: %v", cmd.Args, err)
			t.Logf("output:\n%s", buf.String())
			t.FailNow()
		}
		buf.Reset()
		// Really hose up the database security model:
		cmd = exec.Command("sudo", "sh", "-c", "echo local all all trust >"+filepath.Join(filepath.Dir(confd), "pg_hba.conf"))
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			t.Logf("running %+v: %v", cmd.Args, err)
			t.Logf("output:\n%s", buf.String())
			t.FailNow()
		}
		buf.Reset()
		// Start the database engine.
		cmd = exec.Command("sudo", "systemctl", "start", "postgresql.service")
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		if err := cmd.Run(); err != nil {
			t.Logf("running %+v: %v", cmd.Args, err)
			t.Logf("output:\n%s", buf.String())
			t.FailNow()
		}
	}
}
