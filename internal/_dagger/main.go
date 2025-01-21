// A generated module for Claircore functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
	"context"
	"fmt"
	"path"
	"runtime"

	"dagger/claircore/internal/dagger"
)

const (
	GoVersion  = `1.23.5`
	UBI        = `registry.access.redhat.com/ubi9:9.5`
	PostgreSQL = `docker.io/library/postgres:latest`
)

type Claircore struct{}

// The base image for use with claircore.
func (m *Claircore) Builder() *dagger.Container {
	toolchain := UpstreamGo()

	return dag.Container().
		From(UBI).
		WithMountedDirectory("/usr/local/go", toolchain).
		WithEnvVariable(
			"PATH",
			"/usr/local/go/bin:${PATH}",
			dagger.ContainerWithEnvVariableOpts{Expand: true},
		).
		WithEnvVariable("GOFLAGS", "-trimpath")
}

// Create an environment suitable for building the indicated source.
func (m *Claircore) BuildEnv(
	ctx context.Context,
	source *dagger.Directory,
	// +optional
	cgo bool,
) *dagger.Container {
	download := []string{"go", "mod", "download"}

	return m.Builder().
		With(addGoCaches(ctx)).
		WithDirectory("/src", source).
		WithWorkdir("/src").
		With(func(c *dagger.Container) *dagger.Container {
			const name = `CGO_ENABLED`
			if !cgo {
				return c.
					WithEnvVariable(name, "0")
			}
			return c.
				WithEnvVariable(name, "1").
				WithExec([]string{"sh", "-ec", `dnf install -y gcc && dnf clean all`})
		}).
		WithExec(download)
}

// Return the result of running tests on the indicated source.
func (m *Claircore) Test(
	ctx context.Context,
	source *dagger.Directory,
	// +optional
	race bool,
	// +optional
	cover bool,
	// +optional
	unit bool,
	// +optional
	database *dagger.Service,
) (string, error) {
	cmd := []string{"go", "test"}
	if !unit {
		cmd = append(cmd, `-tags=integration`)
	}
	if race {
		cmd = append(cmd, `-race`)
	}
	if cover {
		cmd = append(cmd, `-cover`)
	}
	cmd = append(cmd, `./...`)

	c := m.BuildEnv(ctx, source, race).
		With(addTestCaches(ctx)).
		WithEnvVariable("CI", "1")

	// TODO(hank) This is probably wrong, figure out what to do.
	if database != nil {
		c = c.
			WithServiceBinding(`db`, database).
			WithEnvVariable(`PG_HOST`, `db`)
	} else {
		c = c.With(PostgreSQLService)
	}

	return c.
		WithExec(cmd).
		Stdout(ctx)
}

func PostgreSQLService(c *dagger.Container) *dagger.Container {
	const (
		user      = `claircore`
		plaintext = `hunter2`
	)
	pass := dag.SetSecret(`POSTGRES_PASSWORD`, plaintext)
	srv := dag.Container().
		From(PostgreSQL).
		WithEnvVariable(`POSTGRES_USER`, user).
		WithSecretVariable(`POSTGRES_PASSWORD`, pass).
		WithEnvVariable(`POSTGRES_INITDB_ARGS`, `--no-sync`).
		WithMountedCache(`/var/lib/postgresql/data`, dag.CacheVolume(`claircore-postgresql`)).
		AsService(dagger.ContainerAsServiceOpts{
			UseEntrypoint: true,
		})
	dsn := fmt.Sprintf(`host=db user=%s password=%s database=%[1]s sslmode=disable`, user, plaintext)
	return c.
		WithEnvVariable(`POSTGRES_CONNECTION_STRING`, dsn).
		WithServiceBinding(`db`, srv)
}

func UpstreamGo() *dagger.Directory {
	const wd = `/run/untar`
	var ( // Using `path` on purpose.
		arFile = path.Join(wd, "archive")
		outDir = path.Join(wd, "go")
	)
	dist := fmt.Sprintf(`https://go.dev/dl/go%s.linux-%s.tar.gz`, GoVersion, runtime.GOARCH)
	tarball := dag.HTTP(dist)
	cmd := []string{`tar`, `-xzf`, arFile}

	return dag.Container().
		From(UBI).
		WithWorkdir(wd).
		WithFile(arFile, tarball).
		WithExec(cmd).
		Directory(outDir)
}

func cacheDir(ctx context.Context, name string, env string) dagger.WithContainerFunc {
	opts := dagger.CacheVolumeOpts{
		Namespace: "claircore",
	}
	return func(c *dagger.Container) *dagger.Container {
		dir, err := c.EnvVariable(ctx, "XDG_CACHE_HOME")
		if dir == "" || err != nil {
			dir = "/root/.cache"
		}
		cache := dag.CacheVolume(name, opts)
		path := path.Join(dir, name)

		c = c.WithMountedCache(path, cache)
		if env != "" {
			c = c.WithEnvVariable(env, path)
		}
		return c
	}
}

func addGoCaches(ctx context.Context) dagger.WithContainerFunc {
	return func(c *dagger.Container) *dagger.Container {
		return c.
			With(cacheDir(ctx, "go-build", "GOCACHE")).
			With(cacheDir(ctx, "go-mod", "GOMODCACHE"))
	}
}

func addTestCaches(ctx context.Context) dagger.WithContainerFunc {
	return cacheDir(ctx, `clair-testing`, "")
}
