# Tests

Tests in the claircore module may use various helpers underneath the `test` directory.
Using these packages outside of testing code is disallowed.
Assert packages are disallowed;
the `go-cmp` package is the only external package helper allowed.

Tests that use external resources or generate test fixtures should be annotated according to the [`integration`] package.

[`integration`]: https://pkg.go.dev/github.com/quay/claircore/test/integration

## Caching

Tests using the `integration` package cache generated and downloaded assets into a directory named `clair-testing` inside the directory reported by [`os.UserCacheDir`].
For example, on a Linux system, the cache directory will be (in `sh` notation) `${XDG_CACHE_HOME-$HOME/.cache}/clair-testing`.

[`os.UserCacheDir`]: https://pkg.go.dev/os#UserCacheDir
