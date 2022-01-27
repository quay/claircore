// Plugins
//
// See the relevant examples and the "_plugin" subdirectory for more
// information.
package driver

const (
	// MatcherEntrypoint is the variable name that is used as an entrypoint for
	// matcher plugins. This variable must implement the MatcherFactory
	// interface.
	//
	// The "Matchers" method will be called for every Libvuln construction in
	// the program. This usually happens only once, but plugins should guard
	// against repeated calls if it affects correctness.
	MatcherEntrypoint = `MatcherFactory`

	// EnricherEntrypoint is the variable name that is used as an entrypoint for
	// enricher plugins. This variable must implement the Enricher interface.
	//
	// Any EnrichmentUpdaters should be provided by the updater plugin's
	// mechanism. See UpdaterEntrypoint for more information.
	EnricherEntrypoint = `Enricher`

	// UpdaterEntrypoint is the variable name that is used as an entrypoint for
	// updater plugins. This variable must implement the UpdaterSetFactory
	// interface.
	//
	// The "UpdaterSet" method will be called for every Libvuln construction in
	// the program. This usually happens only once, but plugins should guard
	// against repeated calls if it affects correctness.
	//
	//
	UpdaterEntrypoint = `UpdaterSetFactory`
)

// DocumentationHelper is used by some logging to help print documentation in
// the logging output.
//
// This is needed because module paths are not recorded in the reflection
// information of plugins.
type DocumentationHelper interface {
	// DocumentationURL reports a URL that an operator can visit for more
	// information.
	DocumentationURL() string
}

/*
I've done some additional research that doesn't really warrant putting the
"real" documentation, so I'm going to stash it here, in a long comment where the
first iteration of a plugin system is implemented.

There's basically 5 ways to get some modularity in a go program:

- Compile-time, a.k.a. blank imports
  The idea here is you add an import purely for its side-effect, which is
  usually registering a driver using a well-known package. Claircore does this
  for the in-tree updaters, but doesn't do it in a "main" (it doesn't have one),
  and instead does it in the package that manages updaters generally. It's a fine
  solution, as long as it's easy to add code. The way we distribute Clair means
  it's not easy to add code.
- The plugin package
  The stdlib plugin package is a thin wrapper over dlopen(3) and implements
  dynamic loading. This has the caveat that it can only reference package-level
  variables and functions; using types defined in the plugin's package(s) is
  basically impossible, as you'd have to import them to name them and so you could
  just import the package normally. The resulting shared libraries are gigantic
  (the same size as compiling a normal "main" package, basically) and have tight
  restrictions on the toolchain, runtime, and packages used. They must all be
  identical, down to the build flags and paths used (Assuming you're not using
  -trimpath. Make sure to use -trimpath). The plugin package doesn't exist on some
  platforms (notably GOOS=windows), so build constraints are needed for conditional
  compilation.
- cgo, a.k.a a C ABI
  Cgo is a go-like language that allows C FFI and has all the safety of C
  combined with the ease of compilation of C. Using it would allow us to define a
  C plugin ABI, which means that plugins could be written in any language that can
  export a C ABI shared object. The major downside is being unable to use our
  common types.  Anything going across the ABI can only use basic C types OR must
  be packed on the C side and then unpacked and copied on the go side OR the
  plugin code must carefully write into go memory such that it can be cast
  correctly. Footguns abound and it would require new driver API, as it would be a
  giant pain to return our extremely pointer-heavy types across the C boundary.
- Scripting/hosted language
  We could host another VM and have all the plugins written in that language,
  providing some convenience functions from go. There's a handful of these written
  in pure go or using reasonably portable C implementations. Lua, javascript,
  prolog, and various schemes come to mind. This means plugins cannot be written
  in go nor arbitrary languages.
  - Wasm
	Wasm is really built for our use case, but unfortunately the "interface
    types" support is, as of now, nonexistent. (Javascript types will disagree, but
    needing to use software that explicitly says in its README to not use it does
    not inspire confidence.) Without that support, we'd essentially be writing C
    bindings with extra steps and with the added bonus of needing to write them for
    every other language.
- IPC/RPC
  The IPC/RPC route would be akin to running an HTTP server over stdin+stdout or
  a pipe shared with a child process. This has the benefit of running the plugin
  in a separate process, but the downside of running the plugin in a separate
  process. We'd need a new, custom API for this style of communication to minimize
  copying and buffering -- e.g. returning a type like []claircore.Vulnerability is
  a no-go. There's also the matter of picking a standard, like jsonrpc2, grpc, or
  something custom.

Long term, using wasm (meaning, most likey, wasmtime) would be ideal -- it's
sandboxed and people are already doing extremely weird things like compiling
CPython with it. This means we could provide a wasm interface definition and
have basically any language interface with it.

In the short term, using the stdlib plugin package will cause headaches on
version matching and ties the plugins to using go, but allows us to re-use the
type definitions and configuration machinery unchanged.
*/
