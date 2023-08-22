Here's various codebase conventions that don't have dedicated pages:

- URLs
  URLs in code should be annotated with a `//doc:url` directive comment. See
  the the `internal/cmd/mdbook-injecturls` command for documentation on how the
  preprocessor works. The list of keywords isn't an allowlist, so an invocation
  like the following should list the ones actually used in the documentation
  using a command like `git grep injecturls -- :/docs/*.md`.
