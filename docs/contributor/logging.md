# Logging
All the logging in claircore is done with [`log/slog`][doc].

This allows for claircore's logging to be used consistently throughout all the
packages without having unintended prints to stderr.

## How to Log

### Adding Context

Within a function, create a `*slog.Logger` to add key-value pairs of any
relevant context:
```go
{{#include ../logger_test.go:kvs}}
```

Alternatively, the `github.com/quay/claircore/toolkit/log` package has a helper
for associating multiple `slog.Attr` values with a `context.Context`.
```go
{{#include ../logger_test.go:ctx}}
```

Programs using claircore should configure their `slog.Handler` to extract the
values using the key in `github.com/quay/claircore/toolkit/log` or use the
`Wrap` helper.

### Logging style

#### Constant Messages
Project style is to use string constants for all logging calls. Any variable
data should be passed as additional arguments to the `slog` methods.

For example, don't do this:
```go
{{#include ../logger_test.go:bad_example}}
```
Do this instead:
```go
{{#include ../logger_test.go:good_example}}
```

#### Grammar
When noting the change during a chunk of work, make sure that the
log messages scan as visually similar. Usually, this means formatting messages
into "${process} ${event}". For example:

```
frob start
frob initialized
frob ready
frob success
frob done
```

Is much easier to scan than:

```
starting to frob
initialized frobber
ready for frobbing
did frob
done with frobing
```

#### Don't log _and_ return
When handling an error, code should only log it if it does not propagate it. The
code that ultimately handles the error is responsible for deciding what to do
with it. Logging and returning ends up with the same message repeated multiple
times in the logs.

#### Levels
Claircore attempts to have consistent leveled logging. The rules for figuring
out what level to use is:

* Error

  Something unexpected occurred and the process can continue, but a
  human needs to be notified. An error will be returned for this request.

* Warn

  Something unexpected occurred and the process can continue. An error will be
  returned for this request.

* Info

  Some information that may be useful to an operator. Examples include
  a timer-based process starting and ending, a user request starting and
  ending, or a summary of work done.

* Debug

  Some information that may be useful to a developer. Examples include entering
  and exiting functions, stepping through a function, or specific file paths
  used while work is being done.

In exceptional situations, levels of `slog.LevelDebug-4` or `slog.LevelError+4`
may be used for "Trace" and "Emergency" logs. There are no predefined constants
for these.

#### Contexts
All logging calls should use the "Context" variant whenever possible.

[doc]: https://pkg.go.dev/log/slog
