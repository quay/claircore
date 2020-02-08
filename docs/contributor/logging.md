# Logging
All the logging in claircore is done with [zerolog][doc] via `context.Context`
values. Loggers are extracted from the Contexts via the `zerolog.Ctx` function,
then a child logger is created via the `With` method and associated with a new
Context via the `(*zerolog.Logger).WithContext` method.

This allows for claircore's logging to be used consistently throughout all the
packages without having unintended prints to stderr.

## How to Log

### Getting a logger
In a function, first obtain a logger:
```go
{{#include ../logger_test.go:logger}}
```
then add key-value pairs of any relevant context:
```go
{{#include ../logger_test.go:kvs}}
```
then create the new logger:
```go
{{#include ../logger_test.go:newlogger}}
```
then add the logger back to the Context so that child functions will have the
annotations on the logger they extract from the Context.

```go
{{#include ../logger_test.go:context}}
```

The log object shouldn't be stored in a struct and should stay function local.

### Logging style

#### Constant Messages
Zerolog emits lines when the `Msg` or `Msgf` methods are called. Project style
is to _not_ use `Msgf`. Any variable data should be set as key-value pairs on
the Event object.

For example, don't do this:
```go
{{#include ../logger_test.go:bad_example}}
```
Do this instead:
```go
{{#include ../logger_test.go:good_example}}
```

#### Grammar
When noting when noting the change during a chunk of work, make sure that the
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

* Panic

  There's some occurrence that means the process won't work correctly.

* Fatal

  Unused, because it prevents defers from running.

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

[doc]: https://pkg.go.dev/github.com/rs/zerolog@v1.15.0
