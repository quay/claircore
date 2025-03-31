# Iterator patterns

Go 1.23 stabilized the "[range over func][rof]" feature.
This allows user-defined types to work with `range` expressions,
which effectively allows for creating "iterators" as in languages like [Rust][rust_iter].

[rof]: https://tip.golang.org/doc/go1.23#language
[rust_iter]: https://doc.rust-lang.org/std/iter/index.html

As this feature is relatively new, here's some helpers on when and where to
deploy it, and what patterns it's replacing. Familiarity with the [`iter`]
documentation is assumed throughout.

[iter]: https://pkg.go.dev/iter

## Large collections

The most obvious use is to replace collections (slices, maps) that have a lot of
entries that callers may ignore. Using an `iter.Seq` allows for the values to be
produced one-by-one, allowing for better resource usage.

A pitfall to watch out for is holding resources longer than intended.
Compare the two following snippets:

```go
func do(ctx context.Context) (err error) {
    var objs []any
    objs, err = getLotsofDatabaseObjects(ctx)
    if err != nil {
        return err
    }
    obj := objs[0]

    // Simulate doing something
    time.Sleep(time.Minute)

    return nil
}
```

```go
func do(ctx context.Context) (err error) {
    var objs iter.Seq[any]
    objs, err = DatabaseObjectsIter(ctx)
    if err != nil {
        return err
    }
    for obj := range objs {
        // Simulate doing something
        time.Sleep(time.Minute)
        break
    }

    return nil
}
```

Although the second one only produces one return, it holds onto a database
handle for the entire duration. This may be a net win or it may not, but the
lifetime of the handle has moved in a non-obvious way between the two
functions: the first has it scoped to the `getLotsofDatabaseObjects` function,
and the second has it captured in the returned `objs` iterator.

There's no way to express this sort of lifetime in Go, so make sure to document
when iterators hold resources in a way that may have not been an issue when
working with builtin collections.

## Error handling

Error propagation requires more thought when working with iterators. There are
three broad classes of error to consider.

As a rule of thumb, using an iterator raises procedure from the "value domain" to
the "function domain," so error reporting must move domains with it.

### Iterator construction errors

This class of errors occurs when code cannot construct an iterator. Functions
generally have the prototype of:
```go
type ConstructError func() (iter.Seq[any], error)
```

This means that if there's an error return, the iterator was not returned.
By way of analogy to the `database/sql` package, this is like constructing a
`sql.Rows` object:

```go
var db *sql.Conn

rows, err := db.QueryContext(ctx, `SELECT version()`) // ← here
if err != nil {
    panic(err)
}
defer rows.Close()

for rows.Next() {
    var v any
    if err := rows.Scan(&v); err != nil {
        panic(err)
    }
    // ...
}

if err := rows.Err(); err != nil {
    panic(err)
}
```

If an error is returned, there are no rows to read.

### Internal iteration errors

This class of errors occurs when there's an error in the iterator itself, almost
certainly from a lower layer. An example prototype would be:
```go
type FallableIterator func() (iter.Seq[any], func() error)
```

Function returns like this are usually meant to be called after the iterator has
been consumed to see if there was a problem. By way of analogy to the
`database/sql` package, this is like calling the `Err` method of a `sql.Rows`
object:

```go
var db *sql.Conn

rows, err := db.QueryContext(ctx, `SELECT version()`)
if err != nil {
    panic(err)
}
defer rows.Close()

for rows.Next() {
    var v any
    if err := rows.Scan(&v); err != nil {
        panic(err)
    }
    // ...
}

if err := rows.Err(); err != nil { // ← here
    panic(err)
}
```

### Per-iteration errors

This class of errors occurs when there's an error producing one specific value.
An example prototype would be:
```go
type PerIterationErr func() iter.Seq2[any, error]
```

Doing this allows the calling code to do error handling in a way it sees fit,
instead of a callee making the decision. For an iterator of this style, the
slice-based equivalent would be something like `func[V any]() []struct{Value V,
Err error}`. The slice-based code usually just returned no results and an error,
though. By way of analogy to the `database/sql` package, this is like the return
of the `Scan` method of a `sql.Rows` object:

```go
var db *sql.Conn

rows, err := db.QueryContext(ctx, `SELECT version()`)
if err != nil {
    panic(err)
}
defer rows.Close()

for rows.Next() {
    var v any
    if err := rows.Scan(&v); err != nil { // ← here
        panic(err)
    }
    // ...
}

if err := rows.Err(); err != nil {
    panic(err)
}
```

### Combining styles

There's no hard-and-fast rule, but if an author needs (wants) to make use of all
three, an "iterator factory" is usually a good pattern:

```go
type Collection struct {}

func NewCollection() (Collection, error) { // construction error reporting
    panic("unimplemented")
}

func (c *Collection) Close() { // explicit lifetime for held resources
    panic("unimplemented")
}

func (c *Collection) All() (iter.Seq2[any, error], func()) { // per-iteration and internal error reporting
    panic("unimplemented")
}
```

## Composition

Iterators are "just" some language help over the function-passing syntax, so
it's possible to compose them in arbitrary ways. Just remember that the
iterators are calling "into" the loop body; to put that another way, iterators
invert control.
