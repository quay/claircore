# DistLock
Dist lock implements a distributed lock via postgres.

## Goals

* No Transcations.
* A single manager uses a single DB conn.
* Cleanup database locks on process death.
* Cleanup application bookkeeping on database disconnection.
* A ctx based api.
* Allocation friendly

current 1m profile
```
54625           1347103 ns/op             517 B/op         11 allocs/op 
```

## Allocs

DistLock wants to be performant. Unfortunately utilizing a context implementation means you cannot pool the use of done channels. 
They must be closed and not reused. 

Despite that we are able to pool our own channel usage for request and response to the guard. 

```
ROUTINE ======================== github.com/ldelossa/distlock.(*Manager).Lock in /home/louis/git/go/distlock/manager.go
    2.50MB     2.50MB (flat, cum)  7.45% of Total
         .          .     89:		return resp.ctx, func() {}
         .          .     90:	}
         .          .     91:
         .          .     92:	m.propagateCancel(ctx, resp.ctx, key)
         .          .     93:
    2.50MB     2.50MB     94:	return resp.ctx, func() {
         .          .     95:		m.unlock(key)
         .          .     96:	}
         .          .     97:}
         .          .     98:
         .          .     99:func (m *Manager) propagateCancel(parent context.Context, child context.Context, key string) {
```
The above demonstrates the Lock function is effectively zero alloc other then returning the function pointer for cancel.

```
ROUTINE ======================== github.com/ldelossa/distlock.(*guard).lock in /home/louis/git/go/distlock/guard.go
      11MB    18.53MB (flat, cum) 55.18% of Total
         .          .    243:	}
         .          .    244:
         .          .    245:	rr := m.conn.PgConn().ExecParams(ctx,
         .          .    246:		trySessionLock,
         .          .    247:		[][]byte{
         .        4MB    248:			keyify(key),
         .          .    249:		},
         .          .    250:		nil,
         .          .    251:		[]int16{1},
         .          .    252:		nil)
         .     3.53MB    253:	tag, err := rr.Close()
         .          .    254:	if err != nil {
         .          .    255:		return response{false, nil, err}
         .          .    256:	}
         .          .    257:	if tag.RowsAffected() == 0 {
         .          .    258:		return response{false, &lctx{done: closedchan, err: ErrMutualExclusion}, ErrMutualExclusion}
         .          .    259:	}
         .          .    260:
       2MB        2MB    261:	lock := &lctx{
         .          .    262:		err:  nil,
       9MB        9MB    263:		done: make(chan struct{}),
         .          .    264:	}
         .          .    265:
         .          .    266:	m.locks[key] = lock
         .          .    267:	m.counter++
         .          .    268:	return response{true, lock, nil}
```
The above demonstrates that we are hit for allocating the done channels. Can't do much about that since they are closed and we cannot pool.

To understand if we obtained a lock from Postgres we only need to understand if any rows were returned when requesting it. Since we do not need to actually read the rows we are able to take a huge shortcut in time and allocations. You will notice we query the database like so:
```
rr := m.conn.PgConn().ExecParams(ctx,
  trySessionUnlock,
  [][]byte{
      keyify(key),
  },
  nil,
  []int16{1},
  nil)
tag, err := rr.Close()
```

This performs a query and gives us back the raw ResultReader. We can simply close it and get the command tag to understand if a lock has been issued. This saves a large amount of allocations.
