package postgres

import (
	"hash/fnv"
	"io"
)

const (
	manifestAdvisoryLock = `SELECT pg_try_advisory_xact_lock($1);`
)

func crushkey(key string) int64 {
	h := fnv.New64a()
	io.WriteString(h, key)
	return int64(h.Sum64())
}
