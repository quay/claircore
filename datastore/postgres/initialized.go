package postgres

import (
	"context"
	"sync/atomic"
)

func (s *MatcherStore) Initialized(ctx context.Context) (bool, error) {
	const query = `
SELECT EXISTS(SELECT 1 FROM vuln LIMIT 1);
`
	ok := atomic.LoadUint32(&s.initialized) != 0
	if ok {
		return true, nil
	}

	if err := s.pool.QueryRow(ctx, query).Scan(&ok); err != nil {
		return false, err
	}
	// There were no rows when we looked, so report that. Don't update the bool,
	// because it's in the 'false' state.
	if !ok {
		return false, nil
	}
	// If this fails, it means a concurrent goroutine already swapped. Any
	// subsequent calls will see the 'true' value.
	atomic.CompareAndSwapUint32(&s.initialized, 0, 1)
	return true, nil
}
