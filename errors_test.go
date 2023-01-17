package claircore

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

func ExampleError() {
	fmt.Println(&Error{
		Inner:   nil,
		Kind:    ErrInternal,
		Message: "test",
		Op:      "ExampleError",
	})

	fmt.Println(&Error{
		Inner:   sql.ErrNoRows,
		Kind:    ErrPrecondition,
		Message: "needed object missing",
		Op:      "Lookup",
	})
	err := &Error{
		Inner: &Error{
			Inner:   sql.ErrNoRows,
			Kind:    ErrPrecondition,
			Message: "needed object missing",
			Op:      "Lookup",
		},
		Kind: ErrTransient,
	}
	fmt.Println(err)
	fmt.Println(fmt.Errorf("somepackage: oops: %w", &Error{
		Inner:   sql.ErrNoRows,
		Kind:    ErrPrecondition,
		Message: "needed object missing",
		Op:      "Lookup",
	}))

	// Output:
	// ExampleError [internal]: test
	// Lookup [precondition]: needed object missing: sql: no rows in result set
	// Lookup [precondition]: needed object missing: sql: no rows in result set
	// somepackage: oops: Lookup [precondition]: needed object missing: sql: no rows in result set
}

type dureeTestcase struct {
	Err       error
	Permanent bool
	Transient bool
	Version   bool
}

func (tc dureeTestcase) Run(t *testing.T) {
	t.Log(tc.Err)
	if got, want := errors.Is(tc.Err, ErrPermanent), tc.Permanent; got != want {
		t.Errorf("%v: got: %v, want: %v", ErrPermanent, got, want)
	}
	if got, want := errors.Is(tc.Err, ErrTransient), tc.Transient; got != want {
		t.Errorf("%v: got: %v, want: %v", ErrTransient, got, want)
	}
	if got, want := errors.Is(tc.Err, ErrVersionDependent), tc.Version; got != want {
		t.Errorf("%v: got: %v, want: %v", ErrVersionDependent, got, want)
	}
}

func TestDuree(t *testing.T) {
	tt := []dureeTestcase{
		// 0: Permanent
		{
			Err: &Error{
				Inner: errors.New("permanent"),
				Kind:  ErrPermanent,
			},
			Permanent: true,
			Transient: false,
			Version:   false,
		},
		// 1: Transient
		{
			Err: &Error{
				Inner: errors.New("transient"),
				Kind:  ErrTransient,
			},
			Permanent: false,
			Transient: true,
			Version:   false,
		},
		// 2: Version
		{
			Err: &Error{
				Inner: errors.New("version"),
				Kind:  ErrInternal,
			},
			Permanent: false,
			Transient: false,
			Version:   true,
		},
		// 3: Broken
		{
			Err: &Error{
				Kind: ErrTransient,
				Inner: &Error{
					Inner: errors.New("confused"),
					Kind:  ErrPermanent,
				},
			},
			Permanent: true,
			Transient: true,
			Version:   false,
		},
	}

	for i, tc := range tt {
		t.Run(strconv.Itoa(i), tc.Run)
	}
}
