package claircore

import (
	"errors"
	"time"
)

// Duration is a serializeable [time.Duration].
type Duration time.Duration

// UnmarshalText implements [encoding.TextUnmarshaler].
func (d *Duration) UnmarshalText(b []byte) error {
	dur, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// MarshalText implements [encoding.TextMarshaler].
func (d *Duration) MarshalText() ([]byte, error) {
	if d == nil {
		return nil, errors.New("cannot marshal nil duration")
	}
	return []byte(time.Duration(*d).String()), nil
}
