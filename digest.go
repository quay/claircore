package claircore

import (
	"bytes"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
)

type Digest struct {
	algo     string
	checksum []byte
}

func (d Digest) Checksum() []byte { return d.checksum }

func (d Digest) Algorithm() string { return d.algo }

func (d Digest) String() string {
	b, _ := d.MarshalText()
	return string(b)
}

// MarshalText implements encoding.TextMarshaler.
func (d Digest) MarshalText() ([]byte, error) {
	el := hex.EncodedLen(len(d.checksum))
	hl := len(d.algo) + 1
	b := make([]byte, hl+el)
	copy(b, d.algo)
	b[len(d.algo)] = ':'
	hex.Encode(b[hl:], d.checksum)
	return b, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Digest) UnmarshalText(t []byte) error {
	i := bytes.IndexByte(t, ':')
	if i == -1 {
		return fmt.Errorf("invalid digest format")
	}
	d.algo = string(t[:i])
	t = t[i+1:]
	d.checksum = make([]byte, hex.DecodedLen(len(t)))
	if _, err := hex.Decode(d.checksum, t); err != nil {
		return fmt.Errorf("invalid digest format")
	}
	return nil
}

// Scan implements sql.Scanner.
func (d *Digest) Scan(i interface{}) error {
	s, ok := i.(string)
	if !ok {
		return fmt.Errorf("invalid digest type")
	}
	return d.UnmarshalText([]byte(s))
}

// Value implements driver.Valuer.
func (d Digest) Value() (driver.Value, error) {
	b, err := d.MarshalText()
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

func NewDigest(algo string, sum []byte) Digest {
	return Digest{
		algo:     algo,
		checksum: sum,
	}
}

func ParseDigest(digest string) (Digest, error) {
	d := Digest{}
	return d, d.UnmarshalText([]byte(digest))
}
