package claircore

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"hash"
)

const (
	SHA256 = "sha256"
	SHA512 = "sha512"
)

// Digest is a type representing the hash of some data.
//
// It's used throughout claircore packages as an attempt to remain independent
// of a specific hashing algorithm.
type Digest struct {
	algo     string
	checksum []byte
	repr     string
}

// Checksum returns the checksum byte slice.
func (d Digest) Checksum() []byte { return d.checksum }

// Algorithm returns a string representation of the algorithm used for this
// digest.
func (d Digest) Algorithm() string { return d.algo }

// Hash returns an instance of the hashing algorithm used for this Digest.
func (d Digest) Hash() hash.Hash {
	switch d.algo {
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	default:
		panic("Hash() called on an invalid Digest")
	}
}

func (d Digest) String() string {
	return d.repr
}

// MarshalText implements encoding.TextMarshaler.
func (d Digest) MarshalText() ([]byte, error) {
	b := make([]byte, len(d.repr))
	copy(b, d.repr)
	return b, nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Digest) UnmarshalText(t []byte) error {
	i := bytes.IndexByte(t, ':')
	if i == -1 {
		return &DigestError{msg: "invalid digest format"}
	}
	d.algo = string(t[:i])
	t = t[i+1:]
	b := make([]byte, hex.DecodedLen(len(t)))
	if _, err := hex.Decode(b, t); err != nil {
		return &DigestError{
			msg:   "unable to decode digest as hex",
			inner: err,
		}
	}
	return d.setChecksum(b)
}

// DigestError is the concrete type backing errors returned from Digest's
// methods.
type DigestError struct {
	msg   string
	inner error
}

// Error implements error.
func (e *DigestError) Error() string {
	return e.msg
}

// Unwrap enables errors.Unwrap.
func (e *DigestError) Unwrap() error {
	return e.inner
}

func (d *Digest) setChecksum(b []byte) error {
	var sz int
	switch d.algo {
	case "sha256":
		sz = sha256.Size
	case "sha512":
		sz = sha512.Size
	default:
		return &DigestError{msg: fmt.Sprintf("unknown algorthm %q", d.algo)}
	}
	if l := len(b); l != sz {
		return &DigestError{msg: fmt.Sprintf("bad checksum length: %d", l)}
	}

	el := hex.EncodedLen(sz)
	hl := len(d.algo) + 1
	sb := make([]byte, hl+el)
	copy(sb, d.algo)
	sb[len(d.algo)] = ':'
	hex.Encode(sb[hl:], b)

	d.checksum = b
	d.repr = string(sb)

	return nil
}

// Scan implements sql.Scanner.
func (d *Digest) Scan(i interface{}) error {
	switch v := i.(type) {
	case nil:
		return nil
	case string:
		d.UnmarshalText([]byte(v))
		return nil
	default:
		return &DigestError{msg: fmt.Sprintf("invalid digest type: %T", v)}
	}
}

// Value implements driver.Valuer.
func (d Digest) Value() (driver.Value, error) {
	return d.repr, nil
}

// NewDigest constructs a Digest.
func NewDigest(algo string, sum []byte) (Digest, error) {
	d := Digest{
		algo: algo,
	}
	return d, d.setChecksum(sum)
}

// ParseDigest constructs a Digest from a string, ensuring it's well-formed.
func ParseDigest(digest string) (Digest, error) {
	d := Digest{}
	return d, d.UnmarshalText([]byte(digest))
}

// MustParseDigest works like ParseDigest but panics if the provided
// string is not well-formed.
func MustParseDigest(digest string) Digest {
	d := Digest{}
	err := d.UnmarshalText([]byte(digest))
	if err != nil {
		s := fmt.Sprintf("digest %s could not be parsed: %v", digest, err)
		panic(s)
	}
	return d
}
