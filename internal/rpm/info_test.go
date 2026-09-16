package rpm

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/quay/claircore/internal/rpm/rpmdb"
)

// retypeTag rewrites the Type of the entry for the named tag in a serialized
// rpm header. The header is a preamble of two uint32s followed by fixed-size
// entries of tag, type, offset and count, all big-endian.
func retypeTag(t *testing.T, header []byte, tag rpmdb.Tag, want rpmdb.Kind) []byte {
	t.Helper()
	const (
		preambleSize  = 8
		entryInfoSize = 16
	)

	out := bytes.Clone(header)
	count := binary.BigEndian.Uint32(out[0:])
	for i := uint32(0); i < count; i++ {
		off := preambleSize + int(i)*entryInfoSize
		if rpmdb.Tag(binary.BigEndian.Uint32(out[off:])) != tag {
			continue
		}
		binary.BigEndian.PutUint32(out[off+4:], uint32(want))
		return out
	}

	t.Fatalf("tag %v not present in the test header", tag)
	return nil
}

// TestInfoLoadClassCompatibleTypes checks that Load tolerates the type
// substitutions the header verifier deliberately allows.
//
// verifyInfo accepts an entry whose Type merely shares a class with the type
// the tag table names, because, as checkTagType puts it, "Some versions of
// string are typed incorrectly in a compatible way". ReadData then returns the
// type that was declared rather than the one the tag table expects, so Load
// used to assert the wrong concrete type and panic on a header that the
// verifier had just accepted.
func TestInfoLoadClassCompatibleTypes(t *testing.T) {
	ctx := t.Context()

	header, err := os.ReadFile("rpmdb/testdata/package.header")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		tag  rpmdb.Tag
		kind rpmdb.Kind
	}{
		{"name as i18n string", rpmdb.TagName, rpmdb.TypeI18nString},
		{"name as string array", rpmdb.TagName, rpmdb.TypeStringArray},
		{"version as string array", rpmdb.TagVersion, rpmdb.TypeStringArray},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := retypeTag(t, header, tc.tag, tc.kind)

			h, err := rpmdb.ParseHeader(ctx, bytes.NewReader(mutated))
			if err != nil {
				t.Skipf("header verifier rejected this entry, so Load is unreachable: %v", err)
			}

			var i Info
			if err := i.Load(ctx, h); err != nil {
				t.Logf("Load reported an error, which is fine: %v", err)
				return
			}
			t.Logf("Load succeeded: name=%q version=%q", i.Name, i.Version)
		})
	}
}
