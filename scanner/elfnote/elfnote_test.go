package elfnote

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

func TestUnmarshalNote(t *testing.T) {
	// This fixture is just the ".note.package" section extracted from an rpm
	// binary I had via
	//
	// 	objcopy -O binary --only-section .note.package /usr/bin/rpm testdata/section.bin
	//
	// and then hex edited to add an "incorrect" section in front of it.
	f, err := os.Open(`testdata/section.bin`)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := bufio.NewReader(f)

	var n *note
Read:
	for {
		var err error
		n, err = unmarshalNote(t.Context(), binary.LittleEndian, buf)
		switch {
		case err == nil:
			break Read
		case errors.Is(err, errSkip):
			continue
		default:
			t.Error(err)
		}
	}

	t.Logf("%#v", n)
	if got, want := n.Type, "rpm"; got != want {
		t.Errorf("unexpected type: got: %q, want: %q", got, want)
	}
	if got, want := n.Name, "rpm"; got != want {
		t.Errorf("unexpected Name: got: %q, want: %q", got, want)
	}
}
