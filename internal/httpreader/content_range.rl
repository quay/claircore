package httpreader

import (
	"errors"
	"strconv"
)
// The "go generate" command assumes ragel 7, which is shipped in Fedora.

//go:generate sh -e ragel.sh

// ContentRange is a parsed "bytes" content range.
//
// Unpopulated sections of the header are set to -1; refer to RFC7233 for
// more information.
type ContentRange struct {
	First, Last, Length int64
}

// Reset sets all fields to a known value (-1).
func (r *ContentRange) Reset() {
	r.First = -1
	r.Last = -1
	r.Length = -1
}

// Parse populates the receiver with the "bytes" content range from the
// supplied header value or reports an error.
func (r *ContentRange) Parse(data string) ( error) {
	r.Reset()
	// Action setup:
	var err error
	sc := 0
	// State machine setup:
	cs, p, pe, eof := 0, 0, len(data), len(data)
%%{
	machine content_range;
	# Set_start is the start of a number to parse later.
	action set_start { sc = fpc; }
	# Set_length parses the number starting at the position stashed by set_start
	# and assigns it to ret.Length.
	action set_length {
		r.Length, err = strconv.ParseInt(data[sc:fpc], 10, 64)
		if err != nil {
			fbreak;
		}
	}
	# Set_first is the same as set_length except it assigns to ret.First.
	action set_first {
		r.First, err = strconv.ParseInt(data[sc:fpc], 10, 64)
		if err != nil {
			fbreak;
		}
	}
	# Set_last is the same as set_length except it assigns to ret.Last.
	action set_last {
		r.Last, err = strconv.ParseInt(data[sc:fpc], 10, 64)
		if err != nil {
			fbreak;
		}
	}

	complete_length = digit+ >set_start %set_length;
	unsatisfied_range = '*/' complete_length;
	pos = digit+;
	byte_range = pos >set_start %set_first '-' pos >set_start %set_last;
	byte_range_resp = byte_range '/' ( complete_length | '*' );
	main := 'bytes ' ( byte_range_resp | unsatisfied_range );

	write data;
	write init;
	write exec;
}%%
	if cs >= content_range_start && cs < content_range_first_final {
		// Expect that err is populated
		return err
	}
	if p != pe {
		// Didn't consume the header.
		return errors.New("malformed header")
	}
	return nil
}
