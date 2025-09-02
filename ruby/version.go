package ruby

import (
	"errors"
	"regexp"
	"strings"
)

var (
	anchoredVersion = regexp.MustCompile(`^\s*([0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?)?\s*$`)

	errInvalidVersion = errors.New("invalid gem version")
)

// Version is a RubyGem version.
// This is based on the official [implementation].
//
// [implementation]: https://github.com/rubygems/rubygems/blob/1a1948424aca90013b37cb8a78f5d1d5576023f1/lib/rubygems/version.rb
type Version struct {
	segs []Segment
}

// NewVersion creates a Version out of the given string.
func NewVersion(version string) (Version, error) {
	if !anchoredVersion.MatchString(version) {
		return Version{}, errInvalidVersion
	}

	version = strings.TrimSpace(version)
	if version == "" {
		version = "0"
	}
	version = strings.ReplaceAll(version, "-", ".pre.")

	return Version{
		segs: canonicalize(version),
	}, nil
}

// Compare returns an integer comparing this version, v, to other.
// The result will be 0 if v == other, -1 if v < other, and +1 if v > other.
func (v Version) Compare(other Version) int {
	segs := v.segs
	otherSegs := other.segs

	leftLen := len(segs)
	rightLen := len(otherSegs)
	limit := max(leftLen, rightLen)
	for i := range limit {
		left, right := Segment(numericSegment("0")), Segment(numericSegment("0"))
		if i < leftLen {
			left = segs[i]
		}
		if i < rightLen {
			right = otherSegs[i]
		}

		if cmp := left.Compare(right); cmp != 0 {
			return cmp
		}
	}

	return 0
}

func canonicalize(v string) []Segment {
	segs, prerelease := partitionSegments(v)

	// Remove trailing zero segments.
	i := len(segs) - 1
	for ; i >= 0; i-- {
		seg, ok := segs[i].(numericSegment)
		if !ok || !seg.isZero() {
			break
		}
	}
	segs = segs[:i+1]

	// Remove all zero segments preceding the first letter in a prerelease version.
	if prerelease {
		// Find the first letter in the version.
		end := -1
		for i := 0; i < len(segs); i++ {
			if _, ok := segs[i].(stringSegment); ok {
				end = i
				break
			}
		}
		if end != -1 {
			// Find where the preceding zeroes start.
			var start int
			for i := end - 1; i >= 0; i-- {
				seg, ok := segs[i].(numericSegment)
				if !ok || !seg.isZero() {
					start = i + 1
					break
				}
			}
			segs = append(segs[:start], segs[end:]...)
		}
	}

	return segs
}

func partitionSegments(v string) ([]Segment, bool) {
	var prerelease bool
	splitVersion := strings.Split(v, ".")
	segs := make([]Segment, 0, len(splitVersion))
	for _, s := range splitVersion {
		if s == "" {
			continue
		}

		if onlyDigits(s) {
			segs = append(segs, numericSegment(s))
			continue
		}

		// Ruby considers any version with a letter to be a prerelease.
		prerelease = true
		segs = append(segs, stringSegment(s))
	}

	return segs, prerelease
}

func onlyDigits(s string) bool {
	// I don't know if converting to a []byte does anything
	// special here, but [strconv.ParseUint] does it when ranging over a string,
	// and this implementation is based on code from [strconv.ParseUint].
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func max(a, b int) int {
	if b > a {
		return b
	}
	return a
}

// Segment is a part of a RubyGem version.
type Segment interface {
	Compare(other Segment) int
}

var (
	_ Segment = (*stringSegment)(nil)
	_ Segment = (*numericSegment)(nil)
)

type stringSegment string

// Compare returns an integer comparing this version, s, to other.
// The result will be 0 if v == other, -1 if v < other, and +1 if v > other.
//
// A stringSegment is always less than a numericSegment.
func (s stringSegment) Compare(other Segment) int {
	switch seg := other.(type) {
	case numericSegment:
		return -1
	case stringSegment:
		return strings.Compare(string(s), string(seg))
	default:
		panic("Programmer error")
	}
}

type numericSegment string

// Compare returns an integer comparing this version, n, to other.
// The result will be 0 if n == other, -1 if n < other, and +1 if n > other.
//
// A numericSegment is always greater than a stringSegment.
func (n numericSegment) Compare(other Segment) int {
	switch seg := other.(type) {
	case stringSegment:
		return +1
	case numericSegment:
		left, leftLen := string(n), len(n)
		right, rightLen := string(seg), len(seg)
		// The length of each string must match to compare them properly.
		// Pad the shorter string with zeroes.
		if leftLen == max(leftLen, rightLen) {
			right = strings.Repeat("0", leftLen-rightLen) + right
		} else {
			left = strings.Repeat("0", rightLen-leftLen) + left
		}
		return strings.Compare(left, right)
	default:
		panic("Programmer error")
	}
}

func (n numericSegment) isZero() bool {
	// Again, I don't know if converting to a []byte does anything
	// special here, but [strconv.ParseUint] does it when ranging over a string,
	// and this implementation is based on code from [strconv.ParseUint].
	for _, c := range []byte(n) {
		if c != '0' {
			return false
		}
	}
	return true
}
