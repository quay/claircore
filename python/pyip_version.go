package python

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/xerrors"
)

var (
	// The compiled regular expression used to test the validity of a version.
	versionRegex *regexp.Regexp

	preReleaseMapping = map[string]string{
		"a":       "a",
		"alpha":   "a",
		"b":       "b",
		"beta":    "b",
		"pre":     "rc",
		"preview": "rc",
		"rc":      "rc",
		"c":       "rc",
	}

	postReleaseMapping = map[string]string{
		"r":    "post",
		"rev":  "post",
		"post": "post",
	}
)

const (
	// The raw regular expression string used for testing the validity of a version.
	regex = `v?` +
		`(?:` +
		`(?:(?P<epoch>[0-9]+)!)?` + // epoch
		`(?P<release>[0-9]+(?:\.[0-9]+)*)` + // release segment
		`(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?` + // pre-release
		`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?` + // post release
		`(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)` + // dev release
		`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?` // local version`
)

// Version represents a single version.
type Version struct {
	epoch    int64
	release  []int64
	pre      letterNumber
	post     letterNumber
	dev      letterNumber
	local    string
	original string
}

type letterNumber struct {
	letter string
	number int64
}

func (ln letterNumber) isNull() bool {
	return ln.letter.IsNull() && ln.number.IsNull()
}

func init() {
	versionRegex = regexp.MustCompile(`(?i)^\s*` + regex + `\s*$`)
}

// MustParse is like Parse but panics if the version cannot be parsed.
func MustParse(v string) Version {
	ver, err := Parse(v)
	if err != nil {
		panic(err)
	}
	return ver
}

// Parse parses the given version and returns a new Version.
func Parse(v string) (Version, error) {
	matches := versionRegex.FindStringSubmatch(v)
	if matches == nil {
		return Version{}, xerrors.Errorf("malformed version: %s", v)
	}

	var epoch, preN, postN, devN int64
	var preL, postL, devL string
	var release []int64
	var local string
	var err error

	for i, name := range versionRegex.SubexpNames() {
		m := matches[i]
		if m == "" {
			continue
		}

		switch name {
		case "epoch":
			epoch, err = strconv.ParseInt(m, 10, 64)
		case "release":
			for _, str := range strings.Split(m, ".") {
				val, err := strconv.ParseInt(str, 10, 64)
				if err != nil {
					return Version{}, xerrors.Errorf("error parsing version: %w", err)
				}

				release = append(release, val)
			}
		case "pre_l":
			preL = preReleaseMapping[strings.ToLower(m)]
		case "pre_n":
			preN, err = strconv.ParseInt(m, 10, 64)
		case "post_l":
			postL = postReleaseMapping[strings.ToLower(m)]
		case "post_n1", "post_n2":
			if postL == "" {
				postL = "post"
			}
			postN, err = strconv.ParseInt(m, 10, 64)
		case "dev_l":
			devL = strings.ToLower(m)
		case "dev_n":
			devN, err = strconv.ParseInt(m, 10, 64)
		case "local":
			local = strings.ToLower(m)
		}
		if err != nil {
			return Version{}, xerrors.Errorf("failed to parse version (%s): %w", v, err)
		}
	}

	pre := letterNumber{
		letter: preL,
		number: preN,
	}
	post := letterNumber{
		letter: postL,
		number: postN,
	}
	dev := letterNumber{
		letter: devL,
		number: devN,
	}

	return Version{
		epoch:    epoch,
		release:  release,
		pre:      pre,
		post:     post,
		dev:      dev,
		local:    local,
		original: v,
	}, nil
}

// Compare compares this version to another version. This
// returns -1, 0, or 1 if this version is smaller, equal,
// or larger than the other version, respectively.
func (v Version) Compare(other Version) int {
	// Compare epochs first
	if v.epoch != other.epoch {
		if v.epoch > other.epoch {
			return 1
		} else {
			return -1
		}
	}

	//Compare release digits
	for i := 0; i < len(v.release) && i < len(other.release); i++ {
		if v.release[i] != other.release[i] {
			if v.release[i] > other.release[i] {
				return 1
			} else {
				return -1
			}
		}
	}
	if len(v.release) > len(other.release) {
		return 1
	} else if len(v.release) < len(other.release) {
		return -1
	}

	//Compare pre release
	if len(v.pre.letter)+len(other.pre.letter) > 0 {
		if strings.Compare(v.pre.letter, other.pre.letter) == 0 {
			return int(v.pre.number - other.pre.number)
		} else {
			if len(other.pre.letter) == 0 {
				return -1
			} else if len(v.pre.letter) == 0 {
				return 1
			}
			return strings.Compare(v.pre.letter, other.pre.letter)
		}
	}

	//Compare post-release
	if len(v.post.letter)+len(other.post.letter) > 0 {
		if strings.Compare(v.post.letter, other.post.letter) == 0 {
			return int(v.post.number - other.post.number)
		} else {
			if len(other.post.letter) == 0 {
				return 1
			} else if len(v.post.letter) == 0 {
				return -1
			}
			return strings.Compare(v.post.letter, other.post.letter)
		}
	}

	if strings.Compare(v.dev.letter, other.dev.letter) == 0 {
		return int(v.dev.number - other.dev.number)
	} else {
		if len(v.dev.letter) == 0 {
			return 1
		} else if len(other.dev.letter) == 0 {
			return -1
		}
		return int(v.dev.number - other.dev.number)
	}

	return nil
}

// Equal tests if two versions are equal.
func (v Version) Equal(o Version) bool {
	return v.Compare(o) == 0
}

// GreaterThan tests if this version is greater than another version.
func (v Version) GreaterThan(o Version) bool {
	return v.Compare(o) > 0
}

// GreaterThanOrEqual tests if this version is greater than or equal to another version.
func (v Version) GreaterThanOrEqual(o Version) bool {
	return v.Compare(o) >= 0
}

// LessThan tests if this version is less than another version.
func (v Version) LessThan(o Version) bool {
	return v.Compare(o) < 0
}

// LessThanOrEqual tests if this version is less than or equal to another version.
func (v Version) LessThanOrEqual(o Version) bool {
	return v.Compare(o) <= 0
}

// String returns the full version string included pre-release
// and metadata information.
func (v Version) String() string {
	var buf bytes.Buffer

	// Epoch
	if v.epoch != 0 {
		fmt.Fprintf(&buf, "%d!", v.epoch)
	}

	// Release segment
	fmt.Fprintf(&buf, "%d", v.release[0])
	for _, r := range v.release[1:len(v.release)] {
		fmt.Fprintf(&buf, ".%d", r)
	}

	// Pre-release
	if !v.pre.isNull() {
		fmt.Fprintf(&buf, "%s%d", v.pre.letter, v.pre.number)
	}

	// Post-release
	if !v.post.isNull() {
		fmt.Fprintf(&buf, ".post%d", v.post.number)
	}

	// Development release
	if !v.dev.isNull() {
		fmt.Fprintf(&buf, ".dev%d", v.dev.number)
	}

	// Local version segment
	if v.local != "" {
		fmt.Fprintf(&buf, "+%s", v.local)
	}

	return buf.String()
}

// BaseVersion returns the base version
func (v Version) BaseVersion() string {
	var buf bytes.Buffer

	// Epoch
	if v.epoch != 0 {
		fmt.Fprintf(&buf, "%d!", v.epoch)
	}

	// Release segment
	fmt.Fprintf(&buf, "%d", v.release[0])
	for _, r := range v.release[1:len(v.release)] {
		fmt.Fprintf(&buf, ".%d", r)
	}

	return buf.String()
}

// Original returns the original parsed version as-is, including any
// potential whitespace, `v` prefix, etc.
func (v Version) Original() string {
	return v.original
}

// Local returns the local version
func (v Version) Local() string {
	return v.local
}
