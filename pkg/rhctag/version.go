// Package rhctag implements types for working with versions as used in the Red
// Hat Container Catalog.
package rhctag

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	rpmVersion "github.com/knqyf263/go-rpm-version"

	"github.com/quay/claircore"
)

// Allows extracting the Major and Minor versions so that we don't compare container tags from different minor versions.
// This is a workaround for another problem where not all minor releases of containers have a unique CPE.
// Take for example ocs4/rook-ceph-rhel8-operator, it shipped at least 2 minor releases into the same container repository.
// Both those major versions use the same CPE "cpe:/a:redhat:openshift_container_storage:4"
// Here are 2 example tags which fixed CVE-2020-8565
// 4.7 minor: 4.7-140.49a6fcf.release_4.7
// 4.8 minor: 4.8-167.9a9db5f.release_4.8

// This class also handles container tags which have a 'v' prefix, for example openshift4/ose-metering-hive
// 4.6 minor: v4.6.0-202112140546.p0.g8b9da97.assembly.stream
// 4.7 minor: v4.7.0-202112140553.p0.g091bb99.assembly.stream
type Version struct {
	Original string
	Major    int
	Minor    int
}

func (v *Version) Version(min bool) (c claircore.Version) {
	const (
		major = 0
		minor = 1
		patch = 2
	)

	c.Kind = "rhctag"
	c.V[major] = int32(v.Major)
	c.V[minor] = int32(v.Minor)
	if min {
		c.V[patch] = int32(0)
	} else {
		c.V[patch] = math.MaxInt32
	}
	return c
}

func upToDot(s string) (value int, remainder string, err error) {
	dotIndex := strings.Index(s, ".")
	if dotIndex > 0 {
		v := s[:dotIndex]
		value, err = strconv.Atoi(v)
		if err == nil {
			return value, s[dotIndex+1:], nil
		} else {
			return value, remainder, err
		}
	}
	// Maybe there's no patch release, trying parsing the value as an int
	value, err = strconv.Atoi(s)
	if err == nil {
		return value, remainder, nil
	}
	return value, remainder, fmt.Errorf("Could not parse %s as an int", s)
}

// Parse attempts to extract a Red Hat container registry tag version string
// from the provided string.
func Parse(s string) (v Version, err error) {
	canonical := s
	if strings.HasPrefix(s, "v") {
		// remove the leading "v" prefix
		canonical = s[1:]
	}
	//strip revision
	dashIndex := strings.Index(canonical, "-")
	if dashIndex > 0 {
		canonical = canonical[:dashIndex]
	}
	major, remainder, err := upToDot(canonical)
	if err != nil {
		return v, err
	}
	minor, _, err := upToDot(remainder)
	if err != nil {
		return Version{
			Original: s,
			Major:    major,
		}, nil
	}
	return Version{
		Original: s,
		Major:    major,
		Minor:    minor,
	}, nil
}

// MinorStart returns a Version which is lower than all others in the minor range
// major-minor series of the receiver.
func (v *Version) MinorStart() (start Version) {
	start, _ = Parse(fmt.Sprintf("%d.%d", v.Major, v.Minor))
	return start
}

func (v *Version) Compare(x *Version) int {
	thisRpmVersion := rpmVersion.NewVersion(v.Original)
	otherRpmVersion := rpmVersion.NewVersion(x.Original)
	return thisRpmVersion.Compare(otherRpmVersion)
}

// Versions implements sort.Interface.
type Versions []Version

func (vs Versions) Len() int {
	return len([]Version(vs))
}

func (vs Versions) Less(i, j int) bool {
	return vs[i].Compare(&vs[j]) == -1
}

func (vs Versions) Swap(i, j int) {
	vs[i], vs[j] = vs[j], vs[i]
}

func (vs Versions) Append(v Version) Versions {
	return append(vs, v)
}

func (vs Versions) First() (Version, error) {
	if len(vs) == 0 {
		return Version{}, fmt.Errorf("First called on empty Versions: %v", vs)
	}
	return vs[0], nil
}
