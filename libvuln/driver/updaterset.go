package driver

import (
	"fmt"
	"regexp"
)

// ErrExists is an error returned if the updater
// already exists in the set.
type ErrExists struct {
	Updater []string
}

func (e ErrExists) Error() string {
	return fmt.Sprintf("reused names: %v", e.Updater)
}

// UpdaterSet holds a deduped
// set of updaters
type UpdaterSet struct {
	set map[string]Updater
}

func NewUpdaterSet() UpdaterSet {
	set := map[string]Updater{}
	return UpdaterSet{
		set: set,
	}
}

// Add will add an Updater to the set.
//
// An erorr will occur if an updater with
func (s *UpdaterSet) Add(u Updater) error {
	if _, ok := s.set[u.Name()]; ok {
		return ErrExists{[]string{u.Name()}}
	}

	s.set[u.Name()] = u
	return nil
}

// Merge will merge the UpdaterSet provided as argument
// into the UpdateSet provided as the function receiver.
//
// If an updater exists in the target set an error
// specifying which updaters could not be merged is returned.
func (s *UpdaterSet) Merge(set UpdaterSet) error {
	exists := make([]string, 0, len(set.set))
	for n, _ := range set.set {
		if _, ok := s.set[n]; ok {
			exists = append(exists, n)
		}
	}

	if len(exists) > 0 {
		return ErrExists{exists}
	}

	for n, u := range set.set {
		s.set[n] = u
	}
	return nil
}

// Updaters() returns the updaters within the set as slice.
func (s *UpdaterSet) Updaters() []Updater {
	u := make([]Updater, 0, len(s.set))
	for _, v := range s.set {
		u = append(u, v)
	}
	return u
}

// RegexFilter will remove any updaters from the set
// that do not match the provided regex string.
func (s *UpdaterSet) RegexFilter(regex string) error {
	set := map[string]Updater{}
	re, err := regexp.Compile(regex)
	if err != nil {
		return fmt.Errorf("regex failed to compile: %v", err)
	}
	for name, u := range s.set {
		if re.MatchString(u.Name()) {
			set[name] = u
		}
	}
	s.set = set
	return nil
}
