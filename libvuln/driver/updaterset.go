package driver

import (
	"context"
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

// UpdaterSetFactory is used to construct updaters at run-time.
type UpdaterSetFactory interface {
	UpdaterSet(context.Context) (UpdaterSet, error)
}

type UpdaterSetFactoryFunc func(context.Context) (UpdaterSet, error)

func (u UpdaterSetFactoryFunc) UpdaterSet(ctx context.Context) (UpdaterSet, error) {
	return u(ctx)
}

// StaticSet creates an UpdaterSetFunc returning the provided set.
func StaticSet(s UpdaterSet) UpdaterSetFactory {
	return UpdaterSetFactoryFunc(func(_ context.Context) (UpdaterSet, error) {
		return s, nil
	})
}

// UpdaterSet holds a deduplicated set of updaters.
type UpdaterSet struct {
	set map[string]Updater
}

// NewUpdaterSet returns an initialized UpdaterSet.
func NewUpdaterSet() UpdaterSet {
	return UpdaterSet{
		set: map[string]Updater{},
	}
}

// Add will add an Updater to the set.
//
// An error will be reported if an updater with the same name already exists.
func (s *UpdaterSet) Add(u Updater) error {
	if _, ok := s.set[u.Name()]; ok {
		return ErrExists{[]string{u.Name()}}
	}

	s.set[u.Name()] = u
	return nil
}

// Merge will merge the UpdaterSet provided as argument
// into the UpdaterSet provided as the function receiver.
//
// If an updater exists in the target set an error
// specifying which updaters could not be merged is returned.
func (s *UpdaterSet) Merge(set UpdaterSet) error {
	exists := make([]string, 0, len(set.set))
	for n := range set.set {
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

// Updaters returns the updaters within the set as slice.
func (s *UpdaterSet) Updaters() []Updater {
	u := make([]Updater, 0, len(s.set))
	for _, v := range s.set {
		u = append(u, v)
	}
	return u
}

// RegexFilter will remove any updaters from the set whose reported names do not
// match the provided regexp string.
func (s *UpdaterSet) RegexFilter(regex string) error {
	re, err := regexp.Compile(regex)
	if err != nil {
		return fmt.Errorf("regex failed to compile: %v", err)
	}
	for name, u := range s.set {
		if !re.MatchString(u.Name()) {
			delete(s.set, name)
		}
	}
	return nil
}
