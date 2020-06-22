package main

import (
	"fmt"
	"time"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/ubuntu"
)

// Fixtures define the image used to create the fixtures
// and the on-disk file the fixtures can be read from.
type Fixture struct {
	// the container image used to create the Index and Vulnerability reports
	Image string `json:"image"`
	// the security database used to create the Vulnerability Report
	SecDB string `json:"secdb"`
	// the IndexReport in json format
	IR string `json:"index_report"`
	// the duration it took to generate the index report
	IRDuration time.Duration `json:"index_report_duration"`
	// the VulnerabilityReport in json format
	VR string `json:"vuln_report"`
	// the duration it took to generate the vulnerability report
	VRDuration time.Duration `json:"vuln_report_duration"`
	// a value which can be used to retrieve a runtime updater
	Updater string `json:"updater"`
	// a private member holding the runtime updater
	updater driver.Updater
}

// SetUpdater will set the private updater field on a Fixture
// given a valid Updater string field.
//
//
// As you create more fixture make sure to add a lookup
// entry so the acceptance test can easily allocate the
// same updater under test.
func (f *Fixture) SetUpdater() error {
	var lookup = map[string]driver.Updater{
		string(ubuntu.Xenial): ubuntu.NewUpdater(ubuntu.Xenial),
		string(ubuntu.Bionic): ubuntu.NewUpdater(ubuntu.Bionic),
		string(ubuntu.Cosmic): ubuntu.NewUpdater(ubuntu.Cosmic),
		string(ubuntu.Disco):  ubuntu.NewUpdater(ubuntu.Disco),
		string(ubuntu.Eoan):   ubuntu.NewUpdater(ubuntu.Eoan),
		string(ubuntu.Focal):  ubuntu.NewUpdater(ubuntu.Focal),
	}

	if updater, ok := lookup[f.Updater]; !ok {
		return fmt.Errorf("fixture was created with unknown updater")
	} else {
		f.updater = updater
	}
	return nil
}
