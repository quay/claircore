package osv

import (
	"encoding/json"
	"time"
)

// See https://ossf.github.io/osv-schema/ for the spec.
//
// This package implements v1.3.0
type (
	advisory struct {
		SchemaVersion string          `json:"schema_version"`
		ID            string          `json:"id"`
		Modified      time.Time       `json:"modified"`
		Published     time.Time       `json:"published"`
		Withdrawn     time.Time       `json:"withdrawn"`
		Aliases       []string        `json:"aliases"`
		Related       []string        `json:"related"`
		Summary       string          `json:"summary"`
		Details       string          `json:"details"`
		Severity      []severity      `json:"severity"`
		Affected      []affected      `json:"affected"`
		References    []reference     `json:"references"`
		Credits       []credit        `json:"credits"`
		Database      json.RawMessage `json:"database_specific"`
	}

	severity struct {
		// Valid types:
		// - CVSS_V3
		Type  string `json:"type"`
		Score string `json:"score"`
	}

	affected struct {
		Package   _package        `json:"package"`
		Ranges    []_range        `json:"ranges"`
		Versions  []string        `json:"versions"`
		Ecosystem json.RawMessage `json:"ecosystem_specific"`
		Database  json.RawMessage `json:"database_specific"`
	}

	_package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	}

	_range struct {
		Type     string          `json:"type"`
		Repo     string          `json:"repo"`
		Events   []rangeEvent    `json:"events"`
		Database json.RawMessage `json:"database_specific"`
	}

	rangeEvent struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
		Limit        string `json:"limit"`
	}

	credit struct {
		Name    string   `json:"name"`
		Contact []string `json:"contact"`
	}

	reference struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
)

func (a *advisory) GitOnly() bool {
	if len(a.Affected) == 0 {
		return false
	}
	for _, aff := range a.Affected {
		for _, r := range aff.Ranges {
			if r.Type != `GIT` {
				return false
			}
		}
	}
	return true
}
