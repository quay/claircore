package vex

// import (
// 	"testing"

// 	"github.com/package-url/packageurl-go"
// )

// // TestTryFixMalformedModule tests the CLAIRDEV-256 fix for malformed rpmmod qualifiers
// func TestTryFixMalformedModule(t *testing.T) {
// 	testCases := []struct {
// 		name     string
// 		input    string
// 		expected string
// 	}{
// 		{
// 			name:     "rhel10 (NEW feed format)",
// 			input:    "rhel10",
// 			expected: "rhel:10",
// 		},
// 		{
// 			name:     "rhel9",
// 			input:    "rhel9",
// 			expected: "rhel:9",
// 		},
// 		{
// 			name:     "nodejs18",
// 			input:    "nodejs18",
// 			expected: "nodejs:18",
// 		},
// 		{
// 			name:     "python311",
// 			input:    "python311",
// 			expected: "python:311",
// 		},
// 		{
// 			name:     "already correct format",
// 			input:    "rhel:10",
// 			expected: "", // Should not match (already has colon)
// 		},
// 		{
// 			name:     "no digits",
// 			input:    "rhel",
// 			expected: "", // Cannot fix
// 		},
// 		{
// 			name:     "starts with digit",
// 			input:    "10rhel",
// 			expected: "", // Invalid format
// 		},
// 		{
// 			name:     "empty string",
// 			input:    "",
// 			expected: "",
// 		},
// 	}

// 	// for _, tc := range testCases {
// 	// 	t.Run(tc.name, func(t *testing.T) {
// 	// 		result := tryFixMalformedModule(tc.input)
// 	// 		if result != tc.expected {
// 	// 			t.Errorf("tryFixMalformedModule(%q) = %q, expected %q", tc.input, result, tc.expected)
// 	// 		}
// 	// 	})
// 	// }
// }

// // TestComponentPURLToModuleNameWithFix tests that malformed rpmmod qualifiers are handled
// func TestComponentPURLToModuleNameWithFix(t *testing.T) {
// 	testCases := []struct {
// 		name        string
// 		purlString  string
// 		expected    string
// 		shouldError bool
// 	}{
// 		{
// 			name:        "correct format",
// 			purlString:  "pkg:rpm/redhat/firefox@1.0?rpmmod=nodejs:18",
// 			expected:    "nodejs:18",
// 			shouldError: false,
// 		},
// 		{
// 			name:        "malformed rhel10 (NEW feed issue)",
// 			purlString:  "pkg:rpm/redhat/firefox-flatpak@1.0?arch=src&rpmmod=rhel10",
// 			expected:    "rhel:10",
// 			shouldError: false,
// 		},
// 		{
// 			name:        "malformed rhel9",
// 			purlString:  "pkg:rpm/redhat/package@1.0?rpmmod=rhel9",
// 			expected:    "rhel:9",
// 			shouldError: false,
// 		},
// 		{
// 			name:        "malformed nodejs18",
// 			purlString:  "pkg:rpm/redhat/package@1.0?rpmmod=nodejs18",
// 			expected:    "nodejs:18",
// 			shouldError: false,
// 		},
// 		{
// 			name:        "no rpmmod qualifier",
// 			purlString:  "pkg:rpm/redhat/package@1.0",
// 			expected:    "",
// 			shouldError: false,
// 		},
// 		{
// 			name:        "completely invalid format",
// 			purlString:  "pkg:rpm/redhat/package@1.0?rpmmod=invalid",
// 			expected:    "",
// 			shouldError: true,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			purl, err := packageurl.FromString(tc.purlString)
// 			if err != nil {
// 				t.Fatal("Failed to parse PURL:", err)
// 			}

// 			result, err := componentPURLToModuleName(&purl)

// 			if tc.shouldError {
// 				if err == nil {
// 					t.Errorf("Expected error for %q, but got result: %q", tc.purlString, result)
// 				}
// 			} else {
// 				if err != nil {
// 					t.Errorf("Unexpected error for %q: %v", tc.purlString, err)
// 				}
// 				if result != tc.expected {
// 					t.Errorf("componentPURLToModuleName(%q) = %q, expected %q", tc.purlString, result, tc.expected)
// 				}
// 			}
// 		})
// 	}
// }

// // TestNewFeedCompatibility specifically tests the firefox-flatpak case from NEW feed
// func TestNewFeedCompatibility(t *testing.T) {
// 	// This is the actual PURL that caused the failure in NEW feed
// 	purlString := "pkg:rpm/redhat/firefox-flatpak?arch=src&rpmmod=rhel10"

// 	purl, err := packageurl.FromString(purlString)
// 	if err != nil {
// 		t.Fatal("Failed to parse PURL:", err)
// 	}

// 	result, err := componentPURLToModuleName(&purl)
// 	if err != nil {
// 		t.Fatalf("Parser should handle malformed rpmmod, but got error: %v", err)
// 	}

// 	expected := "rhel:10"
// 	if result != expected {
// 		t.Errorf("Expected %q for NEW feed compatibility, got %q", expected, result)
// 	}

// 	t.Logf("✅ NEW feed compatibility fix working: %q -> %q", "rpmmod=rhel10", result)
// }
