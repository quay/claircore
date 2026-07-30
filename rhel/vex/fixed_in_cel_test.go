package vex

import (
	"testing"

	"github.com/package-url/packageurl-go"
)

func TestCompileFixedInVersionCEL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name    string
		expr    string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "empty",
			expr:    "",
			wantNil: true,
		},
		{
			name:    "invalid",
			expr:    "this is not valid CEL",
			wantErr: true,
		},
		{
			name:    "non-string",
			expr:    "true",
			wantErr: true,
		},
		{
			name: "valid",
			expr: `fixed_in`,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileFixedInVersionCEL(tc.expr)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected compile error")
				}
				return
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if tc.wantNil {
				if prog != nil {
					t.Fatal("expected nil program")
				}
				return
			}
			if prog == nil {
				t.Fatal("expected non-nil program")
			}
		})
	}
}

// TestEvalFixedInVersionCEL exercises rewriting FixedInVersion via a CEL
// expression that uses PURL fields such as type and qualifiers.
func TestEvalFixedInVersionCEL(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name  string
		expr  string
		purl  packageurl.PackageURL
		stock string
		want  string
	}{
		{
			name: "oci with tag2",
			// Prefer an alternate qualifier when present; otherwise keep stock fixed_in.
			expr: `type == "oci" && has(qualifiers.tag2) ? qualifiers.tag2 : fixed_in`,
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeOCI,
				Namespace: "redhat",
				Name:      "example",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"tag":            "1.0.0",
					"tag2":           "2.0.0-from-tag2",
					"repository_url": "registry.example/example",
				}),
			},
			stock: "1.0.0",
			want:  "2.0.0-from-tag2",
		},
		{
			name: "oci without tag2",
			expr: `type == "oci" && has(qualifiers.tag2) ? qualifiers.tag2 : fixed_in`,
			purl: packageurl.PackageURL{
				Type: packageurl.TypeOCI,
				Name: "example",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"tag": "1.0.0",
				}),
			},
			stock: "1.0.0",
			want:  "1.0.0",
		},
		{
			name: "rpm unchanged",
			expr: `type == "oci" && has(qualifiers.tag2) ? qualifiers.tag2 : fixed_in`,
			purl: packageurl.PackageURL{
				Type:      packageurl.TypeRPM,
				Namespace: "redhat",
				Name:      "bash",
				Version:   "5.1.8-6.el9",
				Qualifiers: packageurl.QualifiersFromMap(map[string]string{
					"epoch": "0",
				}),
			},
			stock: "0:5.1.8-6.el9",
			want:  "0:5.1.8-6.el9",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := CompileFixedInVersionCEL(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			opt, err := WithFixedInVersionCEL(tc.expr)
			if err != nil {
				t.Fatalf("WithFixedInVersionCEL: %v", err)
			}
			p := NewParser(opt)

			stock, err := extractFixedInVersion(&tc.purl)
			if err != nil {
				t.Fatalf("stock extract: %v", err)
			}
			if stock != tc.stock {
				t.Fatalf("stock = %q, want %q", stock, tc.stock)
			}
			got, err := EvalFixedInVersionCEL(prog, &tc.purl, stock)
			if err != nil {
				t.Fatalf("cel eval: %v", err)
			}
			if got != tc.want {
				t.Fatalf("cel rewrite = %q, want %q", got, tc.want)
			}
			gotCreator, err := (&creator{fixedInCEL: p.fixedInCEL}).FixedInVersion(&tc.purl)
			if err != nil {
				t.Fatalf("creator.FixedInVersion: %v", err)
			}
			if gotCreator != tc.want {
				t.Fatalf("creator rewrite = %q, want %q", gotCreator, tc.want)
			}
		})
	}
}

func TestFingerprintVersionCEL(t *testing.T) {
	t.Parallel()
	base := &Updater{}
	withCEL := &Updater{fixedInCELDigest: celExprFingerprintDigest(`fixed_in`)}
	otherCEL := &Updater{fixedInCELDigest: celExprFingerprintDigest(`type == "oci" ? fixed_in : fixed_in`)}

	if base.fingerprintVersion() != updaterVersion {
		t.Fatalf("base = %q, want %q", base.fingerprintVersion(), updaterVersion)
	}
	if withCEL.fingerprintVersion() == base.fingerprintVersion() {
		t.Fatal("CEL fingerprint should differ from base")
	}
	if withCEL.fingerprintVersion() == otherCEL.fingerprintVersion() {
		t.Fatal("different CEL expressions should produce different fingerprints")
	}
	if d := celExprFingerprintDigest(""); d != "" {
		t.Fatalf("empty digest = %q", d)
	}
}
