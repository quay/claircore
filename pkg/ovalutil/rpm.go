package ovalutil

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/quay/goval-parser/oval"
	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

const (
	CVEDefinition        = "cve"
	RHBADefinition       = "rhba"
	RHEADefinition       = "rhea"
	RHSADefinition       = "rhsa"
	UnaffectedDefinition = "unaffected"
)

var moduleCommentRegex, definitionTypeRegex *regexp.Regexp

func init() {
	moduleCommentRegex = regexp.MustCompile(`(Module )(.*)( is enabled)`)
	definitionTypeRegex = regexp.MustCompile(`^oval\:com\.redhat\.([a-z]+)\:def\:\d+$`)
}

// ProtoVulnsFunc allows a caller to create prototype vulnerabilities that will be
// copied and further defined for every applicable oval.Criterion discovered.
//
// This allows the caller to use oval.Definition fields and closure syntax when
// defining how a vulnerability should be parsed
type ProtoVulnsFunc func(def oval.Definition) ([]*claircore.Vulnerability, error)

// RPMDefsToVulns iterates over the definitions in an oval root and assumes RPMInfo objects and states.
//
// Each Criterion encountered with an EVR string will be translated into a claircore.Vulnerability
func RPMDefsToVulns(ctx context.Context, root *oval.Root, protoVulns ProtoVulnsFunc) ([]*claircore.Vulnerability, error) {
	ctx = zlog.ContextWithValues(ctx, "component", "ovalutil/RPMDefsToVulns")
	vulns := make([]*claircore.Vulnerability, 0, 10000)
	cris := []*oval.Criterion{}
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		protoVulns, err := protoVulns(def)
		if err != nil {
			zlog.Debug(ctx).
				Err(err).
				Str("def_id", def.ID).
				Msg("could not create prototype vulnerabilities")
			continue
		}
		// recursively collect criterions for this definition
		cris := cris[:0]
		walkCriterion(ctx, &def.Criteria, &cris)
		enabledModules := getEnabledModules(cris)
		if len(enabledModules) == 0 {
			// add default empty module
			enabledModules = append(enabledModules, "")
		}
		// unpack criterions into vulnerabilities
		for _, criterion := range cris {
			// if test object is not rmpinfo_test the provided test is not
			// associated with a package. this criterion will be skipped.
			test, err := TestLookup(root, criterion.TestRef, func(kind string) bool {
				if kind != "rpminfo_test" {
					return false
				}
				return true
			})
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, errTestSkip):
				continue
			default:
				zlog.Debug(ctx).Str("test_ref", criterion.TestRef).Msg("test ref lookup failure. moving to next criterion")
				continue
			}

			objRefs := test.ObjectRef()
			stateRefs := test.StateRef()

			// from the rpminfo_test specification found here: https://oval.mitre.org/language/version5.7/ovaldefinition/documentation/linux-definitions-schema.html
			// "The required object element references a rpminfo_object and the optional state element specifies the data to check.
			//  The evaluation of the test is guided by the check attribute that is inherited from the TestType."
			//
			// thus we *should* only need to care about a single rpminfo_object and optionally a state object providing the package's fixed-in version.

			objRef := objRefs[0].ObjectRef
			object, err := rpmObjectLookup(root, objRef)
			switch {
			case errors.Is(err, nil):
			case errors.Is(err, errObjectSkip):
				// We only handle rpminfo_objects.
				continue
			default:
				zlog.Debug(ctx).
					Err(err).
					Str("object_ref", objRef).
					Msg("failed object lookup. moving to next criterion")
				continue
			}

			// state refs are optional, so this is not a requirement.
			// if a state object is discovered, we can use it to find
			// the "fixed-in-version"
			var state *oval.RPMInfoState
			if len(stateRefs) > 0 {
				stateRef := stateRefs[0].StateRef
				state, err = rpmStateLookup(root, stateRef)
				if err != nil {
					zlog.Debug(ctx).
						Err(err).
						Str("state_ref", stateRef).
						Msg("failed state lookup. moving to next criterion")
					continue
				}
				// if we find a state, but this state does not contain an EVR,
				// we are not looking at a linux package.
				if state.EVR == nil {
					continue
				}
			}

			for _, module := range enabledModules {
				for _, protoVuln := range protoVulns {
					vuln := *protoVuln
					vuln.Package = &claircore.Package{
						Name:   object.Name,
						Module: module,
						Kind:   claircore.BINARY,
					}
					if state != nil {
						vuln.FixedInVersion = state.EVR.Body
						if state.Arch != nil {
							vuln.ArchOperation = mapArchOp(state.Arch.Operation)
							vuln.Package.Arch = state.Arch.Body
						}
					}
					vulns = append(vulns, &vuln)
				}
			}
		}
	}

	return vulns, nil
}

func mapArchOp(op oval.Operation) claircore.ArchOp {
	switch op {
	case oval.OpEquals:
		return claircore.OpEquals
	case oval.OpNotEquals:
		return claircore.OpNotEquals
	case oval.OpPatternMatch:
		return claircore.OpPatternMatch
	default:
	}
	return claircore.ArchOp(0)
}

// walkCriterion recursively extracts Criterions from a root Crteria node in a depth
// first manor.
//
// a pointer to a slice header is modified in place when appending
func walkCriterion(ctx context.Context, node *oval.Criteria, cris *[]*oval.Criterion) {
	// recursive to leafs
	for _, criteria := range node.Criterias {
		walkCriterion(ctx, &criteria, cris)
	}
	// search for criterions at current node
	for _, criterion := range node.Criterions {
		c := criterion
		*cris = append(*cris, &c)
	}
}

func getEnabledModules(cris []*oval.Criterion) []string {
	enabledModules := []string{}
	for _, criterion := range cris {
		matches := moduleCommentRegex.FindStringSubmatch(criterion.Comment)
		if matches != nil && len(matches) > 2 && matches[2] != "" {
			moduleNameStream := matches[2]
			enabledModules = append(enabledModules, moduleNameStream)
		}
	}
	return enabledModules
}

func rpmObjectLookup(root *oval.Root, ref string) (*oval.RPMInfoObject, error) {
	kind, index, err := root.Objects.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_object" {
		return nil, fmt.Errorf("oval: got kind %q: %w", kind, errObjectSkip)
	}
	return &root.Objects.RPMInfoObjects[index], nil
}

func rpmStateLookup(root *oval.Root, ref string) (*oval.RPMInfoState, error) {
	kind, index, err := root.States.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "rpminfo_state" {
		return nil, fmt.Errorf("bad kind: %s", kind)
	}
	return &root.States.RPMInfoStates[index], nil
}

// GetDefinitionType parses an OVAL definition and extracts its type from ID.
func GetDefinitionType(def oval.Definition) (string, error) {
	match := definitionTypeRegex.FindStringSubmatch(def.ID)
	if len(match) != 2 { // we should have match of the whole string and one submatch
		return "", errors.New("cannot parse definition ID for its type")
	}
	return match[1], nil
}
