package ovalutil

import (
	"context"
	"regexp"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

var moduleCommentRegex *regexp.Regexp

func init() {
	moduleCommentRegex = regexp.MustCompile(`(Module )(.*)( is enabled)`)
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
	log := zerolog.Ctx(ctx).With().
		Str("component", "ovalutil/RPMDefsToVulns").
		Logger()
	ctx = log.WithContext(ctx)
	vulns := make([]*claircore.Vulnerability, 0, 10000)
	cris := []*oval.Criterion{}
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		protoVulns, err := protoVulns(def)
		if err != nil {
			log.Debug().
				Err(err).
				Str("def_id", def.ID).
				Msg("could not create prototype vulnerabilities")
			continue
		}
		// recursively collect criterions for this definition
		cris := cris[:0]
		walkCriterion(ctx, &def.Criteria, &cris)
		// unpack criterions into vulnerabilities
		enabledModules := getEnabledModules(cris)
		if len(enabledModules) == 0 {
			// add default empty module
			enabledModules = append(enabledModules, "")
		}
		for _, criterion := range cris {
			// lookup test
			_, index, err := root.Tests.Lookup(criterion.TestRef)
			if err != nil {
				log.Debug().Str("test_ref", criterion.TestRef).Msg("test ref lookup failure. moving to next criterion")
				continue
			}
			test := root.Tests.RPMInfoTests[index]
			if len(test.ObjectRefs) == 1 && len(test.StateRefs) == 0 {
				// We always take an object reference to imply the existence of
				// that object, so just skip tests with a single object reference
				// and no associated state object.
				continue
			}
			if len(test.ObjectRefs) != len(test.StateRefs) {
				log.Debug().Str("test_ref", criterion.TestRef).Msg("object refs and state refs are not in pairs. moving to next criterion")
				continue
			}
			// look at each object,state pair the test references
			// and create a vuln if an evr tag is found
			for i := 0; i < len(test.ObjectRefs); i++ {
				objRef := test.ObjectRefs[i].ObjectRef
				stateRef := test.StateRefs[i].StateRef
				_, objIndex, err := root.Objects.Lookup(objRef)
				if err != nil {
					log.Debug().Str("object_ref", objRef).Msg("failed object lookup. moving to next object,state pair")
					continue
				}
				_, stateIndex, err := root.States.Lookup(stateRef)
				if err != nil {
					log.Debug().Str("state_ref", stateRef).Msg("failed state lookup. moving to next object,state pair")
					continue
				}
				object := root.Objects.RPMInfoObjects[objIndex]
				state := root.States.RPMInfoStates[stateIndex]
				// if EVR tag not present this is not a linux package
				// see oval definitions for more details
				if state.EVR == nil {
					continue
				}

				for _, module := range enabledModules {
					for _, protoVuln := range protoVulns {
						vuln := *protoVuln
						vuln.FixedInVersion = state.EVR.Body

						p := &claircore.Package{
							Name:   object.Name,
							Module: module,
							Kind:   claircore.BINARY,
						}
						vuln.Package = p
						vuln.FixedInVersion = state.EVR.Body
						if state.Arch != nil {
							vuln.ArchOperation = mapArchOp(state.Arch.Operation)
							vuln.Package.Arch = state.Arch.Body
						}
						vulns = append(vulns, &vuln)
					}
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
