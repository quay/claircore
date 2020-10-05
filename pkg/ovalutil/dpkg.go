package ovalutil

import (
	"context"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

// DpkgDefsToVulns iterates over the definitions in an oval root and assumes DpkgInfo objects and states.
//
// Each Criterion encountered with an EVR string will be translated into a claircore.Vulnerability
func DpkgDefsToVulns(ctx context.Context, root *oval.Root, protoVulns ProtoVulnsFunc) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ovalutil/DpkgDefsToVulns").
		Logger()
	ctx = log.WithContext(ctx)
	vulns := make([]*claircore.Vulnerability, 0, 10000)
	pkgcache := map[string]*claircore.Package{}
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
		for _, criterion := range cris {
			// lookup test
			testKind, index, err := root.Tests.Lookup(criterion.TestRef)
			if err != nil {
				log.Debug().Str("test_ref", criterion.TestRef).Msg("test ref lookup failure. moving to next criterion")
				continue
			}
			if testKind != "dpkginfo_test" {
				continue
			}
			test := root.Tests.DpkgInfoTests[index]
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
				objKind, objIndex, err := root.Objects.Lookup(objRef)
				if err != nil {
					log.Error().Err(err).Str("object_ref", objRef).Msg("failed object lookup. moving to next object,state pair")
					continue
				}
				if objKind != "dpkginfo_object" {
					continue
				}
				stateKind, stateIndex, err := root.States.Lookup(stateRef)
				if err != nil {
					log.Debug().Str("state_ref", stateRef).Msg("failed state lookup. moving to next object,state pair")
					continue
				}
				if stateKind != "dpkginfo_state" {
					continue
				}
				object := root.Objects.DpkgInfoObjects[objIndex]
				state := root.States.DpkgInfoStates[stateIndex]
				// if EVR tag not present this is not a linux package
				// see oval definitions for more details
				if state.EVR == nil {
					continue
				}

				for _, protoVuln := range protoVulns {
					vuln := *protoVuln
					vuln.FixedInVersion = state.EVR.Body
					name := object.Name

					// if the dpkginfo_object>name field has a var_ref it indicates
					// a variable lookup for all packages affected by this vuln is necessary.
					//
					// if the name.Ref field is empty it indicates a single package is affected
					// by the vuln and that package's name is in name.Body.
					if len(name.Ref) > 0 {
						_, i, err := root.Variables.Lookup(name.Ref)
						if err != nil {
							log.Error().Err(err).Msg("could not lookup variable id")
							continue
						}
						consts := root.Variables.ConstantVariables[i]
						for _, v := range consts.Values {
							if pkg, ok := pkgcache[v.Body]; !ok {
								p := &claircore.Package{
									Name: v.Body,
									Kind: claircore.BINARY,
								}
								pkgcache[v.Body] = p
								vuln.Package = p
							} else {
								vuln.Package = pkg
							}
							if state.Arch != nil {
								vuln.ArchOperation = mapArchOp(state.Arch.Operation)
								vuln.Package.Arch = state.Arch.Body
							}
						}
						vulns = append(vulns, &vuln)
						// early continue
						continue
					}

					if pkg, ok := pkgcache[name.Body]; !ok {
						p := &claircore.Package{
							Name: name.Body,
							Kind: claircore.BINARY,
						}
						pkgcache[name.Body] = p
						vuln.Package = p
					} else {
						vuln.Package = pkg
					}
					if state.Arch != nil {
						vuln.ArchOperation = mapArchOp(state.Arch.Operation)
						vuln.Package.Arch = state.Arch.Body
					}
					vulns = append(vulns, &vuln)
				}
			}
		}
	}
	return vulns, nil
}
