package scanner

import (
	"testing"

	"github.com/quay/claircore"
	"github.com/stretchr/testify/assert"
)

type stackArgs struct {
	layer *claircore.Layer
	pkgs  []*claircore.Package
}

func Test_Stacker(t *testing.T) {
	var tt = []struct {
		name                 string
		args                 []stackArgs
		expectedPkgs         []*claircore.Package
		expectedIntroducedIn map[int]string
	}{
		{
			name: "1 layer. 1 package empty distribution",
			args: []stackArgs{
				{
					layer: &claircore.Layer{Hash: "test-layer-hash-1"},
					pkgs: []*claircore.Package{
						&claircore.Package{
							ID:      0,
							Name:    "test-package-1",
							Version: "v0.0.1",
							Dist: &claircore.Distribution{
								ID:              0,
								DID:             "",
								Name:            "",
								Version:         "",
								VersionCodeName: "",
								VersionID:       "",
								Arch:            "",
							},
						},
					},
				},
			},
			expectedPkgs: []*claircore.Package{
				&claircore.Package{
					ID:      0,
					Name:    "test-package-1",
					Version: "v0.0.1",
					Dist: &claircore.Distribution{
						ID:              0,
						DID:             "",
						Name:            "",
						Version:         "",
						VersionCodeName: "",
						VersionID:       "",
						Arch:            "",
					},
				},
			},
			expectedIntroducedIn: map[int]string{
				0: "test-layer-hash-1",
			},
		},
		{
			name: "1 layer 1 package non-empty distribution",
			args: []stackArgs{
				{
					layer: &claircore.Layer{Hash: "test-layer-hash-1"},
					pkgs: []*claircore.Package{
						&claircore.Package{
							ID:      0,
							Name:    "test-package-1",
							Version: "v0.0.1",
							Dist: &claircore.Distribution{
								ID:              10,
								DID:             "test-did",
								Name:            "test-name",
								Version:         "test-version",
								VersionCodeName: "test-verion-code-name",
								VersionID:       "test-version-id",
								Arch:            "test-arch",
							},
						},
					},
				},
			},
			expectedPkgs: []*claircore.Package{
				&claircore.Package{
					ID:      0,
					Name:    "test-package-1",
					Version: "v0.0.1",
					Dist: &claircore.Distribution{
						ID:              10,
						DID:             "test-did",
						Name:            "test-name",
						Version:         "test-version",
						VersionCodeName: "test-verion-code-name",
						VersionID:       "test-version-id",
						Arch:            "test-arch",
					},
				},
			},
			expectedIntroducedIn: map[int]string{
				0: "test-layer-hash-1",
			},
		},
		{
			name: "2 layers 1 package dist info in base layer",
			args: []stackArgs{
				{
					layer: &claircore.Layer{Hash: "test-layer-hash-1"},
					pkgs: []*claircore.Package{
						&claircore.Package{
							ID:      0,
							Name:    "test-package-1",
							Version: "v0.0.1",
							Dist: &claircore.Distribution{
								ID:              10,
								DID:             "test-did",
								Name:            "test-name",
								Version:         "test-version",
								VersionCodeName: "test-verion-code-name",
								VersionID:       "test-version-id",
								Arch:            "test-arch",
							},
						},
					},
				},
			},
			expectedPkgs: []*claircore.Package{
				&claircore.Package{
					ID:      0,
					Name:    "test-package-1",
					Version: "v0.0.1",
					Dist: &claircore.Distribution{
						ID:              10,
						DID:             "test-did",
						Name:            "test-name",
						Version:         "test-version",
						VersionCodeName: "test-verion-code-name",
						VersionID:       "test-version-id",
						Arch:            "test-arch",
					},
				},
			},
			expectedIntroducedIn: map[int]string{
				0: "test-layer-hash-1",
			},
		},
	}
	for _, table := range tt {
		t.Run(table.name, func(t *testing.T) {
			st := NewStacker()

			for _, arg := range table.args {
				st.Stack(arg.layer, arg.pkgs)
			}
			pkgs, intoducedIn := st.Result()
			assert.ElementsMatch(t, table.expectedPkgs, pkgs)

			for k, v := range table.expectedIntroducedIn {
				vv, ok := intoducedIn[k]
				if !ok {
					t.Fatalf("failed to find expected introducedIn package id: %v", k)
				}
				if v != vv {
					t.Fatalf("failed to find correct introducedIn layer for package id %v. found %v expected %v", k, vv, v)
				}
			}
		})
	}
}

// func Test_Stacker(t *testing.T) {
// 	var tt = []struct {
// 		// the name of the test
// 		name string
// 		// 2d array of packages we will stack
// 		pkgs [][]*claircore.Package
// 		// array of expected packages
// 		expectedPkgs []*claircore.Package
// 	}{
// 		{
// 			name: "two iterations, package 2 removed package 3 added",
// 			pkgs: [][]*claircore.Package{
// 				[]*claircore.Package
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   2,
// 						Name: "test-package-2",
// 						Dist: &claircore.Distribution{
// 							ID:   2,
// 							Name: "test-distribution-2",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   3,
// 							Name: "test-distribution-3",
// 						},
// 					},
// 				},
// 			},
// 			expectedPkgs: []*claircore.Package{
// 				&claircore.Package{
// 					ID:   1,
// 					Name: "test-package-1",
// 					Dist: &claircore.Distribution{
// 						ID:   1,
// 						Name: "test-distribution-1",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   3,
// 					Name: "test-package-3",
// 					Dist: &claircore.Distribution{
// 						ID:   3,
// 						Name: "test-distribution-3",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "three iterations with empty layer, package 2 removed package 3 added",
// 			pkgs: [][]*claircore.Package{
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   2,
// 						Name: "test-package-2",
// 						Dist: &claircore.Distribution{
// 							ID:   2,
// 							Name: "test-distribution-2",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   3,
// 							Name: "test-distribution-3",
// 						},
// 					},
// 				},
// 			},
// 			expectedPkgs: []*claircore.Package{
// 				&claircore.Package{
// 					ID:   1,
// 					Name: "test-package-1",
// 					Dist: &claircore.Distribution{
// 						ID:   1,
// 						Name: "test-distribution-1",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   3,
// 					Name: "test-package-3",
// 					Dist: &claircore.Distribution{
// 						ID:   3,
// 						Name: "test-distribution-3",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "four iterations with empty layer, packge two removed package 3,4 added",
// 			pkgs: [][]*claircore.Package{
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   2,
// 						Name: "test-package-2",
// 						Dist: &claircore.Distribution{
// 							ID:   2,
// 							Name: "test-distribution-2",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   3,
// 							Name: "test-distribution-3",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   3,
// 							Name: "test-distribution-3",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   4,
// 						Name: "test-package-4",
// 						Dist: &claircore.Distribution{
// 							ID:   4,
// 							Name: "test-distribution-4",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{},
// 			},
// 			expectedPkgs: []*claircore.Package{
// 				&claircore.Package{
// 					ID:   1,
// 					Name: "test-package-1",
// 					Dist: &claircore.Distribution{
// 						ID:   1,
// 						Name: "test-distribution-1",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   3,
// 					Name: "test-package-3",
// 					Dist: &claircore.Distribution{
// 						ID:   3,
// 						Name: "test-distribution-3",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   4,
// 					Name: "test-package-4",
// 					Dist: &claircore.Distribution{
// 						ID:   4,
// 						Name: "test-distribution-4",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "four iterations with empty layer, packge two removed package 3,4 added distribution upgrade",
// 			pkgs: [][]*claircore.Package{
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   2,
// 						Name: "test-package-2",
// 						Dist: &claircore.Distribution{
// 							ID:   2,
// 							Name: "test-distribution-2",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   3,
// 							Name: "test-distribution-3",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{
// 					&claircore.Package{
// 						ID:   1,
// 						Name: "test-package-1",
// 						Dist: &claircore.Distribution{
// 							ID:   1,
// 							Name: "test-distribution-1",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   3,
// 						Name: "test-package-3",
// 						Dist: &claircore.Distribution{
// 							ID:   33,
// 							Name: "test-distribution-upgraded",
// 						},
// 					},
// 					&claircore.Package{
// 						ID:   4,
// 						Name: "test-package-4",
// 						Dist: &claircore.Distribution{
// 							ID:   4,
// 							Name: "test-distribution-4",
// 						},
// 					},
// 				},
// 				[]*claircore.Package{},
// 			},
// 			expectedPkgs: []*claircore.Package{
// 				&claircore.Package{
// 					ID:   1,
// 					Name: "test-package-1",
// 					Dist: &claircore.Distribution{
// 						ID:   1,
// 						Name: "test-distribution-1",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   3,
// 					Name: "test-package-3",
// 					Dist: &claircore.Distribution{
// 						ID:   33,
// 						Name: "test-distribution-upgraded",
// 					},
// 				},
// 				&claircore.Package{
// 					ID:   4,
// 					Name: "test-package-4",
// 					Dist: &claircore.Distribution{
// 						ID:   4,
// 						Name: "test-distribution-4",
// 					},
// 				},
// 			},
// 		},
// 	}

// 	for _, table := range tt {
// 		t.Run(table.name, func(t *testing.T) {
// 			stacker := NewStacker()

// 			for _, p := range table.pkgs {
// 				stacker.Stack(p)
// 			}

// 			res := stacker.Result()
// 			assert.ElementsMatch(t, table.expectedPkgs, res)
// 		})
// 	}
// }
