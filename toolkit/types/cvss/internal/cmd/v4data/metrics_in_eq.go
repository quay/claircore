package main

import (
	_ "embed"
	"encoding/json"
	"go/ast"
)

//go:embed metrics_in_eq.json
var metricsInEQ []byte

// MetricsInEQ populates the "metricsInEQ" member with processed contents of
// "metrics_in_eq.json".
func MetricsInEQ() *ast.CompositeLit {
	var in [][]string
	if err := json.Unmarshal(metricsInEQ, &in); err != nil {
		panic(err)
	}

	lit := ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: &ast.Ellipsis{},
			Elt: &ast.ArrayType{
				Len: nil,
				Elt: &ast.Ident{
					Name: `V4Metric`,
				},
			},
		},
		Elts: make([]ast.Expr, len(in)),
	}

	for i, ia := range in {
		a := ast.CompositeLit{
			Elts: make([]ast.Expr, len(ia)),
		}
		for i, n := range ia {
			a.Elts[i] = &ast.Ident{Name: `V4` + n}
		}
		lit.Elts[i] = &a
	}
	return &lit
}
