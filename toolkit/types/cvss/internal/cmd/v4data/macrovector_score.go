package main

import (
	_ "embed"
	"encoding/json"
	"go/ast"
	"go/token"
	"slices"
	"strings"
)

//go:embed macrovector_score.json
var macrovectorScore []byte

// MacrovectorScore populates the "macrovectorScore" member with processed
// contents of "macrovector_score.json".
func MacrovectorScore() *ast.CompositeLit {
	in := make(map[string]json.Number)
	if err := json.Unmarshal(macrovectorScore, &in); err != nil {
		panic(err)
	}
	ord := make([]string, 0, len(in))
	for k := range in {
		ord = append(ord, k)
	}
	slices.Sort(ord)

	lit := ast.CompositeLit{
		Type: &ast.MapType{
			Key:   &ast.Ident{Name: `macrovector`},
			Value: &ast.Ident{Name: `float64`},
		},
	}
	for _, s := range ord {
		v := in[s]
		elts := make([]ast.Expr, len(s))
		for i, s := range strings.Split(s, "") {
			elts[i] = &ast.BasicLit{Kind: token.INT, Value: s}
		}
		kv := ast.KeyValueExpr{
			Key: &ast.CompositeLit{
				Type: &ast.Ident{Name: `macrovector`},
				Elts: elts,
			},
			Value: &ast.BasicLit{Kind: token.FLOAT, Value: v.String()},
		}
		lit.Elts = append(lit.Elts, &kv)
	}

	return &lit
}
