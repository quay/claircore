package main

import (
	_ "embed"
	"encoding/json"
	"go/ast"
	"go/token"
)

//go:embed eq_depth.json
var eqDepth []byte

// EqDepth populates the "eqDepth" member with processed contents of
// "eq_depth.json".
//
// Any "null" in the input is translated to a call to [math.Nan].
func EqDepth() *ast.CompositeLit {
	var in [][]json.Number
	if err := json.Unmarshal(eqDepth, &in); err != nil {
		panic(err)
	}

	lit := ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: &ast.Ellipsis{},
			Elt: &ast.ArrayType{
				Elt: &ast.Ident{Name: `float64`},
			},
		},
		Elts: make([]ast.Expr, len(in)),
	}

	for i, ia := range in {
		a := ast.CompositeLit{
			Elts: make([]ast.Expr, len(ia)),
		}
		for i, n := range ia {
			if n == "" {
				a.Elts[i] = nan
				continue
			}
			a.Elts[i] = &ast.BasicLit{Kind: token.FLOAT, Value: n.String()}
		}
		lit.Elts[i] = &a
	}

	return &lit
}

var nan = &ast.CallExpr{
	Fun: &ast.SelectorExpr{
		X:   &ast.Ident{Name: "math"},
		Sel: &ast.Ident{Name: "NaN"},
	},
}
