package main

import (
	_ "embed"
	"encoding/json"
	"go/ast"
	"go/token"
	"strconv"
)

//go:embed max_frag.json
var maxFrag []byte

// MaxFrag populates the "maxFrag" member with processed contents of
// "max_frag.json".
func MaxFrag() *ast.CompositeLit {
	var in [][][]string
	if err := json.Unmarshal(maxFrag, &in); err != nil {
		panic(err)
	}

	lit := ast.CompositeLit{
		Type: &ast.ArrayType{
			Len: &ast.Ellipsis{},
			Elt: &ast.ArrayType{
				Elt: &ast.ArrayType{
					Elt: &ast.Ident{Name: `*V4`},
				},
			},
		},
		Elts: make([]ast.Expr, len(in)),
	}

	// NOTE(hank) This is just a bunch of nested loops, sorry.
	// I couldn't think of a better way to structure this.

	for i, ia := range in {
		a := ast.CompositeLit{
			Elts: make([]ast.Expr, len(ia)),
		}
		for i, ib := range ia {
			b := ast.CompositeLit{
				Elts: make([]ast.Expr, len(ib)),
			}
			for i, frag := range ib {
				v := mustParseV4Frag(frag)
				vs := make([]ast.Expr, len(v))
				for i, b := range v {
					vs[i] = &ast.BasicLit{
						Kind:  token.INT,
						Value: `0x` + strconv.FormatInt(int64(b), 16),
					}
				}
				f := ast.CompositeLit{
					Elts: []ast.Expr{
						&ast.KeyValueExpr{
							Key: &ast.Ident{Name: `mv`},
							Value: &ast.CompositeLit{
								Type: &ast.ArrayType{
									Len: &ast.Ellipsis{},
									Elt: &ast.Ident{Name: `byte`},
								},
								Elts: vs,
							},
						},
					},
				}
				b.Elts[i] = &f
			}
			a.Elts[i] = &b
		}
		lit.Elts[i] = &a
	}
	return &lit
}
