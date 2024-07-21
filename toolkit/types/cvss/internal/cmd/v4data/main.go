// v4data is a helper program to generate the extra tables need for CVSS v4
// score calculation.
//
// This command has a dependency on the [cvss] package, so if it generates
// invalid code you may need to edit the generated file to remove the contents
// of the literal declaration and leave an empty value in its place to be able
// to re-run this command.
package main

import (
	"bytes"
	_ "embed"
	"flag"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"os"
)

func main() {
	outName := flag.String("o", "-", "output file name ('-' for stdout)")
	flag.Parse()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "template.go", template, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		panic(err)
	}
	v := &Visitor{fset}
	ast.Walk(v, f)

	var buf bytes.Buffer
	if err := format.Node(&buf, fset, f); err != nil {
		panic(err)
	}
	b, err := format.Source(buf.Bytes())
	if err != nil {
		panic(err)
	}

	var out *os.File
	if *outName == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(*outName)
		if err != nil {
			panic(err)
		}
		defer out.Close()
	}

	if _, err := io.Copy(out, bytes.NewReader(b)); err != nil {
		panic(err)
	}
}

// This file is the template for the file generated for the cvss package.
//
// Unexported types are fine, as the code generator does not check types and the
// eventual code will be in the [cvss] package.
//
//go:embed _template.go
var template []byte

// Visitor is for [ast.Walk].
type Visitor struct {
	fset *token.FileSet
}

// Visit implements [ast.Visitor].
func (v *Visitor) Visit(node ast.Node) (w ast.Visitor) {
	switch n := node.(type) {
	case *ast.GenDecl:
		if n.Tok != token.VAR {
			break
		}
		val, ok := n.Specs[0].(*ast.ValueSpec)
		if !ok {
			break
		}
		switch val.Names[0].Name {
		case `scoreData`:
			return &Replace{v.fset}
		}
	}
	return v
}

// Replace is an [ast.Visitor] for the "scoreData" variable.
type Replace struct {
	fset *token.FileSet
}

// Visit implements [ast.Visitor].
func (r *Replace) Visit(node ast.Node) (w ast.Visitor) {
	if node == nil {
		return nil
	}
	v, ok := node.(*ast.ValueSpec)
	if !ok {
		return nil
	}
	lit := v.Values[0].(*ast.CompositeLit)

	for _, v := range lit.Elts {
		elt := v.(*ast.KeyValueExpr)
		switch elt.Key.(*ast.Ident).Name {
		case `metricsInEQ`:
			elt.Value = MetricsInEQ()
		case `maxFrag`:
			elt.Value = MaxFrag()
		case `eqDepth`:
			elt.Value = EqDepth()
		case `macrovectorScore`:
			elt.Value = MacrovectorScore()
		}
	}
	return nil
}
