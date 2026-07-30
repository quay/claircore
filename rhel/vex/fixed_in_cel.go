package vex

import (
	"fmt"

	"github.com/cespare/xxhash/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/package-url/packageurl-go"
)

// CompileFixedInVersionCEL compiles a CEL expression that evaluates to a string.
//
// The expression may use these variables:
//
//   - type (string): PURL type (oci, rpm, etc.)
//   - namespace (string): PURL namespace
//   - name (string): PURL name
//   - version (string): PURL version field
//   - qualifiers (map[string]string): PURL qualifiers
//   - fixed_in (string): default FixedInVersion from stock extraction
//
// The environment includes the CEL strings extension (startsWith,
// substring, split etc.) and bindings to be able to set variables.
//
// An empty expression returns a nil program.
// Production expressions are supplied by callers if desired.
func CompileFixedInVersionCEL(expr string) (cel.Program, error) {
	if expr == "" {
		return nil, nil
	}
	env, err := fixedInCELEnv()
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("fixed_in_version_cel: compile: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.StringType) {
		return nil, fmt.Errorf("fixed_in_version_cel: expression must evaluate to string, got %v", ast.OutputType())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("fixed_in_version_cel: program: %w", err)
	}
	return prog, nil
}

// EvalFixedInVersionCEL evaluates a compiled FixedInVersion CEL program.
func EvalFixedInVersionCEL(prog cel.Program, p *packageurl.PackageURL, defaultVersion string) (string, error) {
	if prog == nil {
		return defaultVersion, nil
	}
	out, _, err := prog.Eval(map[string]any{
		"type":       p.Type,
		"namespace":  p.Namespace,
		"name":       p.Name,
		"version":    p.Version,
		"qualifiers": p.Qualifiers.Map(),
		"fixed_in":   defaultVersion,
	})
	if err != nil {
		return "", fmt.Errorf("fixed_in_version_cel: eval: %w", err)
	}
	s, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf("fixed_in_version_cel: result type %T, want string", out.Value())
	}
	return s, nil
}

func fixedInCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("type", cel.StringType),
		cel.Variable("namespace", cel.StringType),
		cel.Variable("name", cel.StringType),
		cel.Variable("version", cel.StringType),
		cel.Variable("qualifiers", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("fixed_in", cel.StringType),
		ext.Strings(),
		ext.Bindings(),
	)
}

// CelExprFingerprintDigest returns a hex-encoded xxhash of expr for fingerprinting.
// Empty expr returns an empty string.
func celExprFingerprintDigest(expr string) string {
	if expr == "" {
		return ""
	}
	return fmt.Sprintf("%016x", xxhash.Sum64String(expr))
}
