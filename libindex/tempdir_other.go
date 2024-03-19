//go:build !unix

package libindex

// FixTemp is a no-op.
func fixTemp(d string) string {
	return d
}
