//go:build race
// +build race

package libvuln

func init() {
	race = true
}
