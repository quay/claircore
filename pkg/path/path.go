package path

import (
	p "path"
)

// CanonicalizeFileName removes any leading '.', '..', './', or '../'
// along with removing duplicate slashes in a file name or path
func CanonicalizeFileName(path string) string {
	// clean the path to remove duplicate slashes
	// deeper in path
	path = p.Clean(path)

	// remove any occurrences of dot pathing at prefix
	runes := []rune(path)
	for i, r := range runes {
		if r == '.' || r == '/' {
			continue
		}
		runes = runes[i:]
		break
	}

	return string(runes)
}
