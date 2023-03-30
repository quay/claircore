package jar

import "path"

// ValidExt determines if the file name extension
// is a valid JAR file extension.
func ValidExt(name string) bool {
	ext := path.Ext(name)
	switch ext {
	case ".jar", ".war", ".ear": // OK
	case ".jpi", ".hpi": // Jenkins plugins
	default:
		return false
	}

	return true
}
