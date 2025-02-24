package ndb

// This is a port of the rpm murmur hash, which uses a single constant rather than a few of them.
func murmur(s string) (h uint32) {
	const m = 0x5bd1e995
	h = uint32(len(s) * m)
	for ; len(s) >= 4; s = s[4:] {
		h += uint32(s[0]) | uint32(s[1])<<8 | uint32(s[2])<<16 | uint32(s[3])<<24
		h *= m
		h ^= h >> 16
	}
	switch len(s) {
	case 3:
		h += uint32(s[2]) << 16
		fallthrough
	case 2:
		h += uint32(s[1]) << 8
		fallthrough
	case 1:
		h += uint32(s[0])
		h *= m
		h ^= h >> 16
	}
	h *= m
	h ^= h >> 10
	h *= m
	h ^= h >> 17
	return h
}
