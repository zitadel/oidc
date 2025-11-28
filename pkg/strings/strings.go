package strings

import "slices"

// Deprecated: Use standard library [slices.Contains] instead.
func Contains(list []string, needle string) bool {
	// TODO(v4): remove package.
	return slices.Contains(list, needle)
}
