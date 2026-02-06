package ghaauth

import (
	"strings"
)

// Match checks if a value matches a pattern with wildcard support
// Supported wildcards:
//   - '*' matches any sequence of characters except '/'
//   - '**' matches any sequence of characters including '/'
func Match(pattern, value string) bool {
	return matchInternal(pattern, value)
}

// matchInternal is the recursive pattern matching implementation
func matchInternal(pattern, value string) bool {
	// Split pattern into segments
	pi := 0
	vi := 0

	for {
		// Both exhausted - match
		if pi >= len(pattern) && vi >= len(value) {
			return true
		}

		// Pattern exhausted but value remains - no match
		if pi >= len(pattern) {
			return false
		}

		// Check for ** (matches any sequence including /)
		if pi+1 < len(pattern) && pattern[pi:pi+2] == "**" {
			// Skip the **
			pi += 2

			// If ** is at the end, match everything
			if pi >= len(pattern) {
				return true
			}

			// Skip optional separator after **
			if pi < len(pattern) && pattern[pi] == '/' {
				pi++
			}

			// Try matching the rest of pattern at each position in value
			for i := vi; i <= len(value); i++ {
				if matchInternal(pattern[pi:], value[i:]) {
					return true
				}
			}
			return false
		}

		// Check for * (matches any sequence except /)
		if pi < len(pattern) && pattern[pi] == '*' {
			pi++

			// Find what comes after the *
			nextSlash := strings.IndexByte(pattern[pi:], '/')
			var suffix string
			if nextSlash >= 0 {
				suffix = pattern[pi : pi+nextSlash]
			} else {
				suffix = pattern[pi:]
			}

			// Find the next / in value (since * doesn't cross /)
			valueSlash := strings.IndexByte(value[vi:], '/')
			searchEnd := len(value)
			if valueSlash >= 0 {
				searchEnd = vi + valueSlash
			}

			// Try matching suffix at each position before the /
			if suffix == "" {
				// No suffix after *, so match up to next /
				if valueSlash >= 0 {
					if matchInternal(pattern[pi:], value[vi+valueSlash:]) {
						return true
					}
				} else {
					// No / in value, so match rest
					return matchInternal(pattern[pi:], "")
				}
				return false
			}

			// Try to find suffix in value before next /
			for i := vi; i <= searchEnd; i++ {
				if matchInternal(pattern[pi:], value[i:]) {
					return true
				}
			}
			return false
		}

		// Value exhausted but pattern remains
		if vi >= len(value) {
			// Only match if rest of pattern is wildcards
			rest := pattern[pi:]
			return rest == "*" || rest == "**" || rest == ""
		}

		// Normal character comparison
		if pattern[pi] != value[vi] {
			return false
		}

		pi++
		vi++
	}
}

// MatchAny checks if a value matches any of the provided patterns
func MatchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if Match(pattern, value) {
			return true
		}
	}
	return false
}
