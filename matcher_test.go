package ghaauth

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		// Exact matches
		{
			name:    "exact match",
			pattern: "myorg/myrepo",
			value:   "myorg/myrepo",
			want:    true,
		},
		{
			name:    "exact mismatch",
			pattern: "myorg/myrepo",
			value:   "myorg/other",
			want:    false,
		},

		// Single wildcard (*)
		{
			name:    "wildcard at end",
			pattern: "myorg/*",
			value:   "myorg/myrepo",
			want:    true,
		},
		{
			name:    "wildcard at end - multiple segments",
			pattern: "myorg/*",
			value:   "myorg/myrepo/extra",
			want:    false, // * doesn't match /
		},
		{
			name:    "wildcard at start",
			pattern: "*/myrepo",
			value:   "myorg/myrepo",
			want:    true,
		},
		{
			name:    "wildcard in middle",
			pattern: "refs/heads/*",
			value:   "refs/heads/main",
			want:    true,
		},
		{
			name:    "wildcard in middle - mismatch",
			pattern: "refs/heads/*",
			value:   "refs/tags/v1.0",
			want:    false,
		},
		{
			name:    "multiple wildcards",
			pattern: "*/workflows/*.yml",
			value:   ".github/workflows/ci.yml",
			want:    true,
		},

		// Double wildcard (**)
		{
			name:    "double wildcard matches everything",
			pattern: "**",
			value:   "myorg/myrepo/path/to/file",
			want:    true,
		},
		{
			name:    "double wildcard at end",
			pattern: "myorg/**",
			value:   "myorg/myrepo/path",
			want:    true,
		},
		{
			name:    "double wildcard at start",
			pattern: "**/file.txt",
			value:   "path/to/file.txt",
			want:    true,
		},
		{
			name:    "double wildcard in middle",
			pattern: "myorg/**/ci.yml",
			value:   "myorg/myrepo/.github/workflows/ci.yml",
			want:    true,
		},
		{
			name:    "double wildcard matches empty",
			pattern: "myorg/**/file",
			value:   "myorg/file",
			want:    true,
		},

		// Edge cases
		{
			name:    "empty pattern and value",
			pattern: "",
			value:   "",
			want:    true,
		},
		{
			name:    "empty pattern",
			pattern: "",
			value:   "something",
			want:    false,
		},
		{
			name:    "empty value",
			pattern: "something",
			value:   "",
			want:    false,
		},
		{
			name:    "pattern with only wildcard",
			pattern: "*",
			value:   "anything",
			want:    true,
		},
		{
			name:    "pattern with only wildcard - no slash",
			pattern: "*",
			value:   "any/thing",
			want:    false,
		},

		// Real-world GitHub examples
		{
			name:    "allow specific repo",
			pattern: "myorg/myrepo",
			value:   "myorg/myrepo",
			want:    true,
		},
		{
			name:    "allow all repos in org",
			pattern: "myorg/*",
			value:   "myorg/myrepo",
			want:    true,
		},
		{
			name:    "allow main branch",
			pattern: "refs/heads/main",
			value:   "refs/heads/main",
			want:    true,
		},
		{
			name:    "allow all branches",
			pattern: "refs/heads/*",
			value:   "refs/heads/feature/new-feature",
			want:    false, // * doesn't match /
		},
		{
			name:    "allow all branches with **",
			pattern: "refs/heads/**",
			value:   "refs/heads/feature/new-feature",
			want:    true,
		},
		{
			name:    "allow all tags",
			pattern: "refs/tags/*",
			value:   "refs/tags/v1.0.0",
			want:    true,
		},
		{
			name:    "deny PR from fork",
			pattern: "myorg/*",
			value:   "otherorg/myrepo",
			want:    false,
		},

		// Complex patterns
		{
			name:    "workflow path pattern",
			pattern: "myorg/myrepo/.github/workflows/*.yml",
			value:   "myorg/myrepo/.github/workflows/ci.yml",
			want:    true,
		},
		{
			name:    "workflow path pattern - nested",
			pattern: "myorg/**/*.yml",
			value:   "myorg/myrepo/.github/workflows/ci.yml",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Match(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		value    string
		want     bool
	}{
		{
			name:     "matches first pattern",
			patterns: []string{"myorg/*", "otherorg/*"},
			value:    "myorg/myrepo",
			want:     true,
		},
		{
			name:     "matches second pattern",
			patterns: []string{"myorg/specific", "otherorg/*"},
			value:    "otherorg/myrepo",
			want:     true,
		},
		{
			name:     "matches no pattern",
			patterns: []string{"myorg/*", "otherorg/*"},
			value:    "thirdorg/myrepo",
			want:     false,
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			value:    "anything",
			want:     false,
		},
		{
			name:     "exact and wildcard patterns",
			patterns: []string{"refs/heads/main", "refs/heads/develop", "refs/heads/release/*"},
			value:    "refs/heads/release/v1.0",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchAny(tt.patterns, tt.value)
			if got != tt.want {
				t.Errorf("MatchAny(%v, %q) = %v, want %v", tt.patterns, tt.value, got, tt.want)
			}
		})
	}
}
