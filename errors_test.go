package ghaauth

import (
	"errors"
	"testing"
)

func TestValidationError(t *testing.T) {
	tests := []struct {
		name        string
		baseErr     error
		reason      string
		wantMessage string
		wantUnwrap  error
	}{
		{
			name:        "with reason",
			baseErr:     ErrInvalidToken,
			reason:      "missing required claims",
			wantMessage: "invalid token: missing required claims",
			wantUnwrap:  ErrInvalidToken,
		},
		{
			name:        "without reason",
			baseErr:     ErrTokenExpired,
			reason:      "",
			wantMessage: "token expired",
			wantUnwrap:  ErrTokenExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewValidationError(tt.baseErr, tt.reason)

			if err.Error() != tt.wantMessage {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMessage)
			}

			if !errors.Is(err, tt.wantUnwrap) {
				t.Errorf("errors.Is() = false, want true for %v", tt.wantUnwrap)
			}
		})
	}
}

func TestPolicyError(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		reason      string
		wantMessage string
	}{
		{
			name:        "with rule name",
			rule:        "allow-main",
			reason:      "repository not matched",
			wantMessage: `policy error in rule "allow-main": repository not matched`,
		},
		{
			name:        "without rule name",
			rule:        "",
			reason:      "no rules defined",
			wantMessage: "policy error: no rules defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewPolicyError(tt.rule, tt.reason)

			if err.Error() != tt.wantMessage {
				t.Errorf("Error() = %q, want %q", err.Error(), tt.wantMessage)
			}
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are distinct
	sentinels := []error{
		ErrInvalidToken,
		ErrTokenExpired,
		ErrInvalidSignature,
		ErrInvalidAudience,
		ErrInvalidIssuer,
		ErrAccessDenied,
		ErrJWKSFetch,
		ErrKeyNotFound,
	}

	for i, err1 := range sentinels {
		for j, err2 := range sentinels {
			if i != j && errors.Is(err1, err2) {
				t.Errorf("sentinel errors should be distinct: %v == %v", err1, err2)
			}
		}
	}
}
