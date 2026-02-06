package ghaauth

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidToken is returned when the token format is invalid
	ErrInvalidToken = errors.New("invalid token")

	// ErrTokenExpired is returned when the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidSignature is returned when the token signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidAudience is returned when the audience claim doesn't match
	ErrInvalidAudience = errors.New("invalid audience")

	// ErrInvalidIssuer is returned when the issuer is not GitHub
	ErrInvalidIssuer = errors.New("invalid issuer")

	// ErrAccessDenied is returned when policy evaluation denies access
	ErrAccessDenied = errors.New("access denied by policy")

	// ErrJWKSFetch is returned when JWKS fetching fails
	ErrJWKSFetch = errors.New("failed to fetch JWKS")

	// ErrKeyNotFound is returned when the signing key is not found in JWKS
	ErrKeyNotFound = errors.New("signing key not found")
)

// ValidationError wraps an error with additional context
type ValidationError struct {
	Err    error
	Reason string
}

func (e *ValidationError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("%v: %s", e.Err, e.Reason)
	}
	return e.Err.Error()
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new ValidationError
func NewValidationError(err error, reason string) error {
	return &ValidationError{
		Err:    err,
		Reason: reason,
	}
}

// PolicyError represents a policy evaluation error
type PolicyError struct {
	Rule   string
	Reason string
}

func (e *PolicyError) Error() string {
	if e.Rule != "" {
		return fmt.Sprintf("policy error in rule %q: %s", e.Rule, e.Reason)
	}
	return fmt.Sprintf("policy error: %s", e.Reason)
}

// NewPolicyError creates a new PolicyError
func NewPolicyError(rule, reason string) error {
	return &PolicyError{
		Rule:   rule,
		Reason: reason,
	}
}
