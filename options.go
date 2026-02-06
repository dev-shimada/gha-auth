package ghaauth

import (
	"net/http"
	"time"
)

// Option is a functional option for configuring the Verifier
type Option func(*Verifier)

// WithPolicy sets the policy to use for access control
func WithPolicy(policy *Policy) Option {
	return func(v *Verifier) {
		v.policy = policy
	}
}

// WithAudience sets the expected audience claim
func WithAudience(audience string) Option {
	return func(v *Verifier) {
		v.audience = audience
	}
}

// WithJWKSURL sets a custom JWKS URL
func WithJWKSURL(url string) Option {
	return func(v *Verifier) {
		v.jwksURL = url
	}
}

// WithJWKSCacheDuration sets how long to cache JWKS
func WithJWKSCacheDuration(duration time.Duration) Option {
	return func(v *Verifier) {
		v.jwksCacheDuration = duration
	}
}

// WithHTTPClient sets a custom HTTP client for JWKS fetching
func WithHTTPClient(client *http.Client) Option {
	return func(v *Verifier) {
		v.httpClient = client
	}
}

// WithClock sets a custom clock for time-based validation (mainly for testing)
func WithClock(clock Clock) Option {
	return func(v *Verifier) {
		v.clock = clock
	}
}

// Clock interface for time operations (useful for testing)
type Clock interface {
	Now() time.Time
}

// DefaultClock uses the system clock
type DefaultClock struct{}

func (DefaultClock) Now() time.Time {
	return time.Now()
}
