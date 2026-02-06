package ghaauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerificationResult contains the verified claims and policy evaluation result
type VerificationResult struct {
	// Claims from the verified token
	Claims *GitHubActionsClaims

	// PolicyResult from policy evaluation
	PolicyResult *EvaluationResult
}

// Verifier verifies GitHub Actions OIDC tokens
type Verifier struct {
	policy             *Policy
	audience           string
	jwksURL            string
	jwksCacheDuration  time.Duration
	httpClient         *http.Client
	clock              Clock
	jwksFetcher        *JWKSFetcher
}

// New creates a new Verifier with the given options
func New(opts ...Option) (*Verifier, error) {
	v := &Verifier{
		jwksURL:           DefaultJWKSURL,
		jwksCacheDuration: DefaultCacheDuration,
		httpClient:        &http.Client{Timeout: 10 * time.Second},
		clock:             DefaultClock{},
	}

	// Apply options
	for _, opt := range opts {
		opt(v)
	}

	// Validate policy if provided
	if v.policy != nil {
		if err := v.policy.Validate(); err != nil {
			return nil, err
		}
	}

	// Create JWKS fetcher
	v.jwksFetcher = NewJWKSFetcher(v.jwksURL, v.jwksCacheDuration)
	if v.httpClient != nil {
		v.jwksFetcher.httpClient = v.httpClient
	}

	return v, nil
}

// Verify verifies a GitHub Actions OIDC token and evaluates it against the policy
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*VerificationResult, error) {
	// Parse and verify the token
	claims, err := v.parseToken(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// Validate claims structure
	if err := claims.Validate(); err != nil {
		return nil, err
	}

	// Verify audience if configured
	if v.audience != "" {
		valid := false
		if aud, err := claims.RegisteredClaims.GetAudience(); err == nil {
			for _, a := range aud {
				if a == v.audience {
					valid = true
					break
				}
			}
		}
		if !valid {
			return nil, NewValidationError(ErrInvalidAudience, "audience mismatch")
		}
	}

	// Evaluate policy
	policyResult := v.policy.Evaluate(claims)
	if !policyResult.Allowed {
		return nil, NewValidationError(ErrAccessDenied, policyResult.Reason)
	}

	return &VerificationResult{
		Claims:       claims,
		PolicyResult: policyResult,
	}, nil
}

// parseToken parses and verifies the JWT token
func (v *Verifier) parseToken(ctx context.Context, tokenString string) (*GitHubActionsClaims, error) {
	var claims GitHubActionsClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, v.jwksFetcher.Keyfunc(ctx))
	if err != nil {
		// Check for specific JWT errors
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, NewValidationError(ErrTokenExpired, "token has expired")
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, NewValidationError(ErrInvalidToken, "token not valid yet")
		}
		return nil, NewValidationError(ErrInvalidToken, err.Error())
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return &claims, nil
}

// VerifyToken is a convenience function that creates a one-time verifier
func VerifyToken(ctx context.Context, tokenString string, opts ...Option) (*VerificationResult, error) {
	verifier, err := New(opts...)
	if err != nil {
		return nil, err
	}

	return verifier.Verify(ctx, tokenString)
}
