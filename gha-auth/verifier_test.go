package ghaauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/example/gha-auth/internal/testutil"
)

func TestVerifier_Verify(t *testing.T) {
	// Create test token generator
	gen, err := testutil.NewTokenGenerator()
	if err != nil {
		t.Fatalf("failed to create token generator: %v", err)
	}

	// Create mock JWKS server
	server := testutil.NewJWKSServer(gen.PublicKey(), gen.KeyID())
	defer server.Close()

	ctx := context.Background()

	t.Run("valid token with matching policy", func(t *testing.T) {
		// Create policy
		policy := &Policy{
			Rules: []Rule{
				{
					Name: "allow-myorg",
					Conditions: Conditions{
						RepositoryOwner: []string{"myorg"},
					},
					Effect: EffectAllow,
				},
			},
			DefaultDeny: true,
		}

		// Create verifier
		verifier, err := New(
			WithPolicy(policy),
			WithAudience("https://api.example.com"),
			WithJWKSURL(server.URL()+"/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		// Generate token
		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		// Verify token
		result, err := verifier.Verify(ctx, tokenString)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		if result == nil {
			t.Fatal("Verify() returned nil result")
		}

		if !result.PolicyResult.Allowed {
			t.Error("expected policy to allow access")
		}

		if result.Claims.Repository != "myorg/myrepo" {
			t.Errorf("Claims.Repository = %q, want %q", result.Claims.Repository, "myorg/myrepo")
		}
	})

	t.Run("valid token but policy denies", func(t *testing.T) {
		// Create restrictive policy
		policy := &Policy{
			Rules: []Rule{
				{
					Name: "allow-other-org",
					Conditions: Conditions{
						RepositoryOwner: []string{"otherorg"},
					},
					Effect: EffectAllow,
				},
			},
			DefaultDeny: true,
		}

		verifier, err := New(
			WithPolicy(policy),
			WithAudience("https://api.example.com"),
			WithJWKSURL(server.URL()+"/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		_, err = verifier.Verify(ctx, tokenString)
		if err == nil {
			t.Fatal("Verify() expected error for denied policy")
		}

		if !errors.Is(err, ErrAccessDenied) {
			t.Errorf("Verify() error = %v, want ErrAccessDenied", err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		verifier, err := New(
			WithJWKSURL(server.URL() + "/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		// Create expired token
		claims := testutil.DefaultClaims()
		claims.ExpiresAt = time.Now().Add(-1 * time.Hour)
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		_, err = verifier.Verify(ctx, tokenString)
		if err == nil {
			t.Fatal("Verify() expected error for expired token")
		}

		if !errors.Is(err, ErrTokenExpired) {
			t.Errorf("Verify() error = %v, want ErrTokenExpired", err)
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		verifier, err := New(
			WithAudience("https://different.example.com"),
			WithJWKSURL(server.URL()+"/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		_, err = verifier.Verify(ctx, tokenString)
		if err == nil {
			t.Fatal("Verify() expected error for invalid audience")
		}

		if !errors.Is(err, ErrInvalidAudience) {
			t.Errorf("Verify() error = %v, want ErrInvalidAudience", err)
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		verifier, err := New(
			WithJWKSURL(server.URL() + "/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		claims := testutil.DefaultClaims()
		claims.Issuer = "https://invalid.example.com"
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		_, err = verifier.Verify(ctx, tokenString)
		if err == nil {
			t.Fatal("Verify() expected error for invalid issuer")
		}

		// The error is wrapped by JWT library validation, so check the chain
		var valErr *ValidationError
		if !errors.As(err, &valErr) {
			t.Errorf("Verify() error should be ValidationError, got %T", err)
		}

		// Check that ErrInvalidIssuer is in the error chain
		if !errors.Is(err, ErrInvalidIssuer) && !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Verify() error = %v, want ErrInvalidIssuer or ErrInvalidToken in chain", err)
		}
	})

	t.Run("no policy allows all", func(t *testing.T) {
		verifier, err := New(
			WithAudience("https://api.example.com"),
			WithJWKSURL(server.URL()+"/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		result, err := verifier.Verify(ctx, tokenString)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}

		if !result.PolicyResult.Allowed {
			t.Error("expected no policy to allow access")
		}
	})
}

func TestNew(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		verifier, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if verifier.jwksURL != DefaultJWKSURL {
			t.Errorf("jwksURL = %q, want %q", verifier.jwksURL, DefaultJWKSURL)
		}

		if verifier.jwksCacheDuration != DefaultCacheDuration {
			t.Errorf("jwksCacheDuration = %v, want %v", verifier.jwksCacheDuration, DefaultCacheDuration)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		policy := &Policy{
			Rules: []Rule{
				{
					Conditions: Conditions{
						Repository: []string{"myorg/*"},
					},
					Effect: EffectAllow,
				},
			},
			DefaultDeny: true,
		}

		verifier, err := New(
			WithPolicy(policy),
			WithAudience("https://api.example.com"),
			WithJWKSURL("https://custom.example.com/jwks"),
			WithJWKSCacheDuration(30*time.Minute),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		if verifier.policy != policy {
			t.Error("policy not set correctly")
		}

		if verifier.audience != "https://api.example.com" {
			t.Errorf("audience = %q, want %q", verifier.audience, "https://api.example.com")
		}

		if verifier.jwksURL != "https://custom.example.com/jwks" {
			t.Errorf("jwksURL = %q, want %q", verifier.jwksURL, "https://custom.example.com/jwks")
		}

		if verifier.jwksCacheDuration != 30*time.Minute {
			t.Errorf("jwksCacheDuration = %v, want %v", verifier.jwksCacheDuration, 30*time.Minute)
		}
	})

	t.Run("invalid policy", func(t *testing.T) {
		invalidPolicy := &Policy{
			Rules:       []Rule{},
			DefaultDeny: true,
		}

		_, err := New(WithPolicy(invalidPolicy))
		if err == nil {
			t.Fatal("New() expected error for invalid policy")
		}
	})
}

func TestVerifyToken(t *testing.T) {
	// Create test token generator
	gen, err := testutil.NewTokenGenerator()
	if err != nil {
		t.Fatalf("failed to create token generator: %v", err)
	}

	// Create mock JWKS server
	server := testutil.NewJWKSServer(gen.PublicKey(), gen.KeyID())
	defer server.Close()

	ctx := context.Background()

	t.Run("one-time verification", func(t *testing.T) {
		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		result, err := VerifyToken(ctx, tokenString,
			WithAudience("https://api.example.com"),
			WithJWKSURL(server.URL()+"/.well-known/jwks"),
		)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if result == nil {
			t.Fatal("VerifyToken() returned nil result")
		}
	})
}
