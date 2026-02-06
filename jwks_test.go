package ghaauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dev-shimada/gha-auth/internal/testutil"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSFetcher_GetKey(t *testing.T) {
	// Create test token generator
	gen, err := testutil.NewTokenGenerator()
	if err != nil {
		t.Fatalf("failed to create token generator: %v", err)
	}

	// Create mock JWKS server
	server := testutil.NewJWKSServer(gen.PublicKey(), gen.KeyID())
	defer server.Close()

	// Create fetcher pointing to mock server
	fetcher := NewJWKSFetcher(server.URL()+"/.well-known/jwks", 1*time.Hour)

	ctx := context.Background()

	t.Run("fetch key successfully", func(t *testing.T) {
		key, err := fetcher.GetKey(ctx, gen.KeyID())
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		if key == nil {
			t.Fatal("GetKey() returned nil key")
		}

		// Verify the key matches
		if key.N.Cmp(gen.PublicKey().N) != 0 {
			t.Error("returned key doesn't match expected key")
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		// First fetch (should populate cache)
		key1, err := fetcher.GetKey(ctx, gen.KeyID())
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		// Second fetch (should use cache)
		key2, err := fetcher.GetKey(ctx, gen.KeyID())
		if err != nil {
			t.Fatalf("GetKey() error = %v", err)
		}

		// Should be the same key object (from cache)
		if key1 != key2 {
			t.Error("expected cache hit to return same key object")
		}
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := fetcher.GetKey(ctx, "nonexistent-key")
		if err == nil {
			t.Fatal("GetKey() expected error for nonexistent key")
		}

		if !errors.Is(err, ErrKeyNotFound) {
			t.Errorf("GetKey() error = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestJWKSFetcher_Keyfunc(t *testing.T) {
	// Create test token generator
	gen, err := testutil.NewTokenGenerator()
	if err != nil {
		t.Fatalf("failed to create token generator: %v", err)
	}

	// Create mock JWKS server
	server := testutil.NewJWKSServer(gen.PublicKey(), gen.KeyID())
	defer server.Close()

	// Create fetcher pointing to mock server
	fetcher := NewJWKSFetcher(server.URL()+"/.well-known/jwks", 1*time.Hour)

	ctx := context.Background()

	t.Run("valid token", func(t *testing.T) {
		// Create a token
		claims := testutil.DefaultClaims()
		tokenString, err := gen.GenerateToken(claims.ToJWT())
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		// Parse token using keyfunc
		token, err := jwt.Parse(tokenString, fetcher.Keyfunc(ctx))
		if err != nil {
			t.Fatalf("Parse() error = %v", err)
		}

		if !token.Valid {
			t.Error("token should be valid")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		// Create token without kid
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": "test",
		})
		// Don't set kid in header

		keyfunc := fetcher.Keyfunc(ctx)
		_, err := keyfunc(token)
		if err == nil {
			t.Fatal("Keyfunc() expected error for missing kid")
		}

		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Keyfunc() error = %v, want ErrInvalidToken", err)
		}
	})

	t.Run("wrong signing method", func(t *testing.T) {
		// Create token with HMAC (not RSA)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": "test",
		})
		token.Header["kid"] = "test-key"

		keyfunc := fetcher.Keyfunc(ctx)
		_, err := keyfunc(token)
		if err == nil {
			t.Fatal("Keyfunc() expected error for wrong signing method")
		}

		if !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("Keyfunc() error = %v, want ErrInvalidSignature", err)
		}
	})
}

func TestJWKSFetcher_CacheExpiry(t *testing.T) {
	// Create test token generator
	gen, err := testutil.NewTokenGenerator()
	if err != nil {
		t.Fatalf("failed to create token generator: %v", err)
	}

	// Create mock JWKS server
	server := testutil.NewJWKSServer(gen.PublicKey(), gen.KeyID())
	defer server.Close()

	// Create fetcher with short cache duration
	fetcher := NewJWKSFetcher(server.URL()+"/.well-known/jwks", 50*time.Millisecond)

	ctx := context.Background()

	// First fetch
	_, err = fetcher.GetKey(ctx, gen.KeyID())
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	firstCacheTime := fetcher.cachedAt

	// Wait for cache to expire
	time.Sleep(100 * time.Millisecond)

	// Second fetch (should refresh)
	_, err = fetcher.GetKey(ctx, gen.KeyID())
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if !fetcher.cachedAt.After(firstCacheTime) {
		t.Error("cache should have been refreshed after expiry")
	}
}

func TestNewJWKSFetcher(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		fetcher := NewJWKSFetcher("", 0)

		if fetcher.url != DefaultJWKSURL {
			t.Errorf("url = %q, want %q", fetcher.url, DefaultJWKSURL)
		}

		if fetcher.cacheDuration != DefaultCacheDuration {
			t.Errorf("cacheDuration = %v, want %v", fetcher.cacheDuration, DefaultCacheDuration)
		}
	})

	t.Run("custom values", func(t *testing.T) {
		customURL := "https://example.com/jwks"
		customDuration := 30 * time.Minute

		fetcher := NewJWKSFetcher(customURL, customDuration)

		if fetcher.url != customURL {
			t.Errorf("url = %q, want %q", fetcher.url, customURL)
		}

		if fetcher.cacheDuration != customDuration {
			t.Errorf("cacheDuration = %v, want %v", fetcher.cacheDuration, customDuration)
		}
	})
}
