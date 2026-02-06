package ghaauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultJWKSURL is GitHub's JWKS endpoint
	DefaultJWKSURL = "https://token.actions.githubusercontent.com/.well-known/jwks"

	// DefaultCacheDuration is how long to cache JWKS
	DefaultCacheDuration = 1 * time.Hour
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSFetcher fetches and caches JWKS
type JWKSFetcher struct {
	url           string
	httpClient    *http.Client
	cacheDuration time.Duration

	mu    sync.RWMutex
	cache map[string]*rsa.PublicKey
	cachedAt time.Time
}

// NewJWKSFetcher creates a new JWKS fetcher
func NewJWKSFetcher(url string, cacheDuration time.Duration) *JWKSFetcher {
	if url == "" {
		url = DefaultJWKSURL
	}
	if cacheDuration == 0 {
		cacheDuration = DefaultCacheDuration
	}

	return &JWKSFetcher{
		url:           url,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
		cacheDuration: cacheDuration,
		cache:         make(map[string]*rsa.PublicKey),
	}
}

// GetKey returns the public key for the given key ID
func (f *JWKSFetcher) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	f.mu.RLock()
	if key, ok := f.cache[kid]; ok && time.Since(f.cachedAt) < f.cacheDuration {
		f.mu.RUnlock()
		return key, nil
	}
	f.mu.RUnlock()

	// Fetch JWKS
	if err := f.refresh(ctx); err != nil {
		return nil, err
	}

	// Try cache again
	f.mu.RLock()
	key, ok := f.cache[kid]
	f.mu.RUnlock()

	if !ok {
		return nil, NewValidationError(ErrKeyNotFound, fmt.Sprintf("key ID %q not found in JWKS", kid))
	}

	return key, nil
}

// refresh fetches the JWKS and updates the cache
func (f *JWKSFetcher) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", f.url, nil)
	if err != nil {
		return NewValidationError(ErrJWKSFetch, err.Error())
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return NewValidationError(ErrJWKSFetch, err.Error())
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return NewValidationError(ErrJWKSFetch, fmt.Sprintf("HTTP %d", resp.StatusCode))
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return NewValidationError(ErrJWKSFetch, err.Error())
	}

	// Convert JWKs to RSA public keys
	newCache := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}

		key, err := jwkToPublicKey(jwk)
		if err != nil {
			// Skip invalid keys but don't fail entirely
			continue
		}

		newCache[jwk.Kid] = key
	}

	// Update cache
	f.mu.Lock()
	f.cache = newCache
	f.cachedAt = time.Now()
	f.mu.Unlock()

	return nil
}

// jwkToPublicKey converts a JWK to an RSA public key
func jwkToPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode N (modulus) - base64url without padding
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}

	// Decode E (exponent) - base64url without padding
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	// Convert to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Create RSA public key
	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// Keyfunc returns a jwt.Keyfunc for use with jwt.Parse
func (f *JWKSFetcher) Keyfunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, NewValidationError(ErrInvalidSignature, fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]))
		}

		// Get key ID from header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, NewValidationError(ErrInvalidToken, "missing kid in token header")
		}

		// Fetch key
		return f.GetKey(ctx, kid)
	}
}
