package testutil

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
)

// JWKSServer is a mock JWKS endpoint server for testing
type JWKSServer struct {
	server    *httptest.Server
	publicKey *rsa.PublicKey
	keyID     string
}

// NewJWKSServer creates a new mock JWKS server
func NewJWKSServer(publicKey *rsa.PublicKey, keyID string) *JWKSServer {
	s := &JWKSServer{
		publicKey: publicKey,
		keyID:     keyID,
	}

	s.server = httptest.NewServer(http.HandlerFunc(s.handler))
	return s
}

// URL returns the server's URL
func (s *JWKSServer) URL() string {
	return s.server.URL
}

// Close shuts down the server
func (s *JWKSServer) Close() {
	s.server.Close()
}

// handler serves the JWKS endpoint
func (s *JWKSServer) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/.well-known/jwks.json" && r.URL.Path != "/.well-known/jwks" {
		http.NotFound(w, r)
		return
	}

	jwks := s.buildJWKS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// buildJWKS constructs the JWKS response
func (s *JWKSServer) buildJWKS() map[string]interface{} {
	n := s.publicKey.N.Bytes()
	e := big.NewInt(int64(s.publicKey.E)).Bytes()

	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": s.keyID,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(n),
				"e":   base64.RawURLEncoding.EncodeToString(e),
			},
		},
	}
}
