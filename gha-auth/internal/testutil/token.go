package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenGenerator helps create test JWT tokens
type TokenGenerator struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewTokenGenerator creates a new token generator with a random RSA key pair
func NewTokenGenerator() (*TokenGenerator, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &TokenGenerator{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      "test-key-1",
	}, nil
}

// PublicKey returns the public key
func (g *TokenGenerator) PublicKey() *rsa.PublicKey {
	return g.publicKey
}

// KeyID returns the key ID
func (g *TokenGenerator) KeyID() string {
	return g.keyID
}

// GenerateToken creates a signed JWT token with the given claims
func (g *TokenGenerator) GenerateToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyID

	return token.SignedString(g.privateKey)
}

// TokenClaims is a helper for building test token claims
type TokenClaims struct {
	Issuer              string
	Subject             string
	Audience            []string
	ExpiresAt           time.Time
	IssuedAt            time.Time
	NotBefore           time.Time
	Repository          string
	RepositoryOwner     string
	RepositoryOwnerID   string
	RepositoryVisibility string
	RepositoryID        string
	Ref                 string
	RefType             string
	SHA                 string
	Workflow            string
	WorkflowRef         string
	WorkflowSHA         string
	JobWorkflowRef      string
	JobWorkflowSHA      string
	EventName           string
	RunID               string
	RunNumber           string
	RunAttempt          string
	RunnerEnvironment   string
	Actor               string
	ActorID             string
	TriggeringActor     string
	Environment         string
	EnterpriseID        string
	EnterpriseSlug      string
}

// DefaultClaims returns a set of valid default claims for testing
func DefaultClaims() *TokenClaims {
	now := time.Now()
	return &TokenClaims{
		Issuer:              "https://token.actions.githubusercontent.com",
		Subject:             "repo:myorg/myrepo:ref:refs/heads/main",
		Audience:            []string{"https://api.example.com"},
		ExpiresAt:           now.Add(5 * time.Minute),
		IssuedAt:            now,
		NotBefore:           now,
		Repository:          "myorg/myrepo",
		RepositoryOwner:     "myorg",
		RepositoryOwnerID:   "12345",
		RepositoryVisibility: "private",
		RepositoryID:        "67890",
		Ref:                 "refs/heads/main",
		RefType:             "branch",
		SHA:                 "abc123def456",
		Workflow:            "CI",
		WorkflowRef:         "myorg/myrepo/.github/workflows/ci.yml@refs/heads/main",
		WorkflowSHA:         "abc123def456",
		JobWorkflowRef:      "myorg/myrepo/.github/workflows/ci.yml@refs/heads/main",
		JobWorkflowSHA:      "abc123def456",
		EventName:           "push",
		RunID:               "123456789",
		RunNumber:           "42",
		RunAttempt:          "1",
		RunnerEnvironment:   "github-hosted",
		Actor:               "johndoe",
		ActorID:             "11111",
	}
}

// ToJWT converts TokenClaims to jwt.MapClaims
func (tc *TokenClaims) ToJWT() jwt.MapClaims {
	claims := jwt.MapClaims{}

	if tc.Issuer != "" {
		claims["iss"] = tc.Issuer
	}
	if tc.Subject != "" {
		claims["sub"] = tc.Subject
	}
	if len(tc.Audience) > 0 {
		claims["aud"] = tc.Audience
	}
	if !tc.ExpiresAt.IsZero() {
		claims["exp"] = tc.ExpiresAt.Unix()
	}
	if !tc.IssuedAt.IsZero() {
		claims["iat"] = tc.IssuedAt.Unix()
	}
	if !tc.NotBefore.IsZero() {
		claims["nbf"] = tc.NotBefore.Unix()
	}

	// GitHub Actions specific claims
	if tc.Repository != "" {
		claims["repository"] = tc.Repository
	}
	if tc.RepositoryOwner != "" {
		claims["repository_owner"] = tc.RepositoryOwner
	}
	if tc.RepositoryOwnerID != "" {
		claims["repository_owner_id"] = tc.RepositoryOwnerID
	}
	if tc.RepositoryVisibility != "" {
		claims["repository_visibility"] = tc.RepositoryVisibility
	}
	if tc.RepositoryID != "" {
		claims["repository_id"] = tc.RepositoryID
	}
	if tc.Ref != "" {
		claims["ref"] = tc.Ref
	}
	if tc.RefType != "" {
		claims["ref_type"] = tc.RefType
	}
	if tc.SHA != "" {
		claims["sha"] = tc.SHA
	}
	if tc.Workflow != "" {
		claims["workflow"] = tc.Workflow
	}
	if tc.WorkflowRef != "" {
		claims["workflow_ref"] = tc.WorkflowRef
	}
	if tc.WorkflowSHA != "" {
		claims["workflow_sha"] = tc.WorkflowSHA
	}
	if tc.JobWorkflowRef != "" {
		claims["job_workflow_ref"] = tc.JobWorkflowRef
	}
	if tc.JobWorkflowSHA != "" {
		claims["job_workflow_sha"] = tc.JobWorkflowSHA
	}
	if tc.EventName != "" {
		claims["event_name"] = tc.EventName
	}
	if tc.RunID != "" {
		claims["run_id"] = tc.RunID
	}
	if tc.RunNumber != "" {
		claims["run_number"] = tc.RunNumber
	}
	if tc.RunAttempt != "" {
		claims["run_attempt"] = tc.RunAttempt
	}
	if tc.RunnerEnvironment != "" {
		claims["runner_environment"] = tc.RunnerEnvironment
	}
	if tc.Actor != "" {
		claims["actor"] = tc.Actor
	}
	if tc.ActorID != "" {
		claims["actor_id"] = tc.ActorID
	}
	if tc.TriggeringActor != "" {
		claims["triggering_actor"] = tc.TriggeringActor
	}
	if tc.Environment != "" {
		claims["environment"] = tc.Environment
	}
	if tc.EnterpriseID != "" {
		claims["enterprise_id"] = tc.EnterpriseID
	}
	if tc.EnterpriseSlug != "" {
		claims["enterprise_slug"] = tc.EnterpriseSlug
	}

	return claims
}
