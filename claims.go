package ghaauth

import (
	"github.com/golang-jwt/jwt/v5"
)

// GitHubActionsClaims represents the claims in a GitHub Actions OIDC token
type GitHubActionsClaims struct {
	jwt.RegisteredClaims

	// Repository information
	Repository           string `json:"repository"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	RepositoryID         string `json:"repository_id"`

	// Git reference information
	Ref     string `json:"ref"`
	RefType string `json:"ref_type"`
	SHA     string `json:"sha"`

	// Workflow information
	Workflow            string `json:"workflow"`
	WorkflowRef         string `json:"workflow_ref"`
	WorkflowSHA         string `json:"workflow_sha"`
	JobWorkflowRef      string `json:"job_workflow_ref"`
	JobWorkflowSHA      string `json:"job_workflow_sha"`
	EventName           string `json:"event_name"`
	RunID               string `json:"run_id"`
	RunNumber           string `json:"run_number"`
	RunAttempt          string `json:"run_attempt"`
	RunnerEnvironment   string `json:"runner_environment"`

	// Actor information
	Actor         string `json:"actor"`
	ActorID       string `json:"actor_id"`
	TriggeringActor string `json:"triggering_actor,omitempty"`

	// Environment information
	Environment string `json:"environment,omitempty"`

	// Enterprise information
	EnterpriseID   string `json:"enterprise_id,omitempty"`
	EnterpriseSlug string `json:"enterprise_slug,omitempty"`
}

// Validate performs basic validation on the claims
func (c *GitHubActionsClaims) Validate() error {
	// Check required fields
	if c.Issuer != "https://token.actions.githubusercontent.com" {
		return NewValidationError(ErrInvalidIssuer, "expected https://token.actions.githubusercontent.com")
	}

	if c.Repository == "" {
		return NewValidationError(ErrInvalidToken, "repository claim is required")
	}

	if c.RepositoryOwner == "" {
		return NewValidationError(ErrInvalidToken, "repository_owner claim is required")
	}

	if c.Ref == "" {
		return NewValidationError(ErrInvalidToken, "ref claim is required")
	}

	if c.Workflow == "" {
		return NewValidationError(ErrInvalidToken, "workflow claim is required")
	}

	if c.EventName == "" {
		return NewValidationError(ErrInvalidToken, "event_name claim is required")
	}

	if c.Actor == "" {
		return NewValidationError(ErrInvalidToken, "actor claim is required")
	}

	return nil
}
