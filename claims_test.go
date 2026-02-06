package ghaauth

import (
	"errors"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGitHubActionsClaims_Validate(t *testing.T) {
	tests := []struct {
		name    string
		claims  *GitHubActionsClaims
		wantErr error
	}{
		{
			name: "valid claims",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: nil,
		},
		{
			name: "invalid issuer",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://invalid.example.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidIssuer,
		},
		{
			name: "missing repository",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing repository_owner",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing ref",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing workflow",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "",
				EventName:       "push",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing event_name",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "",
				Actor:           "johndoe",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "missing actor",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "CI",
				EventName:       "push",
				Actor:           "",
			},
			wantErr: ErrInvalidToken,
		},
		{
			name: "with optional fields",
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:         "myorg/myrepo",
				RepositoryOwner:    "myorg",
				Ref:                "refs/heads/main",
				Workflow:           "CI",
				EventName:          "push",
				Actor:              "johndoe",
				Environment:        "production",
				TriggeringActor:    "janedoe",
				EnterpriseID:       "123",
				EnterpriseSlug:     "myenterprise",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.claims.Validate()

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("Validate() error = nil, want %v", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() error = %v, want nil", err)
				}
			}
		})
	}
}
