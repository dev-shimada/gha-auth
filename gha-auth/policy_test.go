package ghaauth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestPolicy_Evaluate(t *testing.T) {
	baseClaims := &GitHubActionsClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://token.actions.githubusercontent.com",
		},
		Repository:           "myorg/myrepo",
		RepositoryOwner:      "myorg",
		RepositoryVisibility: "private",
		Ref:                  "refs/heads/main",
		RefType:              "branch",
		Workflow:             "CI",
		EventName:            "push",
		Actor:                "johndoe",
	}

	tests := []struct {
		name         string
		policy       *Policy
		claims       *GitHubActionsClaims
		wantAllowed  bool
		wantRuleName string
	}{
		{
			name:        "nil policy allows",
			policy:      nil,
			claims:      baseClaims,
			wantAllowed: true,
		},
		{
			name: "exact repository match allows",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-myrepo",
						Conditions: Conditions{
							Repository: []string{"myorg/myrepo"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:       baseClaims,
			wantAllowed:  true,
			wantRuleName: "allow-myrepo",
		},
		{
			name: "wildcard repository match allows",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-org",
						Conditions: Conditions{
							RepositoryOwner: []string{"myorg"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:       baseClaims,
			wantAllowed:  true,
			wantRuleName: "allow-org",
		},
		{
			name: "multiple conditions must all match",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-main-push",
						Conditions: Conditions{
							Repository: []string{"myorg/myrepo"},
							Ref:        []string{"refs/heads/main"},
							EventName:  []string{"push"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:       baseClaims,
			wantAllowed:  true,
			wantRuleName: "allow-main-push",
		},
		{
			name: "one condition mismatch denies",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-develop",
						Conditions: Conditions{
							Repository: []string{"myorg/myrepo"},
							Ref:        []string{"refs/heads/develop"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:      baseClaims,
			wantAllowed: false,
		},
		{
			name: "explicit deny rule",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "deny-actor",
						Conditions: Conditions{
							Actor: []string{"johndoe"},
						},
						Effect: EffectDeny,
					},
				},
				DefaultDeny: false,
			},
			claims:       baseClaims,
			wantAllowed:  false,
			wantRuleName: "deny-actor",
		},
		{
			name: "first matching rule wins",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "deny-all",
						Conditions: Conditions{
							RepositoryOwner: []string{"myorg"},
						},
						Effect: EffectDeny,
					},
					{
						Name: "allow-myrepo",
						Conditions: Conditions{
							Repository: []string{"myorg/myrepo"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:       baseClaims,
			wantAllowed:  false,
			wantRuleName: "deny-all",
		},
		{
			name: "default deny when no match",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-otherrepo",
						Conditions: Conditions{
							Repository: []string{"myorg/otherrepo"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:      baseClaims,
			wantAllowed: false,
		},
		{
			name: "default allow when no match",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "deny-otherrepo",
						Conditions: Conditions{
							Repository: []string{"myorg/otherrepo"},
						},
						Effect: EffectDeny,
					},
				},
				DefaultDeny: false,
			},
			claims:      baseClaims,
			wantAllowed: true,
		},
		{
			name: "environment condition with matching environment",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-production",
						Conditions: Conditions{
							Environment: []string{"production"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims: &GitHubActionsClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer: "https://token.actions.githubusercontent.com",
				},
				Repository:      "myorg/myrepo",
				RepositoryOwner: "myorg",
				Ref:             "refs/heads/main",
				Workflow:        "Deploy",
				EventName:       "push",
				Actor:           "johndoe",
				Environment:     "production",
			},
			wantAllowed:  true,
			wantRuleName: "allow-production",
		},
		{
			name: "environment condition with empty environment denies",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-production",
						Conditions: Conditions{
							Environment: []string{"production"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:      baseClaims, // no Environment set
			wantAllowed: false,
		},
		{
			name: "visibility condition",
			policy: &Policy{
				Rules: []Rule{
					{
						Name: "allow-private-repos",
						Conditions: Conditions{
							RepositoryVisibility: []string{"private"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			claims:       baseClaims,
			wantAllowed:  true,
			wantRuleName: "allow-private-repos",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.policy.Evaluate(tt.claims)

			if result.Allowed != tt.wantAllowed {
				t.Errorf("Evaluate().Allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}

			if tt.wantRuleName != "" && result.MatchedRule != tt.wantRuleName {
				t.Errorf("Evaluate().MatchedRule = %q, want %q", result.MatchedRule, tt.wantRuleName)
			}
		})
	}
}

func TestPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantErr bool
	}{
		{
			name:    "nil policy is valid",
			policy:  nil,
			wantErr: false,
		},
		{
			name: "valid policy",
			policy: &Policy{
				Rules: []Rule{
					{
						Conditions: Conditions{
							Repository: []string{"myorg/*"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			wantErr: false,
		},
		{
			name: "empty rules",
			policy: &Policy{
				Rules:       []Rule{},
				DefaultDeny: true,
			},
			wantErr: true,
		},
		{
			name: "invalid effect",
			policy: &Policy{
				Rules: []Rule{
					{
						Conditions: Conditions{
							Repository: []string{"myorg/*"},
						},
						Effect: Effect("invalid"),
					},
				},
				DefaultDeny: true,
			},
			wantErr: true,
		},
		{
			name: "no conditions",
			policy: &Policy{
				Rules: []Rule{
					{
						Conditions: Conditions{},
						Effect:     EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			wantErr: true,
		},
		{
			name: "multiple valid conditions",
			policy: &Policy{
				Rules: []Rule{
					{
						Conditions: Conditions{
							Repository: []string{"myorg/*"},
							Ref:        []string{"refs/heads/main"},
							EventName:  []string{"push"},
						},
						Effect: EffectAllow,
					},
				},
				DefaultDeny: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
