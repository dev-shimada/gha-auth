package ghaauth

// Effect represents the effect of a policy rule
type Effect string

const (
	// EffectAllow allows access
	EffectAllow Effect = "allow"

	// EffectDeny denies access
	EffectDeny Effect = "deny"
)

// Conditions defines the conditions that must be met for a rule to match
type Conditions struct {
	// Repository patterns (e.g., "myorg/*", "myorg/myrepo")
	Repository []string `json:"repository,omitempty"`

	// RepositoryOwner patterns (e.g., "myorg", "myorg*")
	RepositoryOwner []string `json:"repository_owner,omitempty"`

	// RepositoryVisibility values (e.g., "public", "private", "internal")
	RepositoryVisibility []string `json:"repository_visibility,omitempty"`

	// Ref patterns (e.g., "refs/heads/main", "refs/heads/**")
	Ref []string `json:"ref,omitempty"`

	// RefType values (e.g., "branch", "tag")
	RefType []string `json:"ref_type,omitempty"`

	// Workflow patterns (e.g., "CI", "Deploy*")
	Workflow []string `json:"workflow,omitempty"`

	// EventName values (e.g., "push", "pull_request", "workflow_dispatch")
	EventName []string `json:"event_name,omitempty"`

	// Actor patterns (e.g., "johndoe", "bot-*")
	Actor []string `json:"actor,omitempty"`

	// Environment patterns (e.g., "production", "staging")
	Environment []string `json:"environment,omitempty"`
}

// Rule represents a single policy rule
type Rule struct {
	// Name is an optional identifier for the rule
	Name string `json:"name,omitempty"`

	// Conditions that must be met for this rule to apply
	Conditions Conditions `json:"conditions"`

	// Effect specifies whether to allow or deny when conditions match
	Effect Effect `json:"effect"`
}

// Policy defines the access control policy
type Policy struct {
	// Rules to evaluate in order
	Rules []Rule `json:"rules"`

	// DefaultDeny specifies whether to deny access if no rules match
	// If false, unmatched requests are allowed (not recommended)
	DefaultDeny bool `json:"default_deny"`
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	// Allowed indicates whether access is allowed
	Allowed bool

	// MatchedRule is the name of the rule that matched (if any)
	MatchedRule string

	// Reason provides additional context about the decision
	Reason string
}

// Evaluate evaluates the policy against the given claims
func (p *Policy) Evaluate(claims *GitHubActionsClaims) *EvaluationResult {
	if p == nil {
		return &EvaluationResult{
			Allowed: true,
			Reason:  "no policy configured",
		}
	}

	// Evaluate each rule in order
	for _, rule := range p.Rules {
		if p.matchesRule(rule, claims) {
			allowed := rule.Effect == EffectAllow

			reason := "default"
			if rule.Name != "" {
				reason = "rule: " + rule.Name
			}

			return &EvaluationResult{
				Allowed:     allowed,
				MatchedRule: rule.Name,
				Reason:      reason,
			}
		}
	}

	// No rule matched - apply default
	if p.DefaultDeny {
		return &EvaluationResult{
			Allowed: false,
			Reason:  "default deny policy",
		}
	}

	return &EvaluationResult{
		Allowed: true,
		Reason:  "default allow (no matching rules)",
	}
}

// matchesRule checks if claims match all conditions in a rule
func (p *Policy) matchesRule(rule Rule, claims *GitHubActionsClaims) bool {
	cond := rule.Conditions

	// All specified conditions must match
	if len(cond.Repository) > 0 && !MatchAny(cond.Repository, claims.Repository) {
		return false
	}

	if len(cond.RepositoryOwner) > 0 && !MatchAny(cond.RepositoryOwner, claims.RepositoryOwner) {
		return false
	}

	if len(cond.RepositoryVisibility) > 0 && !MatchAny(cond.RepositoryVisibility, claims.RepositoryVisibility) {
		return false
	}

	if len(cond.Ref) > 0 && !MatchAny(cond.Ref, claims.Ref) {
		return false
	}

	if len(cond.RefType) > 0 && !MatchAny(cond.RefType, claims.RefType) {
		return false
	}

	if len(cond.Workflow) > 0 && !MatchAny(cond.Workflow, claims.Workflow) {
		return false
	}

	if len(cond.EventName) > 0 && !MatchAny(cond.EventName, claims.EventName) {
		return false
	}

	if len(cond.Actor) > 0 && !MatchAny(cond.Actor, claims.Actor) {
		return false
	}

	if len(cond.Environment) > 0 {
		// Environment is optional in claims, so empty matches nothing
		if claims.Environment == "" {
			return false
		}
		if !MatchAny(cond.Environment, claims.Environment) {
			return false
		}
	}

	// All conditions matched
	return true
}

// Validate checks if the policy is valid
func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}

	if len(p.Rules) == 0 {
		return NewPolicyError("", "policy must have at least one rule")
	}

	for i, rule := range p.Rules {
		if rule.Effect != EffectAllow && rule.Effect != EffectDeny {
			return NewPolicyError(rule.Name, "effect must be 'allow' or 'deny'")
		}

		// Check that at least one condition is specified
		if len(rule.Conditions.Repository) == 0 &&
			len(rule.Conditions.RepositoryOwner) == 0 &&
			len(rule.Conditions.RepositoryVisibility) == 0 &&
			len(rule.Conditions.Ref) == 0 &&
			len(rule.Conditions.RefType) == 0 &&
			len(rule.Conditions.Workflow) == 0 &&
			len(rule.Conditions.EventName) == 0 &&
			len(rule.Conditions.Actor) == 0 &&
			len(rule.Conditions.Environment) == 0 {
			ruleName := rule.Name
			if ruleName == "" {
				ruleName = string(rune(i))
			}
			return NewPolicyError(ruleName, "rule must have at least one condition")
		}
	}

	return nil
}
