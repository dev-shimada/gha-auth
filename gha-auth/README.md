# GitHub Actions OIDC Verification Package

A Go package for verifying GitHub Actions OIDC tokens and enforcing policy-based access control.

## Features

- **JWT Verification**: Validates GitHub Actions OIDC tokens using GitHub's JWKS endpoint
- **Policy-based Access Control**: Flexible rule-based authorization system
- **Pattern Matching**: Support for wildcards (`*`, `**`) in policy conditions
- **Caching**: Automatic JWKS caching to reduce external requests
- **Type-safe**: Full type definitions for GitHub Actions claims
- **Tested**: Comprehensive test coverage

## Installation

```bash
go get github.com/example/gha-auth
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"

    ghaauth "github.com/example/gha-auth"
)

func main() {
    // Define access policy
    policy := &ghaauth.Policy{
        Rules: []ghaauth.Rule{
            {
                Name: "allow-main-branch",
                Conditions: ghaauth.Conditions{
                    RepositoryOwner: []string{"myorg"},
                    Ref:             []string{"refs/heads/main"},
                },
                Effect: ghaauth.EffectAllow,
            },
        },
        DefaultDeny: true,
    }

    // Create verifier
    verifier, err := ghaauth.New(
        ghaauth.WithPolicy(policy),
        ghaauth.WithAudience("https://api.example.com"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Verify token
    token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI..." // From GitHub Actions
    result, err := verifier.Verify(context.Background(), token)
    if err != nil {
        log.Printf("Verification failed: %v", err)
        return
    }

    fmt.Printf("Access granted to %s from %s\n",
        result.Claims.Actor,
        result.Claims.Repository)
}
```

## Policy Configuration

### Basic Policy

```go
policy := &ghaauth.Policy{
    Rules: []ghaauth.Rule{
        {
            Name: "allow-specific-repo",
            Conditions: ghaauth.Conditions{
                Repository: []string{"myorg/myrepo"},
            },
            Effect: ghaauth.EffectAllow,
        },
    },
    DefaultDeny: true,
}
```

### Wildcard Patterns

The package supports two types of wildcards:

- `*` - Matches any sequence of characters except `/`
- `**` - Matches any sequence including `/`

```go
policy := &ghaauth.Policy{
    Rules: []ghaauth.Rule{
        {
            Name: "allow-org-repos",
            Conditions: ghaauth.Conditions{
                // Allow all repos in myorg
                RepositoryOwner: []string{"myorg"},

                // Allow main and all release branches
                Ref: []string{
                    "refs/heads/main",
                    "refs/heads/release/**",
                },
            },
            Effect: ghaauth.EffectAllow,
        },
    },
    DefaultDeny: true,
}
```

### Multiple Conditions

All conditions in a rule must match for the rule to apply:

```go
{
    Name: "production-deployment",
    Conditions: ghaauth.Conditions{
        Repository:  []string{"myorg/myrepo"},
        Ref:         []string{"refs/heads/main"},
        EventName:   []string{"push", "workflow_dispatch"},
        Environment: []string{"production"},
    },
    Effect: ghaauth.EffectAllow,
}
```

### Deny Rules

```go
policy := &ghaauth.Policy{
    Rules: []ghaauth.Rule{
        {
            Name: "deny-bots",
            Conditions: ghaauth.Conditions{
                Actor: []string{"bot-*", "dependabot"},
            },
            Effect: ghaauth.EffectDeny,
        },
        {
            Name: "allow-org",
            Conditions: ghaauth.Conditions{
                RepositoryOwner: []string{"myorg"},
            },
            Effect: ghaauth.EffectAllow,
        },
    },
    DefaultDeny: true,
}
```

Rules are evaluated in order - the first matching rule determines the result.

## Available Claim Conditions

Policy conditions can filter on any of these GitHub Actions claims:

- `Repository` - Full repository name (e.g., "myorg/myrepo")
- `RepositoryOwner` - Organization or user (e.g., "myorg")
- `RepositoryVisibility` - "public", "private", or "internal"
- `Ref` - Git reference (e.g., "refs/heads/main")
- `RefType` - "branch" or "tag"
- `Workflow` - Workflow name
- `EventName` - Trigger event (e.g., "push", "pull_request")
- `Actor` - User who triggered the workflow
- `Environment` - Deployment environment name

## Configuration Options

```go
verifier, err := ghaauth.New(
    // Required: Set policy
    ghaauth.WithPolicy(policy),

    // Recommended: Validate audience
    ghaauth.WithAudience("https://api.example.com"),

    // Optional: Custom JWKS URL (defaults to GitHub's endpoint)
    ghaauth.WithJWKSURL("https://custom.example.com/jwks"),

    // Optional: JWKS cache duration (defaults to 1 hour)
    ghaauth.WithJWKSCacheDuration(30 * time.Minute),

    // Optional: Custom HTTP client
    ghaauth.WithHTTPClient(customHTTPClient),
)
```

## Error Handling

The package provides typed errors for different failure scenarios:

```go
result, err := verifier.Verify(ctx, token)
if err != nil {
    switch {
    case errors.Is(err, ghaauth.ErrTokenExpired):
        log.Println("Token has expired")
    case errors.Is(err, ghaauth.ErrInvalidSignature):
        log.Println("Invalid token signature")
    case errors.Is(err, ghaauth.ErrAccessDenied):
        log.Println("Policy denied access")
    case errors.Is(err, ghaauth.ErrInvalidAudience):
        log.Println("Audience mismatch")
    default:
        log.Printf("Verification failed: %v", err)
    }
    return
}
```

Available error types:
- `ErrInvalidToken`
- `ErrTokenExpired`
- `ErrInvalidSignature`
- `ErrInvalidAudience`
- `ErrInvalidIssuer`
- `ErrAccessDenied`
- `ErrJWKSFetch`
- `ErrKeyNotFound`

## HTTP Handler Example

```go
func AuthMiddleware(next http.Handler) http.Handler {
    verifier, _ := ghaauth.New(
        ghaauth.WithPolicy(policy),
        ghaauth.WithAudience("https://api.example.com"),
    )

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from Authorization header
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization", http.StatusUnauthorized)
            return
        }

        token := strings.TrimPrefix(authHeader, "Bearer ")

        // Verify token
        result, err := verifier.Verify(r.Context(), token)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Add claims to request context
        ctx := context.WithValue(r.Context(), "claims", result.Claims)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Testing

Run the test suite:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Verifier                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  JWKSFetcher │  │   JWTParser  │  │   PolicyEvaluator    │  │
│  │  - JWKS取得  │  │  - 署名検証  │  │  - ポリシー評価      │  │
│  │  - キャッシュ │  │  - クレーム  │  │  - パターンマッチ    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

1. **JWKSFetcher**: Fetches GitHub's public keys and caches them
2. **JWTParser**: Validates token signature and extracts claims
3. **PolicyEvaluator**: Evaluates access rules against token claims
4. **Matcher**: Implements wildcard pattern matching

## Security Considerations

1. **Always validate audience**: Use `WithAudience()` to prevent token reuse
2. **Use DefaultDeny**: Set `DefaultDeny: true` in policies for fail-safe behavior
3. **Principle of least privilege**: Define narrow policy rules
4. **Keep dependencies updated**: Regularly update the jwt library
5. **HTTPS only**: JWKS fetching uses HTTPS by default

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`go test ./...`)
- Code is formatted (`go fmt ./...`)
- New features include tests
