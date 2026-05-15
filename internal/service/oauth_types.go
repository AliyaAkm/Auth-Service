package service

import "context"

// OAuthProvider - interface for OAuth providers (Google, GitHub, etc.)
type OAuthProvider interface {
	// GetAuthURL returns the URL to redirect user to for login
	GetAuthURL(state string) string

	// ExchangeCode exchanges authorization code for user info
	// Returns: email, provider ID, error
	ExchangeCode(ctx context.Context, code string) (email, providerID string, err error)
}

// UserInfo - user information returned from OAuth provider
type UserInfo struct {
	Email      string
	ProviderID string
	Name       string
}
