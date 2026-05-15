package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleProvider struct {
	config *oauth2.Config
}

// NewGoogleProvider initializes Google OAuth2 provider
func NewGoogleProvider(clientID, clientSecret, redirectURL string) *GoogleProvider {
	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"openid",
				"email",
				"profile",
			},
			Endpoint: google.Endpoint,
		},
	}
}

// GetAuthURL returns the URL to redirect user to Google login
// state should be a random string stored in session for CSRF protection
func (p *GoogleProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// ExchangeCode exchanges authorization code for user email and Google ID
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (email, providerID string, err error) {
	// 1. Exchange authorization code for access token
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// 2. Use token to fetch user info from Google
	client := p.config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo?alt=json")
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch user info: %w", err)
	}
	defer resp.Body.Close()

	// 3. Parse JSON response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read response: %w", err)
	}

	var userInfo struct {
		Email string `json:"email"`
		ID    string `json:"id"` // Google's unique ID (subject)
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return "", "", fmt.Errorf("failed to parse user info: %w", err)
	}

	if userInfo.Email == "" || userInfo.ID == "" {
		return "", "", fmt.Errorf("missing email or id in user info")
	}

	return userInfo.Email, userInfo.ID, nil
}
