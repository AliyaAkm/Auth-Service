package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"net/http"
)

type GitHubProvider struct {
	config *oauth2.Config
}

// NewGitHubProvider initializes GitHub OAuth2 provider
func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"user:email",
			},
			Endpoint: github.Endpoint,
		},
	}
}

// GetAuthURL returns the URL to redirect user to GitHub login
func (p *GitHubProvider) GetAuthURL(state string) string {
	return p.config.AuthCodeURL(state)
}

// ExchangeCode exchanges authorization code for user email and GitHub ID
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (email, providerID string, err error) {
	// 1. Exchange authorization code for access token
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("failed to exchange code: %w", err)
	}

	// 2. Use token to fetch user info from GitHub
	client := p.config.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
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
		ID    int    `json:"id"`    // GitHub unique ID
		Email string `json:"email"` // Can be null if private
	}

	if err := json.Unmarshal(body, &userInfo); err != nil {
		return "", "", fmt.Errorf("failed to parse user info: %w", err)
	}

	// If email is private, fetch it separately
	if userInfo.Email == "" {
		email, err = getGitHubUserEmail(ctx, client)
		if err != nil {
			return "", "", fmt.Errorf("failed to fetch email: %w", err)
		}
	} else {
		email = userInfo.Email
	}

	if email == "" {
		return "", "", fmt.Errorf("no email found")
	}

	providerID = strconv.Itoa(userInfo.ID)
	return email, providerID, nil
}

// getGitHubUserEmail fetches email from GitHub if it's private
func getGitHubUserEmail(ctx context.Context, client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", fmt.Errorf("failed to fetch emails: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read emails: %w", err)
	}

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("failed to parse emails: %w", err)
	}

	// Return primary email
	for _, e := range emails {
		if e.Primary {
			return e.Email, nil
		}
	}

	// If no primary found, return first one
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}
