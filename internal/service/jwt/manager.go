package jwt

import (
	"auth-service/internal/domain"
	"github.com/google/uuid"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
	jwtlib.RegisteredClaims
}

type Manager struct {
	secret   []byte
	issuer   string
	audience string
	ttl      time.Duration
}

func New(secret []byte, issuer, audience string, ttl time.Duration) *Manager {
	return &Manager{secret: secret, issuer: issuer, audience: audience, ttl: ttl}
}

func (m *Manager) NewAccessToken(userID uuid.UUID, role string, isActive bool) (string, error) {
	now := time.Now()
	claims := Claims{
		Role:     role,
		IsActive: isActive,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwtlib.ClaimStrings{m.audience},
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(m.ttl)),
		},
	}
	t := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	return t.SignedString(m.secret)
}

func (m *Manager) VerifyAccessToken(tokenStr string) (*Claims, error) {
	claims, err := m.Verify(tokenStr)
	if err != nil {
		return nil, domain.ErrInvalidToken
	}
	return claims, nil
}

func (m *Manager) Verify(tokenStr string) (*Claims, error) {
	parser := jwtlib.NewParser(jwtlib.WithValidMethods([]string{jwtlib.SigningMethodHS256.Alg()}))

	tok, err := parser.ParseWithClaims(tokenStr, &Claims{}, func(token *jwtlib.Token) (any, error) {
		return m.secret, nil
	})
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	claims, ok := tok.Claims.(*Claims)
	if !ok || !tok.Valid {
		return nil, domain.ErrInvalidToken
	}

	if claims.Issuer != m.issuer {
		return nil, domain.ErrInvalidToken
	}

	if !audienceHas(claims.Audience, m.audience) {
		return nil, domain.ErrInvalidToken
	}

	return claims, nil
}

func audienceHas(auds jwtlib.ClaimStrings, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}
