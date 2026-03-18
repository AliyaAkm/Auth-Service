package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type RefreshRepo struct {
	db *pgxpool.Pool
}

func NewRefreshRepo(db *pgxpool.Pool) *RefreshRepo {
	return &RefreshRepo{
		db: db,
	}
}

func (r *RefreshRepo) Create(ctx context.Context, s domain.RefreshSession) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO refresh_sessions (id, user_id, refresh_token_hash, expires_at, revoked_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, s.ID, s.UserID, s.RefreshTokenHash, s.ExpiresAt, s.RevokedAt, s.CreatedAt)
	return err
}

func (r *RefreshRepo) GetByHash(ctx context.Context, tokenHash string) (domain.RefreshSession, bool) {
	var s domain.RefreshSession
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, refresh_token_hash, expires_at, revoked_at, created_at
		FROM refresh_sessions
		WHERE refresh_token_hash = $1
	`, tokenHash).Scan(&s.ID, &s.UserID, &s.RefreshTokenHash, &s.ExpiresAt, &s.RevokedAt, &s.CreatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RefreshSession{}, false
		}
		return domain.RefreshSession{}, false
	}
	return s, true
}
func (r *RefreshRepo) RevokeByHash(ctx context.Context, hash string, when time.Time) error {
	_, err := r.db.Exec(ctx, `
        UPDATE refresh_sessions
        SET revoked_at = $2
        WHERE refresh_token_hash = $1 AND revoked_at IS NULL
    `, hash, when)
	return err
}
