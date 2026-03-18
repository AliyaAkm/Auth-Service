package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PasswordResetRepo struct {
	db *pgxpool.Pool
}

func NewPasswordResetRepo(db *pgxpool.Pool) *PasswordResetRepo {
	return &PasswordResetRepo{db: db}
}

func (r *PasswordResetRepo) Create(ctx context.Context, reset domain.PasswordResetCode) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO password_reset_codes (id, user_id, code_hash, expires_at, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, reset.ID, reset.UserID, reset.CodeHash, reset.ExpiresAt, reset.UsedAt, reset.CreatedAt)
	return err
}

func (r *PasswordResetRepo) GetActiveByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, codeHash string, now time.Time) (domain.PasswordResetCode, bool, error) {
	var reset domain.PasswordResetCode
	err := r.db.QueryRow(ctx, `
		SELECT id, user_id, code_hash, expires_at, used_at, created_at
		FROM password_reset_codes
		WHERE user_id = $1
		  AND code_hash = $2
		  AND used_at IS NULL
		  AND expires_at > $3
		ORDER BY created_at DESC
		LIMIT 1
	`, userID, codeHash, now).Scan(
		&reset.ID,
		&reset.UserID,
		&reset.CodeHash,
		&reset.ExpiresAt,
		&reset.UsedAt,
		&reset.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.PasswordResetCode{}, false, nil
		}
		return domain.PasswordResetCode{}, false, err
	}

	return reset, true, nil
}

func (r *PasswordResetRepo) InvalidateActiveByUserID(ctx context.Context, userID uuid.UUID, when time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE password_reset_codes
		SET used_at = $2
		WHERE user_id = $1
		  AND used_at IS NULL
		  AND expires_at > $2
	`, userID, when)
	return err
}

func (r *PasswordResetRepo) MarkUsed(ctx context.Context, resetID uuid.UUID, when time.Time) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE password_reset_codes
		SET used_at = $2
		WHERE id = $1 AND used_at IS NULL
	`, resetID, when)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidResetCode
	}

	return nil
}
