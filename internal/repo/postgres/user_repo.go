package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"
	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{
		db: db,
	}
}

func (r *UserRepo) Create(ctx context.Context, u domain.User) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, is_active, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
	`, u.ID, u.Email, u.PasswordHash, u.IsActive, u.CreatedAt) // todo role_id
	return err
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (domain.User, bool) {
	var u domain.User
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash,  is_active, created_at
		FROM users
		WHERE email = $1
	`, email).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.IsActive,
		&u.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, false
		}
		return domain.User{}, false
	}

	return u, true
}

func (r *UserRepo) FindByID(ctx context.Context, id uuid.UUID) (domain.User, bool) {
	var u domain.User
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, is_active, created_at
		FROM users
		WHERE id = $1
	`, id).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.IsActive,
		&u.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.User{}, false
		}
		return domain.User{}, false
	}
	return u, true
}
func (r *UserRepo) FindUserRoles(ctx context.Context, id uuid.UUID) (domain.Role, bool) {
	var role domain.Role
	err := r.db.QueryRow(ctx, `
	Select id, code, name, description, is_default, is_privileged, is_support, created_at
	from roles
	where id = $1
`, id).Scan(
		&role.ID,
		&role.Code,
		&role.Name,
		&role.Description,
		&role.IsDefault,
		&role.IsPrivileged,
		&role.IsSupport,
		&role.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Role{}, false
		}
		return domain.Role{}, false
	}
	return role, true
}
