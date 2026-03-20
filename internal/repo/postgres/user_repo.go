package postgres

import (
	"auth-service/internal/domain"
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type UserRepo struct {
	db *pgxpool.Pool
}

func NewUserRepo(db *pgxpool.Pool) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, u domain.User) error {
	return r.CreateWithRoles(ctx, u, []string{domain.RoleStudent}, nil)
}

func (r *UserRepo) CreateWithRoles(ctx context.Context, u domain.User, roleCodes []string, assignedBy *uuid.UUID) error {
	if len(roleCodes) == 0 {
		return domain.ErrValidation
	}

	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, email, password_hash, is_active, created_at)
		VALUES ($1,$2,$3,$4,$5)
	`, u.ID, u.Email, u.PasswordHash, u.IsActive, u.CreatedAt)
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(roleCodes))
	for _, roleCode := range roleCodes {
		role, ok, err := r.getRoleByCode(ctx, tx, roleCode)
		if err != nil {
			return err
		}
		if !ok {
			return domain.ErrRoleNotFound
		}

		normalizedCode := role.Code
		if _, exists := seen[normalizedCode]; exists {
			continue
		}
		seen[normalizedCode] = struct{}{}

		_, err = tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, role_id) DO NOTHING
		`, u.ID, role.ID, assignedBy, u.CreatedAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *UserRepo) FindByEmail(ctx context.Context, email string) (domain.User, bool) {
	var u domain.User
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, is_active, created_at
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

	u.Roles, err = r.listUserRoles(ctx, r.db, u.ID)
	if err != nil {
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

	u.Roles, err = r.listUserRoles(ctx, r.db, u.ID)
	if err != nil {
		return domain.User{}, false
	}

	return u, true
}

func (r *UserRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash string) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE users
		SET password_hash = $2
		WHERE id = $1
	`, userID, passwordHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *UserRepo) UpdateStatus(ctx context.Context, userID uuid.UUID, isActive bool) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE users
		SET is_active = $2
		WHERE id = $1
	`, userID, isActive)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}

	return nil
}

func (r *UserRepo) ListUsers(ctx context.Context) ([]domain.User, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, email, password_hash, is_active, created_at
		FROM users
		ORDER BY created_at DESC, email
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.PasswordHash,
			&user.IsActive,
			&user.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		user.Roles, err = r.listUserRoles(ctx, r.db, user.ID)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (r *UserRepo) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, code, name, description, is_default, is_privileged, is_support, created_at
		FROM roles
		ORDER BY
			CASE code
				WHEN 'student' THEN 1
				WHEN 'teacher' THEN 2
				WHEN 'manager' THEN 3
				WHEN 'admin' THEN 4
				ELSE 99
			END,
			code
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanRoles(rows)
}

func (r *UserRepo) GetRoleByCode(ctx context.Context, code string) (domain.Role, bool, error) {
	return r.getRoleByCode(ctx, r.db, code)
}

func (r *UserRepo) GetRoleByID(ctx context.Context, id uuid.UUID) (domain.Role, bool, error) {
	return r.getRoleByID(ctx, r.db, id)
}

func (r *UserRepo) ReplaceUserRoles(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID, assignedBy *uuid.UUID) error {
	if len(roleIDs) == 0 {
		return domain.ErrUserMustHaveRole
	}

	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	seen := make(map[uuid.UUID]struct{}, len(roleIDs))
	for _, roleID := range roleIDs {
		if _, exists := seen[roleID]; exists {
			continue
		}
		seen[roleID] = struct{}{}

		_, err = tx.Exec(ctx, `
			INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at)
			VALUES ($1, $2, $3, NOW())
		`, userID, roleID, assignedBy)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *UserRepo) RevokeRole(ctx context.Context, userID uuid.UUID, roleID uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`, userID, roleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrRoleNotAssigned
	}

	return nil
}

func (r *UserRepo) CountUsersByRole(ctx context.Context, roleCode string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE r.code = $1
	`, roleCode).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *UserRepo) CountActiveUsersByRole(ctx context.Context, roleCode string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		INNER JOIN users u ON u.id = ur.user_id
		WHERE r.code = $1 AND u.is_active = TRUE
	`, roleCode).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

func (r *UserRepo) getRoleByCode(ctx context.Context, db queryer, code string) (domain.Role, bool, error) {
	var role domain.Role
	err := db.QueryRow(ctx, `
		SELECT id, code, name, description, is_default, is_privileged, is_support, created_at
		FROM roles
		WHERE code = $1
	`, code).Scan(
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
			return domain.Role{}, false, nil
		}
		return domain.Role{}, false, err
	}

	return role, true, nil
}

func (r *UserRepo) getRoleByID(ctx context.Context, db queryer, id uuid.UUID) (domain.Role, bool, error) {
	var role domain.Role
	err := db.QueryRow(ctx, `
		SELECT id, code, name, description, is_default, is_privileged, is_support, created_at
		FROM roles
		WHERE id = $1
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
			return domain.Role{}, false, nil
		}
		return domain.Role{}, false, err
	}

	return role, true, nil
}

func (r *UserRepo) listUserRoles(ctx context.Context, db queryer, userID uuid.UUID) ([]domain.Role, error) {
	rows, err := db.Query(ctx, `
		SELECT r.id, r.code, r.name, r.description, r.is_default, r.is_privileged, r.is_support, r.created_at
		FROM user_roles ur
		INNER JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY
			CASE r.code
				WHEN 'student' THEN 1
				WHEN 'teacher' THEN 2
				WHEN 'manager' THEN 3
				WHEN 'admin' THEN 4
				ELSE 99
			END,
			r.code
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanRoles(rows)
}

func scanRoles(rows pgx.Rows) ([]domain.Role, error) {
	var roles []domain.Role

	for rows.Next() {
		var role domain.Role
		err := rows.Scan(
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
			return nil, err
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return roles, nil
}
