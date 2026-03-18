CREATE TABLE IF NOT EXISTS users(
    id UUID Primary key,
    email TEXT not null unique,
    password_hash text not null,
    is_active boolean not null default true,
    created_at TIMESTAMPTZ not null default now()
);

CREATE TABLE IF NOT EXISTS refresh_sessions(
    id UUID primary key,
    user_id uuid not null references user(id) on delete cascade,
    refresh_token_hash text not null unique,
    expires_at TIMESTAMPTZ nut null,
    revoked_at TIMESTAMPTZ null,
    created_at TIMESTAMPTZ nut null default now()
);

CREATE TABLE IF NOT EXISTS roles (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code         text NOT NULL UNIQUE,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    is_default   boolean NOT NULL DEFAULT false,
    is_privileged boolean NOT NULL DEFAULT false,
    is_support   boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    assigned_by uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_refresh_user_id on refresh_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);