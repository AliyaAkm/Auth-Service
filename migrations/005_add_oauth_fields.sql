-- Add OAuth fields to support Google and GitHub login
ALTER TABLE users 
    ADD COLUMN oauth_provider VARCHAR(50) NULL,
    ADD COLUMN oauth_provider_id VARCHAR(255) NULL;

-- Make password_hash nullable for OAuth-only users
ALTER TABLE users 
    ALTER COLUMN password_hash DROP NOT NULL;

-- Index for fast OAuth lookup: find user by provider + provider_id
CREATE INDEX idx_oauth_provider ON users(oauth_provider, oauth_provider_id);

-- Constraint: if oauth_provider is set, oauth_provider_id must also be set
ALTER TABLE users ADD CONSTRAINT check_oauth_fields 
    CHECK (
        (oauth_provider IS NULL AND oauth_provider_id IS NULL) OR 
        (oauth_provider IS NOT NULL AND oauth_provider_id IS NOT NULL)
    );
