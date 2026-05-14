ALTER TABLE users
    ADD COLUMN IF NOT EXISTS login TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS photo_url TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS max_streak INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS level INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_max_streak_non_negative'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_max_streak_non_negative CHECK (max_streak >= 0);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_level_non_negative'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_level_non_negative CHECK (level >= 0);
    END IF;
END $$;
