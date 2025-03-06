-- Drop the NOT NULL constraint on user_id
ALTER TABLE oauth_tokens ALTER COLUMN user_id DROP NOT NULL;

-- Drop the index on user_id
DROP INDEX oauth_tokens_user_id_idx;

-- Remove user_id from oauth_tokens
ALTER TABLE oauth_tokens DROP COLUMN user_id;

-- Drop user's active sessions index
DROP INDEX sessions_user_active_idx;

-- Drop user's sessions index
DROP INDEX sessions_user_id_idx;

-- Drop sessions expiration index
DROP INDEX sessions_expires_at_idx;

-- Drop sessions table
DROP TABLE sessions;

-- Drop users table
DROP TABLE users;