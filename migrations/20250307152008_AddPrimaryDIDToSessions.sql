-- Add primary_token_id column to sessions table
-- This will reference the oauth_tokens table to identify the user's primary account
ALTER TABLE sessions ADD COLUMN primary_token_id BIGINT REFERENCES oauth_tokens(id);

-- Add index for faster lookups
CREATE INDEX sessions_primary_token_id_idx ON sessions(primary_token_id);
