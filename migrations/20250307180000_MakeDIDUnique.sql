-- Make DID unique and remove is_active since we'll use uniqueness instead
-- First, drop foreign keys that might reference oauth_tokens
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_primary_token_id_fkey;

-- First, drop any indexes that might include is_active
DROP INDEX IF EXISTS oauth_tokens_did_active_idx;
DROP INDEX IF EXISTS oauth_tokens_active_idx;

-- If duplicate DIDs exist, keep only the most recent active token for each DID
CREATE TEMPORARY TABLE latest_tokens AS
SELECT DISTINCT ON (did) id, did, access_token, token_type, expires_at, refresh_token, scope, dpop_jkt, user_id, handle, created_at_utc, updated_at_utc
FROM oauth_tokens 
WHERE is_active = TRUE
ORDER BY did, created_at_utc DESC;

-- Delete all tokens that aren't the latest active ones
DELETE FROM oauth_tokens 
WHERE id NOT IN (SELECT id FROM latest_tokens);

-- Remove the is_active column since we'll use uniqueness instead
ALTER TABLE oauth_tokens DROP COLUMN is_active;

-- Add unique constraint on DID
ALTER TABLE oauth_tokens ADD CONSTRAINT oauth_tokens_did_unique UNIQUE (did);

-- Add any foreign key back to sessions table pointing to oauth_tokens
ALTER TABLE sessions ADD CONSTRAINT sessions_primary_token_id_fkey 
    FOREIGN KEY (primary_token_id) REFERENCES oauth_tokens(id) ON DELETE SET NULL;
