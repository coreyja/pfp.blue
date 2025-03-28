-- Add encrypted columns for oauth_sessions data
-- These columns enable storing sensitive OAuth session data in encrypted form
-- Note: This migration only adds the columns. The application code will:
-- 1. Start using these columns for new sessions
-- 2. Migrate existing data when it's accessed
-- 3. Eventually we can drop the data column once all data is migrated

ALTER TABLE oauth_sessions
ADD COLUMN encrypted_code_verifier TEXT,
ADD COLUMN encrypted_code_challenge TEXT,
ADD COLUMN encrypted_dpop_nonce TEXT;

-- The JSONB data column is kept for backward compatibility
-- We'll maintain both formats during the transition period
