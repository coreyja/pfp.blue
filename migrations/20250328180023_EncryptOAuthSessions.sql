-- Add encrypted columns for oauth_sessions data
-- These columns enable storing sensitive OAuth session data in encrypted form
-- We'll use these columns for all session data instead of the JSON data column

ALTER TABLE oauth_sessions
ADD COLUMN encrypted_code_verifier TEXT,
ADD COLUMN encrypted_code_challenge TEXT,
ADD COLUMN encrypted_dpop_nonce TEXT;
