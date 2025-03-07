-- Add handle column to oauth_tokens table
ALTER TABLE oauth_tokens ADD COLUMN handle TEXT;
-- Add index for faster lookup by handle
CREATE INDEX oauth_tokens_handle_idx ON oauth_tokens(handle);
