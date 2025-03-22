-- Rename handle column to display_name in oauth_tokens table
ALTER TABLE oauth_tokens RENAME COLUMN handle TO display_name;

-- Rename index as well
DROP INDEX oauth_tokens_handle_idx;
CREATE INDEX oauth_tokens_display_name_idx ON oauth_tokens(display_name);
