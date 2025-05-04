-- Add migration script here
ALTER TABLE sessions
DROP COLUMN primary_token_id;

ALTER TABLE sessions
ADD COLUMN primary_account_id uuid NOT NULL REFERENCES accounts (account_id);

CREATE INDEX sessions_primary_account_id_idx ON sessions (primary_account_id);

ALTER TABLE profile_picture_progress
DROP COLUMN token_id;

ALTER TABLE profile_picture_progress
ADD COLUMN account_id uuid NOT NULL REFERENCES accounts (account_id);

CREATE INDEX profile_picture_progress_account_id_idx ON profile_picture_progress (account_id);

DROP TABLE oauth_tokens;
