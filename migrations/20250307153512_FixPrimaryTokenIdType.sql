-- Fix type of primary_token_id in sessions table to match oauth_tokens.id
ALTER TABLE sessions DROP CONSTRAINT sessions_primary_token_id_fkey;
ALTER TABLE sessions ALTER COLUMN primary_token_id TYPE INT;
ALTER TABLE sessions ADD CONSTRAINT sessions_primary_token_id_fkey FOREIGN KEY (primary_token_id) REFERENCES oauth_tokens(id);
