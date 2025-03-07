-- Create a simpler fix by just changing the id type in oauth_tokens
-- First, save the current tokens
CREATE TABLE oauth_tokens_temp AS SELECT * FROM oauth_tokens;

-- Remove foreign key constraint from sessions
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_primary_token_id_fkey;

-- Update sessions to not reference any token (temporary)
UPDATE sessions SET primary_token_id = NULL;

-- Add a new UUID column to the oauth_tokens table
ALTER TABLE oauth_tokens ADD COLUMN uuid_id UUID DEFAULT gen_random_uuid();

-- Generate UUIDs for all existing tokens
UPDATE oauth_tokens SET uuid_id = gen_random_uuid();

-- Make the UUID column NOT NULL
ALTER TABLE oauth_tokens ALTER COLUMN uuid_id SET NOT NULL;

-- Add a unique constraint to the UUID column
ALTER TABLE oauth_tokens ADD CONSTRAINT oauth_tokens_uuid_id_key UNIQUE (uuid_id);

-- Make sure primary_token_id in sessions has the correct type
ALTER TABLE sessions ALTER COLUMN primary_token_id TYPE UUID USING NULL;

-- Create a new foreign key constraint from sessions to oauth_tokens
ALTER TABLE sessions ADD CONSTRAINT sessions_primary_token_id_fkey 
    FOREIGN KEY (primary_token_id) REFERENCES oauth_tokens(uuid_id);
