-- This migration updates the foreign key constraint to use uuid_id

-- Update the sessions table to refer to the uuid_id column
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_primary_token_id_fkey;

-- Add the foreign key constraint using uuid_id
ALTER TABLE sessions ADD CONSTRAINT sessions_primary_token_id_fkey 
    FOREIGN KEY (primary_token_id) REFERENCES oauth_tokens(uuid_id);
