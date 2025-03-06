-- Create users table as the central model for all user data
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Optional username that can be set later
    username TEXT UNIQUE,
    -- Optional email that can be set later
    email TEXT UNIQUE,
    -- Creation timestamp
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Last updated timestamp
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create sessions table for secure authentication
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The user this session belongs to
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    -- When this session expires
    expires_at TIMESTAMPTZ NOT NULL,
    -- Optional user agent information
    user_agent TEXT,
    -- Optional IP address for security tracking
    ip_address TEXT,
    -- Whether this session is active
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    -- Creation timestamp
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Last updated timestamp
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add index for faster lookup by session_id (although redundant with PK)
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);
-- Add index for user's active sessions
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_user_active_idx ON sessions(user_id, is_active);

-- Add user_id to oauth_tokens for the relationship
ALTER TABLE oauth_tokens ADD COLUMN user_id UUID REFERENCES users(user_id) ON DELETE CASCADE;
CREATE INDEX oauth_tokens_user_id_idx ON oauth_tokens(user_id);

-- Migration procedure to link existing tokens to users
DO $$
DECLARE
    token_record RECORD;
    new_user_id UUID;
BEGIN
    -- Process each token
    FOR token_record IN SELECT DISTINCT did FROM oauth_tokens LOOP
        -- Create a new user for this DID
        INSERT INTO users DEFAULT VALUES RETURNING user_id INTO new_user_id;
        
        -- Link all tokens for this DID to the new user
        UPDATE oauth_tokens SET user_id = new_user_id WHERE did = token_record.did;
    END LOOP;
END $$;

-- Make user_id NOT NULL after migration
ALTER TABLE oauth_tokens ALTER COLUMN user_id SET NOT NULL;
