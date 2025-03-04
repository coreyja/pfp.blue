-- Create sessions table for storing OAuth sessions
CREATE TABLE oauth_sessions (
    id SERIAL PRIMARY KEY,
    -- A unique session ID for identifying this session
    session_id UUID NOT NULL UNIQUE,
    -- The user's DID
    did TEXT NOT NULL,
    -- Original redirect URI provided to the authorize endpoint (optional)
    redirect_uri TEXT,
    -- State parameter passed to the authorize endpoint (optional)
    state TEXT,
    -- The authorization server's token endpoint
    token_endpoint TEXT NOT NULL,
    -- The timestamp when this session was created
    created_at BIGINT NOT NULL,
    -- JSON representation of additional data
    data JSONB DEFAULT '{}'::JSONB,
    -- Creation timestamp
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Last updated timestamp
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add index for faster lookup by session_id
CREATE INDEX oauth_sessions_session_id_idx ON oauth_sessions(session_id);
-- Add index for faster lookup by did
CREATE INDEX oauth_sessions_did_idx ON oauth_sessions(did);
-- Add index for cleanup of expired sessions
CREATE INDEX oauth_sessions_created_at_idx ON oauth_sessions(created_at);

-- Create tokens table for storing OAuth tokens
CREATE TABLE oauth_tokens (
    id SERIAL PRIMARY KEY,
    -- The user's DID that this token belongs to
    did TEXT NOT NULL,
    -- The access token for making API requests
    access_token TEXT NOT NULL,
    -- The token type (usually "Bearer")
    token_type TEXT NOT NULL,
    -- When the access token expires (as Unix timestamp)
    expires_at BIGINT NOT NULL,
    -- Refresh token for obtaining a new access token (optional)
    refresh_token TEXT,
    -- The scopes granted to this token
    scope TEXT NOT NULL,
    -- DPoP JWK thumbprint for DPoP-bound tokens
    dpop_jkt TEXT,
    -- Whether this token is currently active
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    -- Creation timestamp
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Last updated timestamp
    updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add index for faster lookup by did
CREATE INDEX oauth_tokens_did_idx ON oauth_tokens(did);
-- Add index for faster lookup of active tokens
CREATE INDEX oauth_tokens_active_idx ON oauth_tokens(is_active);
-- Add index for faster lookup of tokens by expiration
CREATE INDEX oauth_tokens_expires_idx ON oauth_tokens(expires_at);