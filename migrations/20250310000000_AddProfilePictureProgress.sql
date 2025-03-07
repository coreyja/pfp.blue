-- Add pgcrypto extension for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Create a table to store profile picture progress settings
CREATE TABLE
    profile_picture_progress (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
        -- Reference to the oauth_tokens table (which token this is for)
        token_id UUID NOT NULL REFERENCES oauth_tokens (id) ON DELETE CASCADE,
        -- Whether the feature is enabled
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        -- The original profile picture blob reference
        original_blob_cid TEXT,
        -- Created and updated timestamps
        created_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        updated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW ()
    );

-- Create index for faster lookup by token_id
CREATE UNIQUE INDEX profile_picture_progress_token_id_idx ON profile_picture_progress (token_id);
