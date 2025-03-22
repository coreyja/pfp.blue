-- Add a handle column to store the user's Bluesky handle (@username)
ALTER TABLE oauth_tokens ADD COLUMN handle TEXT;

-- Add comment explaining the column
COMMENT ON COLUMN oauth_tokens.handle IS 'The user''s Bluesky handle (e.g., @user.bsky.social), which is their unique username on the network';
