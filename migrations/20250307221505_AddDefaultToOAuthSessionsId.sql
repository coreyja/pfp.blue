-- Add default value to id column in oauth_sessions
ALTER TABLE oauth_sessions ALTER COLUMN id SET DEFAULT gen_random_uuid();
