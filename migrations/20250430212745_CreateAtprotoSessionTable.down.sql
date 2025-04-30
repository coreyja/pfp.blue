-- Add migration script here
DROP TABLE atproto_sessions;

DROP FUNCTION IF EXISTS update_updated_at;
