ALTER TABLE profile_picture_progress
RENAME COLUMN id to profile_picture_progress_id;

ALTER TABLE profile_picture_progress
RENAME COLUMN created_at_utc to created_at;

ALTER TABLE profile_picture_progress
RENAME COLUMN updated_at_utc to updated_at;

ALTER TABLE sessions
RENAME COLUMN id to session_id;

ALTER TABLE sessions
RENAME COLUMN created_at_utc to created_at;

ALTER TABLE sessions
RENAME COLUMN updated_at_utc to updated_at;

ALTER TABLE users
RENAME COLUMN id to user_id;

ALTER TABLE users
RENAME COLUMN created_at_utc to created_at;

ALTER TABLE users
RENAME COLUMN updated_at_utc to updated_at;

ALTER TABLE users
DROP COLUMN username;
