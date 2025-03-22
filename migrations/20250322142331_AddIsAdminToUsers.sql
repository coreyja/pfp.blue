-- Add is_admin column to users table
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;

-- Create index for faster admin checks
CREATE INDEX users_is_admin_idx ON users(is_admin) WHERE is_admin = true;

-- For down migration: Remove column
-- ALTER TABLE users DROP COLUMN is_admin;