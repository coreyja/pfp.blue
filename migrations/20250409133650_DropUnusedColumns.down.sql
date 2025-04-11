-- Add migration script here
ALTER TABLE sessions
ADD COLUMN user_agent TEXT;

ALTER TABLE sessions
ADD COLUMN ip_address TEXT;

ALTER TABLE users
ADD COLUMN email TEXT;
