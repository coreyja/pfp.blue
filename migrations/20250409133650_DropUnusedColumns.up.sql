-- Add migration script here
ALTER TABLE sessions
DROP COLUMN user_agent;

ALTER TABLE sessions
DROP COLUMN ip_address;

ALTER TABLE users
DROP COLUMN email;
