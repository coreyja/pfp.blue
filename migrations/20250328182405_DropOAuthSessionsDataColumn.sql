-- IMPORTANT: This migration depends on 20250328180023_EncryptOAuthSessions.sql
-- Make sure that migration is applied first.
--
-- Since the production DB is empty, we can directly remove the 'data' column
-- without worrying about backward compatibility. The application code has been
-- updated to use the encrypted columns from the previous migration.

-- Drop the JSONB data column
ALTER TABLE oauth_sessions DROP COLUMN data;
