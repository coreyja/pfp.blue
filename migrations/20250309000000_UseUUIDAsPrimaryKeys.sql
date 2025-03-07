-- Add pgcrypto extension for gen_random_uuid
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Change primary keys in all tables from integer to UUID

-- First drop existing foreign key constraints
ALTER TABLE oauth_tokens DROP CONSTRAINT IF EXISTS oauth_tokens_user_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_primary_token_id_fkey;

-- Update oauth_tokens table
ALTER TABLE oauth_tokens 
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS oauth_tokens_pkey,
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (gen_random_uuid()),
  ADD CONSTRAINT oauth_tokens_id_pk PRIMARY KEY (id),
  -- Change user_id to UUID
  ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

-- Update oauth_sessions table  
ALTER TABLE oauth_sessions
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS oauth_sessions_pkey,
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (gen_random_uuid()),
  ADD CONSTRAINT oauth_sessions_id_pk PRIMARY KEY (id);

-- Update sessions table
ALTER TABLE sessions
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS sessions_pkey;
  
-- Rename session_id to id
ALTER TABLE sessions RENAME COLUMN session_id TO id;

-- Update rest of sessions table
ALTER TABLE sessions
  -- Add new primary key constraint
  ADD CONSTRAINT sessions_id_pk PRIMARY KEY (id),
  -- Change user_id to UUID
  ALTER COLUMN user_id TYPE UUID USING user_id::uuid,
  -- Change primary_token_id type
  ALTER COLUMN primary_token_id TYPE UUID USING (gen_random_uuid());

-- Update users table
ALTER TABLE users
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS users_pkey;

-- Rename user_id to id  
ALTER TABLE users RENAME COLUMN user_id TO id;

-- Add new primary key constraint
ALTER TABLE users ADD CONSTRAINT users_id_pk PRIMARY KEY (id);

-- Update jobs table
ALTER TABLE Jobs
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS Jobs_pkey;
  
-- Rename job_id to id
ALTER TABLE Jobs RENAME COLUMN job_id TO id;

-- Add new constraint
ALTER TABLE Jobs ADD CONSTRAINT jobs_id_pk PRIMARY KEY (id);

-- Update crons table
ALTER TABLE Crons
  -- Drop existing primary key constraint
  DROP CONSTRAINT IF EXISTS Crons_pkey;
  
-- Rename cron_id to id
ALTER TABLE Crons RENAME COLUMN cron_id TO id;

-- Add new constraint
ALTER TABLE Crons ADD CONSTRAINT crons_id_pk PRIMARY KEY (id);

-- Re-add foreign key constraints
ALTER TABLE oauth_tokens 
  ADD CONSTRAINT oauth_tokens_user_id_fkey 
  FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE sessions 
  ADD CONSTRAINT sessions_user_id_fkey 
  FOREIGN KEY (user_id) REFERENCES users(id);

ALTER TABLE sessions 
  ADD CONSTRAINT sessions_primary_token_id_fkey 
  FOREIGN KEY (primary_token_id) REFERENCES oauth_tokens(id);

-- Extension is already added at the top of the file
