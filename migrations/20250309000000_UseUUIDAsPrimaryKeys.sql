-- Change primary keys in all tables from integer to UUID

-- First drop existing foreign key constraints
ALTER TABLE oauth_tokens DROP CONSTRAINT IF EXISTS oauth_tokens_user_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_user_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_primary_token_id_fkey;

-- Update oauth_tokens table
ALTER TABLE oauth_tokens 
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (uuid_generate_v4()),
  ADD CONSTRAINT oauth_tokens_id_pk PRIMARY KEY (id),
  -- Change user_id to UUID
  ALTER COLUMN user_id TYPE UUID USING user_id::uuid;

-- Update oauth_sessions table  
ALTER TABLE oauth_sessions
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (uuid_generate_v4()),
  ADD CONSTRAINT oauth_sessions_id_pk PRIMARY KEY (id);

-- Update sessions table
ALTER TABLE sessions
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (uuid_generate_v4()),
  ADD CONSTRAINT sessions_id_pk PRIMARY KEY (id),
  -- Change user_id to UUID
  ALTER COLUMN user_id TYPE UUID USING user_id::uuid,
  -- Change primary_token_id type
  ALTER COLUMN primary_token_id TYPE UUID USING NULL;

-- Update users table
ALTER TABLE users
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING user_id,
  ADD CONSTRAINT users_id_pk PRIMARY KEY (id);

-- Update jobs table
ALTER TABLE jobs
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (uuid_generate_v4()),
  ADD CONSTRAINT jobs_id_pk PRIMARY KEY (id);

-- Update crons table
ALTER TABLE crons
  -- Change id from SERIAL to UUID
  ALTER COLUMN id DROP DEFAULT,
  ALTER COLUMN id TYPE UUID USING (uuid_generate_v4()),
  ADD CONSTRAINT crons_id_pk PRIMARY KEY (id);

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

-- Add uuid-ossp extension if not exists for uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
