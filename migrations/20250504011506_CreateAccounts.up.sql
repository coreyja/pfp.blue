-- Add migration script here
CREATE TABLE
  accounts (
    account_id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid (),
    user_id UUID NOT NULL REFERENCES users (id),
    did TEXT NOT NULL UNIQUE,
    display_name TEXT,
    handle TEXT,
    created_at TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP
    WITH
      TIME ZONE DEFAULT CURRENT_TIMESTAMP
  );
