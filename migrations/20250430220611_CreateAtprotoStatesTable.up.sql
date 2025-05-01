-- Add migration script here
CREATE TABLE
  atproto_states (
    atproto_state_id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    key TEXT NOT NULL,
    encrypted_state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
  );

CREATE UNIQUE INDEX ON atproto_states (key);

-- Automatically update the updated_at column
CREATE TRIGGER update_atproto_states_updated_at BEFORE
UPDATE ON atproto_states FOR EACH ROW EXECUTE FUNCTION update_updated_at ();
