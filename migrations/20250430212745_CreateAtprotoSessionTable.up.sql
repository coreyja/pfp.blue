CREATE TABLE
  atproto_sessions (
    atproto_session_id UUID PRIMARY KEY DEFAULT gen_random_uuid (),
    did TEXT NOT NULL,
    encrypted_session TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW ()
  );

CREATE FUNCTION update_updated_at () RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW ();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Automatically update the updated_at column
CREATE TRIGGER update_atproto_sessions_updated_at BEFORE
UPDATE ON atproto_sessions FOR EACH ROW EXECUTE FUNCTION update_updated_at ();
