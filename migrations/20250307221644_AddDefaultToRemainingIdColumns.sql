-- Add default values to remaining ID columns without defaults

-- Add default value to oauth_tokens.id
ALTER TABLE oauth_tokens ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- Add default value to jobs.job_id
ALTER TABLE jobs ALTER COLUMN job_id SET DEFAULT gen_random_uuid();

-- Add default value to crons.cron_id
ALTER TABLE crons ALTER COLUMN cron_id SET DEFAULT gen_random_uuid();
