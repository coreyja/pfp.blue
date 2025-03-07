-- Revert column name changes in Crons and Jobs tables
ALTER TABLE Crons RENAME COLUMN id TO cron_id;
ALTER TABLE Jobs RENAME COLUMN id TO job_id;

-- Rename primary key constraints to match original
ALTER TABLE Crons DROP CONSTRAINT crons_id_pk;
ALTER TABLE Crons ADD CONSTRAINT crons_pkey PRIMARY KEY (cron_id);

ALTER TABLE Jobs DROP CONSTRAINT jobs_id_pk;
ALTER TABLE Jobs ADD CONSTRAINT jobs_pkey PRIMARY KEY (job_id);
