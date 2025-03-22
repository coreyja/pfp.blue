-- Add migration script here
ALTER TABLE profile_picture_progress
DROP COLUMN original_blob_cid;
