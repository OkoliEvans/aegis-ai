DROP INDEX IF EXISTS registered_users_email_address_idx;

ALTER TABLE registered_users
    DROP COLUMN IF EXISTS email_display_name;

ALTER TABLE registered_users
    DROP COLUMN IF EXISTS email_address;
