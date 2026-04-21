ALTER TABLE registered_users
    ADD COLUMN IF NOT EXISTS email_address TEXT;

ALTER TABLE registered_users
    ADD COLUMN IF NOT EXISTS email_display_name TEXT;

CREATE INDEX IF NOT EXISTS registered_users_email_address_idx
    ON registered_users (email_address);

