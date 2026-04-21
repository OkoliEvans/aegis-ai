ALTER TABLE watched_addresses
    ADD COLUMN IF NOT EXISTS is_simulation_target BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE registered_users
    ADD COLUMN IF NOT EXISTS telegram_handle TEXT;

ALTER TABLE watched_addresses
    DROP CONSTRAINT IF EXISTS watched_addresses_address_key;

CREATE UNIQUE INDEX IF NOT EXISTS watched_addresses_owner_address_idx
    ON watched_addresses (owner_address, address);

CREATE INDEX IF NOT EXISTS watched_addresses_owner_simulation_target_idx
    ON watched_addresses (owner_address, is_simulation_target);

