DROP INDEX IF EXISTS watched_addresses_owner_simulation_target_idx;
DROP INDEX IF EXISTS watched_addresses_owner_address_idx;

ALTER TABLE watched_addresses
    ADD CONSTRAINT watched_addresses_address_key UNIQUE (address);

ALTER TABLE registered_users
    DROP COLUMN IF EXISTS telegram_handle;

ALTER TABLE watched_addresses
    DROP COLUMN IF EXISTS is_simulation_target;

