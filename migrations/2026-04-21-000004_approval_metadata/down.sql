ALTER TABLE approval_records
    DROP COLUMN IF EXISTS revoke_messages,
    DROP COLUMN IF EXISTS contract_address,
    DROP COLUMN IF EXISTS approval_type;
