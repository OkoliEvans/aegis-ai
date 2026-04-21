ALTER TABLE approval_records
    ADD COLUMN IF NOT EXISTS approval_type TEXT,
    ADD COLUMN IF NOT EXISTS contract_address TEXT,
    ADD COLUMN IF NOT EXISTS revoke_messages JSONB NOT NULL DEFAULT '[]'::jsonb;
