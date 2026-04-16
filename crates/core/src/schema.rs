diesel::table! {
    approval_records (id) {
        id -> diesel::sql_types::Uuid,
        owner -> diesel::sql_types::Text,
        spender -> diesel::sql_types::Text,
        token_denom -> diesel::sql_types::Text,
        amount -> diesel::sql_types::Text,
        granted_at_height -> diesel::sql_types::BigInt,
        revoked -> diesel::sql_types::Bool,
        risk_score -> diesel::sql_types::Integer,
        created_at -> diesel::sql_types::Timestamptz,
    }
}

diesel::table! {
    registered_users (id) {
        id -> diesel::sql_types::Uuid,
        address -> diesel::sql_types::Text,
        telegram_chat_id -> diesel::sql_types::Nullable<diesel::sql_types::BigInt>,
        created_at -> diesel::sql_types::Timestamptz,
    }
}

diesel::table! {
    risk_events (id) {
        id -> diesel::sql_types::Uuid,
        address -> diesel::sql_types::Text,
        event_type -> diesel::sql_types::Text,
        severity -> diesel::sql_types::Text,
        tx_hash -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        payload -> diesel::sql_types::Jsonb,
        created_at -> diesel::sql_types::Timestamptz,
    }
}

diesel::table! {
    tx_patterns (address) {
        address -> diesel::sql_types::Text,
        avg_value_uinit -> diesel::sql_types::BigInt,
        typical_recipients -> diesel::sql_types::Jsonb,
        typical_hour_utc -> diesel::sql_types::Integer,
        sample_count -> diesel::sql_types::Integer,
        updated_at -> diesel::sql_types::Timestamptz,
    }
}

diesel::table! {
    watched_addresses (id) {
        id -> diesel::sql_types::Uuid,
        address -> diesel::sql_types::Text,
        label -> diesel::sql_types::Nullable<diesel::sql_types::Text>,
        owner_address -> diesel::sql_types::Text,
        is_poisoned -> diesel::sql_types::Bool,
        risk_score -> diesel::sql_types::Integer,
        first_seen -> diesel::sql_types::Timestamptz,
        last_activity -> diesel::sql_types::Timestamptz,
    }
}
