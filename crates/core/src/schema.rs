// @generated automatically by Diesel CLI.

diesel::table! {
    approval_records (id) {
        id -> Uuid,
        owner -> Text,
        spender -> Text,
        token_denom -> Text,
        amount -> Text,
        granted_at_height -> Int8,
        revoked -> Bool,
        risk_score -> Int4,
        created_at -> Timestamptz,
        approval_type -> Nullable<Text>,
        contract_address -> Nullable<Text>,
        revoke_messages -> Jsonb,
    }
}

diesel::table! {
    registered_users (id) {
        id -> Uuid,
        address -> Text,
        telegram_chat_id -> Nullable<Int8>,
        created_at -> Timestamptz,
        telegram_handle -> Nullable<Text>,
        email_address -> Nullable<Text>,
        email_display_name -> Nullable<Text>,
    }
}

diesel::table! {
    risk_events (id) {
        id -> Uuid,
        address -> Text,
        event_type -> Text,
        severity -> Text,
        tx_hash -> Nullable<Text>,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    tx_patterns (address) {
        address -> Text,
        avg_value_uinit -> Int8,
        typical_recipients -> Jsonb,
        typical_hour_utc -> Int4,
        sample_count -> Int4,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    watched_addresses (id) {
        id -> Uuid,
        address -> Text,
        label -> Nullable<Text>,
        owner_address -> Text,
        is_poisoned -> Bool,
        risk_score -> Int4,
        first_seen -> Timestamptz,
        last_activity -> Timestamptz,
        is_simulation_target -> Bool,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    approval_records,
    registered_users,
    risk_events,
    tx_patterns,
    watched_addresses,
);
