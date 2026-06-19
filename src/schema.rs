//! Diesel table definitions. Hand-written rather than emitted by `diesel
//! print-schema` so they're identical for both backends — every column is
//! `Text` / `Nullable<Text>` / `Integer`, with timestamps as ISO-8601 UTC
//! strings. See `migrations/{sqlite,postgres}/...` for the SQL.

diesel::table! {
    webhook_outbox (id) {
        id -> Text,
        event_id -> Text,
        client_id -> Text,
        url -> Text,
        payload -> Text,
        state -> Text,
        attempts -> Integer,
        next_attempt_at -> Text,
        last_error -> Nullable<Text>,
        created_at -> Text,
        delivered_at -> Nullable<Text>,
    }
}

diesel::table! {
    _forseti_meta (key) {
        key -> Text,
        value -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    secret_reveals (token) {
        token -> Text,
        payload -> Text,
        created_at -> Text,
        attempts -> Integer,
    }
}

diesel::table! {
    dcr_initial_access_tokens (id) {
        id -> Text,
        token_hash -> Text,
        created_by -> Text,
        created_at -> Text,
        expires_at -> Nullable<Text>,
        uses_remaining -> Nullable<Integer>,
        revoked_at -> Nullable<Text>,
        note -> Text,
        daily_use_count -> Integer,
        daily_window_started_at -> Nullable<Text>,
    }
}

diesel::table! {
    oauth_client_metadata (client_id) {
        client_id -> Text,
        verification -> Text,
        verified_by -> Nullable<Text>,
        verified_at -> Nullable<Text>,
        verification_revoked_by -> Nullable<Text>,
        verification_revoked_at -> Nullable<Text>,
        source -> Text,
        dcr_iat_id -> Nullable<Text>,
        dcr_registered_at -> Nullable<Text>,
        created_at -> Text,
        audience -> Nullable<Text>,
        resource_url -> Nullable<Text>,
        org_id -> Text,
        template_slug -> Nullable<Text>,
    }
}

diesel::table! {
    organizations (id) {
        id -> Text,
        slug -> Text,
        name -> Text,
        logo_url -> Nullable<Text>,
        support_email -> Nullable<Text>,
        created_at -> Text,
        created_by -> Nullable<Text>,
    }
}

diesel::table! {
    organization_members (org_id, identity_id) {
        org_id -> Text,
        identity_id -> Text,
        role -> Text,
        added_at -> Text,
        added_by -> Nullable<Text>,
    }
}

diesel::table! {
    organization_invites (token) {
        token -> Text,
        org_id -> Text,
        email -> Text,
        role -> Text,
        invited_by -> Nullable<Text>,
        created_at -> Text,
        expires_at -> Text,
        accepted_at -> Nullable<Text>,
        accepted_by -> Nullable<Text>,
    }
}

diesel::table! {
    forseti_license (id) {
        id -> Text,
        blob -> Text,
        license_id -> Text,
        customer -> Text,
        email -> Text,
        tier -> Text,
        issued_at -> Text,
        expires_at -> Nullable<Text>,
        features -> Text,
        max_orgs -> Nullable<Integer>,
        max_seats -> Nullable<Integer>,
        activated_at -> Text,
        verified_at -> Text,
    }
}

diesel::table! {
    audit_events (id) {
        id -> Text,
        created_at -> Text,
        actor_kind -> Text,
        actor_id -> Nullable<Text>,
        actor_email -> Nullable<Text>,
        action -> Text,
        target_kind -> Nullable<Text>,
        target_id -> Nullable<Text>,
        org_id -> Nullable<Text>,
        ip_hash -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        request_id -> Nullable<Text>,
        severity -> Text,
        success -> Integer,
        metadata -> Text,
    }
}

diesel::table! {
    member_profiles (identity_id) {
        identity_id -> Text,
        bio -> Nullable<Text>,
        location -> Nullable<Text>,
        pronouns -> Nullable<Text>,
        website -> Nullable<Text>,
        avatar_url -> Nullable<Text>,
        links_json -> Nullable<Text>,
        updated_at -> Text,
    }
}

diesel::table! {
    saml_connections (org_id) {
        org_id -> Text,
        enabled -> Integer,
        display_name -> Text,
        created_by -> Text,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    saml_links (org_id, email) {
        org_id -> Text,
        email -> Text,
        identity_id -> Text,
        created_at -> Text,
        idp_subject -> Nullable<Text>,
    }
}

diesel::joinable!(organization_members -> organizations (org_id));
diesel::joinable!(saml_connections -> organizations (org_id));
diesel::allow_tables_to_appear_in_same_query!(organizations, organization_members);
diesel::allow_tables_to_appear_in_same_query!(organizations, saml_connections);
