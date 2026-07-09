//! Diesel table definitions. Hand-written rather than emitted by `diesel
//! print-schema` so they're identical for both backends — every column is
//! `Text` / `Nullable<Text>` / `Integer`, with timestamps as ISO-8601 UTC
//! strings, except `org_logos.bytes` which is `Binary` (`BLOB`/`BYTEA`).
//! See `migrations/{sqlite,postgres}/...` for the SQL.

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
        member_visibility -> Text,
        theme_preset -> Nullable<Text>,
        brand_primary -> Nullable<Text>,
        brand_on_primary -> Nullable<Text>,
        brand_secondary -> Nullable<Text>,
        public_login_enabled -> Integer,
        has_logo -> Integer,
        access_mode -> Text,
        domain_join_policy -> Text,
    }
}

diesel::table! {
    org_logos (org_id) {
        org_id -> Text,
        bytes -> Binary,
        content_type -> Text,
        etag -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    organization_members (org_id, identity_id) {
        org_id -> Text,
        identity_id -> Text,
        role -> Text,
        added_at -> Text,
        added_by -> Nullable<Text>,
        hidden_from_directory -> Integer,
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

diesel::table! {
    posix_accounts (identity_id) {
        identity_id -> Text,
        username -> Text,
        uid -> Integer,
        gid -> Integer,
        gecos -> Text,
        shell -> Text,
        home_dir -> Text,
        enabled -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    posix_groups (gid) {
        gid -> Integer,
        name -> Text,
        kind -> Text,
        created_at -> Text,
    }
}

diesel::table! {
    org_teams (id) {
        id -> Text,
        org_id -> Text,
        name -> Text,
        slug -> Text,
        gid -> Nullable<Integer>,
        parent_id -> Nullable<Text>,
        created_at -> Text,
        created_by -> Nullable<Text>,
    }
}

diesel::table! {
    org_team_members (team_id, identity_id) {
        team_id -> Text,
        identity_id -> Text,
        source -> Text,
        added_at -> Text,
    }
}

diesel::table! {
    posix_sequences (name) {
        name -> Text,
        next -> Integer,
    }
}

diesel::table! {
    posix_group_members (gid, identity_id) {
        gid -> Integer,
        identity_id -> Text,
        added_at -> Text,
    }
}

diesel::table! {
    host_enrollments (id) {
        id -> Text,
        hostname -> Text,
        secret_hash -> Text,
        org_id -> Text,
        force_mfa -> Integer,
        created_by -> Nullable<Text>,
        created_at -> Text,
        last_seen_at -> Nullable<Text>,
    }
}

diesel::table! {
    host_allowed_groups (host_id, team_id) {
        host_id -> Text,
        team_id -> Text,
    }
}

diesel::table! {
    device_sessions (device_code) {
        device_code -> Text,
        user_code -> Text,
        host_id -> Text,
        requested_username -> Text,
        status -> Text,
        identity_id -> Nullable<Text>,
        created_at -> Text,
        expires_at -> Text,
    }
}

diesel::table! {
    ssh_authorized_keys (id) {
        id -> Text,
        identity_id -> Text,
        public_key -> Text,
        comment -> Text,
        created_at -> Text,
        expires_at -> Nullable<Text>,
    }
}

diesel::table! {
    offline_secrets (identity_id) {
        identity_id -> Text,
        verifier -> Text,
        algo_version -> Integer,
        created_at -> Text,
        updated_at -> Text,
    }
}

diesel::table! {
    org_allowed_domains (org_id, domain) {
        org_id -> Text,
        domain -> Text,
        method -> Text,
        verification_token -> Text,
        verified_at -> Nullable<Text>,
        added_by -> Nullable<Text>,
        added_at -> Text,
    }
}

diesel::joinable!(organization_members -> organizations (org_id));
diesel::joinable!(saml_connections -> organizations (org_id));
diesel::joinable!(org_allowed_domains -> organizations (org_id));
diesel::allow_tables_to_appear_in_same_query!(organizations, organization_members);
diesel::allow_tables_to_appear_in_same_query!(organizations, saml_connections);
diesel::allow_tables_to_appear_in_same_query!(organizations, org_allowed_domains);
diesel::allow_tables_to_appear_in_same_query!(posix_group_members, posix_accounts);
diesel::allow_tables_to_appear_in_same_query!(
    posix_accounts,
    organization_members,
    org_team_members,
    org_teams
);
