-- User-chosen handle, emitted as the OIDC `preferred_username` claim under
-- the `profile` scope. Nullable: absent means the claim is omitted, which is
-- what OIDC Core 5.3.2 asks for (sqlite).
--
-- `username` keeps the casing the user typed; `username_lc` is the folded
-- uniqueness key, stored rather than indexed as `lower(username)` so both
-- backends and Diesel see a plain column. NULLs compare distinct in both, so
-- any number of profiles without a handle coexist.

ALTER TABLE member_profiles ADD COLUMN username TEXT;
ALTER TABLE member_profiles ADD COLUMN username_lc TEXT;

CREATE UNIQUE INDEX idx_member_profiles_username_lc ON member_profiles (username_lc);

-- Released handles are tombstoned here and never reassigned. OIDC Core 5.7
-- says RPs must not treat preferred_username as unique, but they do anyway
-- (Forgejo provisions local accounts from it), so recycling a handle would
-- hand the next holder someone else's account.
CREATE TABLE member_username_history (
    username_lc TEXT PRIMARY KEY NOT NULL,
    identity_id TEXT NOT NULL,
    released_at TEXT NOT NULL
);

CREATE INDEX idx_member_username_history_identity ON member_username_history (identity_id);
