# Integration Guide

For application developers integrating with an `forseti` deployment (e.g. `accounts.example.com`) as an OIDC Provider for single sign-on.

For operators deploying `forseti` itself, see [`operator-guide.md`](./operator-guide.md). For project status, see [`../README.md`](../README.md).

## What this is

`forseti` is a self-service UI and OAuth2 bridge over Ory Kratos and Ory Hydra. From a downstream application's perspective:

- The **OAuth2 / OIDC Provider** is Hydra, reachable at the operator's public Hydra URL (e.g. `https://hydra.example.com` or, more commonly, the same hostname as Forseti under `/oauth2/*` depending on the operator's routing).
- The **login / consent UI** is Forseti at `https://accounts.example.com`. Hydra delegates user interaction to it via `/oauth/login`, `/oauth/consent`, `/oauth/logout`.
- Your app does not talk to Forseti directly. It talks to Hydra's OAuth2 endpoints and OIDC discovery document.

Integration follows the standard OIDC authorization-code flow. Forseti is a normal OIDC Provider as far as your OAuth2 library is concerned.

## Spec alignment (OAuth 2.1 / RFC 9700)

Where the playground sits relative to current OAuth / OIDC normative work (as of May 2026):

| Spec / behaviour | Status in this stack |
|---|---|
| OAuth 2.1 draft-15 — PKCE on every code flow (S256) | Enforced for public clients via Hydra `oauth2.pkce.enforced_for_public_clients: true` (`infra/hydra/hydra.yml:70`) |
| OAuth 2.1 — Implicit grant removed | Not enabled on the playground; do not add `response_type=token` clients |
| OAuth 2.1 — ROPC removed | Not enabled |
| OAuth 2.1 — Exact-string redirect matching | Hydra default; no wildcard / prefix matching |
| OAuth 2.1 — Refresh tokens sender-constrained OR rotated | Rotated (Hydra default; one-shot with reuse detection) |
| RFC 9068 JWT Access Token profile (`typ=at+jwt`) | Partial — Hydra v26 emits JWT access tokens with `typ: JWT`. Strict RFC 9068 validators that require `typ=at+jwt` will reject. Either relax your validator or stay on opaque tokens + introspection until Hydra ships the profile |
| RFC 8707 Resource Indicators (`resource=` parameter) | Hydra ignores `resource=`; Forseti's consent handler bridges it — a requested `resource` is bound into the access token's `aud` when the operator has enrolled that resource in the registry (`/admin/resources`). Default deny for everything else |
| CIMD (draft-ietf-oauth-client-id-metadata-document) | Implemented by Forseti (Hydra has none): URL-shaped `client_id`s are resolved by the `/oauth2/authorize` shim, public clients (`token_endpoint_auth_method: "none"`) only. RFC 7591 DCR is retired — no `registration_endpoint` exists |
| RFC 9449 DPoP | **Not implemented.** Tokens are bearer-only |
| RFC 8705 mTLS client auth + cert-bound tokens | Not configured |
| RFC 9126 PAR (Pushed Authorization Requests) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9101 JAR (signed request objects) | Supported by Hydra; no Forseti-side enforcement |
| RFC 9396 RAR (Rich Authorization Requests) | Not used |
| RFC 9700 OAuth Security BCP (Jan 2025) | Reference document — the items above cover the BCP's MUST-level requirements except DPoP/mTLS |

If you're building an MCP server, see also [Protecting an MCP server](#protecting-an-mcp-server) — Forseti does not host RFC 9728 Protected Resource Metadata on your behalf.

## Registering your app

Your app is an OAuth2 client of Hydra. Forseti operator registers it; you tell them what to register. Ask for a client with the following:

**Required:**

- **Name** — human label, shown on consent screens and in the operator's admin UI.
- **Grant types** — typically `authorization_code`, plus `refresh_token` if you need offline access.
- **Response types** — typically `code`.
- **Scopes** — start with `openid` (required for OIDC); add `email`, `profile`, `offline_access` as you need them. See [Scope reference](#scope-reference).
- **Redirect URI(s)** — every URL Hydra is allowed to send the user back to after authentication. Exact match, no wildcards.
- **Token-endpoint auth method** — one of:
  - `client_secret_post` — credentials in the form body. Most common.
  - `client_secret_basic` — HTTP Basic header.
  - `none` — public client (SPAs, mobile). Pair with PKCE.

**Optional:**

- **Backchannel logout URI** — server-to-server endpoint Hydra POSTs to when the user signs out elsewhere. See [Logout](#logout).
- **Post-logout redirect URI(s)** — where Hydra sends the user after RP-initiated logout.
- **`skip_consent: true`** — first-party apps where the operator pre-authorizes consent. Forseti skips the consent screen entirely. (This is a top-level client field, not a `metadata` key.)
- **`metadata.forseti.account_deletion_url`** — HTTPS webhook target Forseti POSTs to when one of your users self-deletes. See [Account deletion webhooks](#account-deletion-webhooks).
- **Audience** — restrict tokens to a specific resource server `aud`.
- **Custom scopes** — app-specific permission grants beyond the standard OIDC set.

From the operator, capture:

- `client_id`
- `client_secret` (confidential clients only)

Config changes later go back through the operator (admin UI or admin API) — there is no client-held management credential.

For the operator-side CLI invocation, see [`operator-guide.md`](./operator-guide.md#client-registration).

## The auth code flow

> **Use a library.** Any conformant OIDC client (`openid-client` for Node, `go-oidc` for Go, `authlib` for Python, `nimbus-jose-jwt`/`oauth2-oidc-sdk` for Java) handles every step in this section — discovery, the redirect dance, code exchange, id_token validation, refresh. Point it at `https://hydra.example.com/.well-known/openid-configuration` and you're done. The rest of this section is what's happening under the hood — read it if you're debugging, writing your own client, or just curious.

```
                         +-----------+
                         | Your App  |
                         |           |
                         | 1. User   |
                         |    clicks |
                         | "Sign in" |
                         +-----+-----+
                               |
                               | 2. 302 to /oauth2/auth?... on Hydra
                               v
                       +---------------+
                       |     Hydra     |
                       | (OAuth2 srvr) |
                       +-------+-------+
                               |
                               | 3. 302 to /oauth/login?login_challenge=...
                               v
                     +-------------------+
                     |    forseti     |
                     |  login + consent  |
                     +---------+---------+
                               |
                               | 4. user authenticates, Forseti accepts
                               |    challenges with Hydra admin
                               v
                       +---------------+
                       |     Hydra     |
                       +-------+-------+
                               |
                               | 5. 302 to https://yourapp.com/auth/callback?code=...&state=...
                               v
                         +-----------+
                         | Your App  |
                         |           |
                         | 6. POST   |
                         |    /token |
                         |    code   |
                         +-----+-----+
                               |
                               | 7. {access_token, id_token, refresh_token}
                               v
                         +-----------+
                         | Your App  |
                         | session   |
                         +-----------+
```

### 1. Start the flow

Redirect the user from your app to Hydra's authorization endpoint:

```
https://hydra.example.com/oauth2/auth
  ?client_id=<your client_id>
  &response_type=code
  &scope=openid+email+profile+offline_access
  &redirect_uri=https://yourapp.com/auth/callback
  &state=<random, >= 8 chars>
  &nonce=<random, recommended>
```

- `state` is mandatory and must be cryptographically random per attempt. Store it in your app's pre-session (server-side or signed cookie) and compare on callback. Defends against CSRF on the redirect.
- `nonce` is optional but recommended; binds the id_token to this specific flow. Store and compare on callback.
- `prompt=login` forces re-authentication even if the user has an active Forseti session.
- `acr_values=aal2` requests a second-factor step-up (see [AAL step-up](#aal-step-up)).
- `max_age=<seconds>` requires the user to have authenticated within the window; otherwise re-prompts.

### 2. Handle the callback

Hydra redirects the browser to `redirect_uri`:

```
https://yourapp.com/auth/callback?code=<authorization code>&state=<your state>
```

Verify `state` matches what your app sent. If it does not, abort with a 400.

### 3. Exchange the code for tokens

```http
POST /oauth2/token HTTP/1.1
Host: hydra.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<the code>
&redirect_uri=https://yourapp.com/auth/callback
&client_id=<your client_id>
&client_secret=<your client_secret>
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "ory_rt_...",
  "expires_in": 300,
  "scope": "openid email profile offline_access",
  "token_type": "bearer"
}
```

### 4. Validate the id_token

See [Validating the id_token](#validating-the-id_token) below. After validation, create a local session in your app and redirect the user to their destination.

## The id_token

The id_token is a JWT signed with RS256 by Hydra's signing key. The claims depend on requested scopes.

### Always present

| Claim       | Type    | Description                                                                                  |
|-------------|---------|----------------------------------------------------------------------------------------------|
| `iss`       | string  | Issuer. Matches `urls.self.issuer` from Hydra's config.                                      |
| `aud`       | string[]/string | Audience. Contains your `client_id`.                                                |
| `sub`       | string  | The Kratos identity UUID. Stable for the life of the user account.                           |
| `auth_time` | number  | Unix seconds when the user authenticated.                                                    |
| `iat`       | number  | Unix seconds when the token was issued.                                                      |
| `exp`       | number  | Unix seconds when the token expires.                                                         |
| `sid`       | string  | Session ID. Used to scope back-channel logouts to a specific session.                        |
| `acr`       | string  | Authenticator context class reference. Typically `aal1` or `aal2`.                           |
| `amr`       | string[]| Authentication methods used. E.g. `["password"]`, `["password","totp"]`.                     |
| `jti`       | string  | Unique token ID. Use for replay defence on backchannel logout tokens.                        |
| `at_hash`   | string  | Hash of the access_token (first half of `SHA-256(at)`, base64url). Bind id_token to at.      |
| `nonce`     | string  | Echoed from your auth request if you sent one.                                               |

### With `email` scope

| Claim            | Type    | Description                                                          |
|------------------|---------|----------------------------------------------------------------------|
| `email`          | string  | The user's primary email address.                                    |
| `email_verified` | boolean | Whether the address is verified: either the user completed Forseti's own verification flow, or they signed in with a provider whose verification the operator trusts (Google, Apple). |

#### Membership and verification are not the same

Forseti will issue a token for a user whose email is **not** verified (`email_verified: false`), and that user can already be a member of an org: everyone belongs to at least the Default home org, and an external org's public signup admits anyone without a verification step. So:

- **Never authorize on `email` without checking `email_verified == true`.** An unverified `email` claim only says "the user typed this address", not "the user controls it".
- **`email_verified: true` means Forseti's operator vouches for the address, not that Forseti mailed it.** For social sign-ins it may originate upstream (Google, Apple), so the assurance is that provider's, inherited. Treat it the way you'd treat any federated assertion: good enough to key a profile on, not a substitute for your own step-up if you're guarding something sensitive. Use `sub` — never `email` — as the stable user identifier.
- **A membership claim is not identity proof.** Do not treat an `org` claim — least of all `org.id = "default"` — as evidence of who the user is or that they belong to your organization in a trusted sense. Membership of the Default home org and of open external orgs is not gated on verification.
- Membership that *is* email-gated (domain auto-join, invite acceptance) always requires a verified address, but you cannot tell from the token which door a user came through, so apply the two rules above uniformly.

### With `profile` scope

| Claim         | Type   | Description                                                |
|---------------|--------|------------------------------------------------------------|
| `name`        | string | Full name, if present in the identity schema.              |
| `given_name`  | string | First name, if present.                                    |
| `family_name` | string | Surname, if present.                                       |
| `preferred_username` | string | The handle the user chose under Settings → Profile. Omitted when they haven't set one. |
| `updated_at`  | number | Seconds since the epoch, last time the user's portal profile changed. |

These come from the identity's `traits.*` fields as configured by the operator's identity schema. Absent fields are omitted from the token.

#### `preferred_username`

Forseti omits this claim entirely when the user hasn't chosen a handle. It never falls back to the email address: that would leak the address to apps that asked for `profile` but not `email`, and hand you an email-shaped value you'd be tempted to key accounts on. Plan for it to be absent.

**Do not use it as an account identifier.** OIDC Core §5.7 is explicit: `sub` and `iss` together are the only stable, unique identifier, and `preferred_username`, like `email` and `name`, "MUST NOT be used as unique identifiers for the End-User". Key your local records on `sub`; treat this claim as a display string or a signup suggestion. Mapping accounts by username is the [nOAuth](https://www.descope.com/blog/post/noauth) bug class, and it bypasses every control on the IdP side.

Forseti applies restrictions the spec doesn't require, because apps key on the value anyway:

- 2 to 39 characters, ASCII letters, digits, `.`, `_` and `-`, starting and ending alphanumeric. No `@`, so a handle can never be mistaken for an email address.
- Unique, case-insensitively, across the deployment.
- **Never reassigned.** A released handle is tombstoned and only its previous holder can reclaim it.
- Changeable at most once every 30 days, with a `profile.username_changed` audit row recording the old and new value.

`updated_at` moves whenever any portal-owned profile field changes, so it is a drift signal rather than a username-change signal. Both claims are snapshotted into the consent session, so a change only reaches you at the next authorization — see [Freshness cheatsheet](#freshness-cheatsheet).

### With `groups` scope

| Claim              | Type     | Description                                                                                       |
|--------------------|----------|---------------------------------------------------------------------------------------------------|
| `groups`           | string[] | Slugs of the teams the user belongs to in their active org. Empty array when the user has no teams. Always present when the scope is granted. |
| `groups_truncated` | boolean  | Present and `true` only when the user is in more than 200 teams and the list was capped.          |

`groups` is scoped to the user's active org (the same org the `org` claim resolves to). It reflects state as of the user's last authorization and is not re-resolved on a refresh-token grant. See the [scope reference](#scope-reference).

### Example decoded payload

```json
{
  "iss": "https://hydra.example.com",
  "aud": ["a1b2c3d4-e5f6-7890-abcd-ef0123456789"],
  "sub": "f8c9d0e1-2345-6789-abcd-ef0123456789",
  "iat": 1700000000,
  "exp": 1700003600,
  "auth_time": 1700000000,
  "sid": "0a1b2c3d-4e5f-6789-abcd-ef0123456789",
  "acr": "aal1",
  "amr": ["password"],
  "jti": "9f8e7d6c-5b4a-3210-fedc-ba9876543210",
  "at_hash": "wfgvdfP3qS6mPq3jeKxYHA",
  "email": "user@example.com",
  "email_verified": true,
  "name": "User Example"
}
```

## Validating the id_token

> **Use a library.** Every mainstream OIDC client does these eight steps correctly, including JWKS caching and `kid` rotation. Hand-rolling validation is how you get CVEs. The steps below exist so you know what your library is doing — and so you can spot it doing the wrong thing.

Validation steps:

1. Fetch the JWKS from `https://hydra.example.com/.well-known/jwks.json`. Cache with a TTL (~24h). When you see a `kid` not in your cache, refetch immediately.
2. Look up the public key by the token's `kid` header. Verify the signature with the declared `alg` (RS256).
3. Verify `iss == https://hydra.example.com` (exact match).
4. Verify `aud` contains your `client_id`.
5. Verify `exp > now` (allow a small clock skew, e.g. 60 seconds).
6. Verify `iat <= now + skew`.
7. If you sent a `nonce`, verify it matches.
8. If you also received an `access_token`, verify `at_hash` matches:
   `at_hash == base64url(SHA-256(access_token)[0:16])`.

### Rust (jsonwebtoken)

```rust
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    aud: Vec<String>,
    sub: String,
    exp: i64,
    iat: i64,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
}

fn verify_id_token(id_token: &str, jwks: &Jwks, expected_nonce: &str) -> anyhow::Result<Claims> {
    let header = decode_header(id_token)?;
    let kid = header.kid.ok_or_else(|| anyhow::anyhow!("id_token missing kid"))?;
    let jwk = jwks.find(&kid).ok_or_else(|| anyhow::anyhow!("unknown kid"))?;
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)?;

    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(&["https://hydra.example.com"]);
    v.set_audience(&[std::env::var("OIDC_CLIENT_ID")?]);
    v.leeway = 60;

    let data = decode::<Claims>(id_token, &key, &v)?;
    if data.claims.nonce.as_deref() != Some(expected_nonce) {
        anyhow::bail!("nonce mismatch");
    }
    Ok(data.claims)
}
```

### Other languages

- **Go**: [`github.com/coreos/go-oidc/v3/oidc`](https://github.com/coreos/go-oidc) handles JWKS caching, discovery, and validation.
- **Python**: `authlib` or `python-jose`. Use Authlib's `OAuth2Session` for the full flow.
- **Node.js**: `openid-client` (the maintained successor to `node-openid-client`).
- **Java**: `nimbus-jose-jwt` plus `oauth2-oidc-sdk`.

All of these consume the OIDC discovery document at `https://hydra.example.com/.well-known/openid-configuration`. Prefer discovery over hardcoded endpoints; it surfaces JWKS URI, supported algorithms, and endpoint URLs.

## Refresh tokens

> **Use a library.** OIDC clients handle refresh-token rotation, retry on transient errors, and surface `invalid_grant` as a "re-authenticate" signal. The Hydra-specific quirks below are for when you need to reason about behavior — your library has already done the right thing in 95% of cases.

If your initial scope included `offline_access`, the token response includes `refresh_token`. Exchange it for fresh tokens:

```http
POST /oauth2/token HTTP/1.1
Host: hydra.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<the refresh token>
&client_id=<your client_id>
&client_secret=<your client_secret>
```

### What you get back

The `refresh_token` field is an opaque string (`ory_rt_...`) — **always opaque, regardless of whether access tokens are JWT or opaque**. That's deliberate: refresh tokens have to be immediately revocable, and JWT-style local validation can't honor a revocation until the token expires. The format stays opaque even in the JWT access-token configuration.

The token response also does not include an `expires_in` for the refresh token itself. RFC 6749 doesn't define one, and Hydra doesn't surface a lifetime in the response — the only ways to know if a refresh token is still alive are (a) try to use it and handle `invalid_grant`, or (b) introspect it (see below). Hydra's default refresh-token TTL is 720h (30 days); if your operator hasn't tuned it, that's what you've got.

### Rotation behavior in the playground

The playground config (`infra/hydra/hydra.yml`) uses Hydra's defaults: **strict one-shot rotation**. A refresh token can be redeemed exactly once — the successful response carries a new `refresh_token`, and the old one is dead the instant it lands at the token endpoint. Always overwrite your stored value.

Reuse — replaying a token Hydra has already seen — is a security signal. Hydra invalidates the entire token chain (current refresh token + every access token issued from it) and returns `invalid_grant`. The next call has to be a fresh auth flow.

Hydra also offers a **graceful rotation** mode (`oauth2.grant.refresh_token.grace_period`, off by default) that keeps the old token usable for a short overlap window. Useful if your app makes concurrent refresh attempts from multiple processes or tabs — without it, the second-place process gets `invalid_grant` on a token the first process already burned. Ask your operator to enable it if you're hitting that race; the cost is a slightly larger reuse-detection blind spot.

### Handling `invalid_grant`

A 400 with `error: invalid_grant` means the refresh token has been used, revoked, expired, or never existed. The default response is to force re-authentication.

One nuance with strict rotation: a network retry on a refresh request Hydra already processed lands as `invalid_grant` even though the user's grant is fine — your retry looks like a replay. If you implement retries on transient errors, a single backoff-then-retry is defensible, but treat the *second* `invalid_grant` as authoritative and re-auth. Don't loop.

Operators can also wire `oauth2.refresh_token_hook` to deny refresh based on out-of-band signals (account flagged, device revoked, step-up required). To the client, that surfaces as the same `invalid_grant`. Same handling: re-auth.

### Checking validity without consuming the token

If you have a route into the operator's admin network — service mesh, private link, anything reaching Hydra's admin port — you can introspect a refresh token to check it's still valid without redeeming it:

```http
POST /admin/oauth2/introspect HTTP/1.1
Host: hydra-admin.internal:4445
Content-Type: application/x-www-form-urlencoded

token=<the refresh token>
&token_type_hint=refresh_token
```

Same caveat as the opaque access-token case (see [Alternative: opaque + introspection](#alternative-opaque--introspection-private-network-only)): **the admin API is private**. If your app runs on Cloudflare Workers, Vercel, or anywhere without a tunnel into the operator's network, introspection is not an option — you check validity by trying to refresh and handling `invalid_grant`.

`active: true` confirms the token is currently redeemable. `active: false` means dead — skip the redemption round trip and go straight to re-auth.

### Refresh cadence

Refresh ahead of the access token's `expires_in`. A common pattern is to refresh at 80% of the lifetime (~4 minutes in for a 5-minute access token). Don't refresh on every request — that defeats the JWT-local-validation win and turns Hydra's token endpoint into a hot path.

### Revoking a refresh token

For explicit logout — or when a user disconnects an integration on your side — revoke the token rather than just dropping it:

```http
POST /oauth2/revoke HTTP/1.1
Host: hydra.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<the refresh token>
```

RFC 7009. Revoking a refresh token kills it and every access token minted from it. Confidential clients authenticate on this endpoint; public clients pass `client_id` in the body without credentials. Always best-effort — the spec says return 200 even if the token was already invalid, so don't trust the response code for diagnostics.

### Patterns by client type

**Confidential clients (server-rendered web apps, backend services).** Store the refresh token in your session store, encrypted at rest. Hand client credentials to every refresh call. Handle `invalid_grant` by clearing the session and 302'ing the user to `/oauth2/auth`. No special storage gymnastics — your server is the trust boundary.

**Browser SPAs.** Don't store refresh tokens in the browser. The modern recommendation (codified in [draft-ietf-oauth-browser-based-apps](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps)) is the **Backend-for-Frontend (BFF)** pattern: a thin server colocated with your SPA holds the refresh token, exchanges it for fresh access tokens on the SPA's behalf, and proxies API calls. The SPA holds nothing more than a session cookie scoped to the BFF. LocalStorage / SessionStorage / IndexedDB are all XSS-reachable; treat them as unsafe for any token that outlives a tab.

**Native mobile apps.** Refresh tokens live in the OS-provided secure store — Keychain on iOS (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` or stricter), `EncryptedSharedPreferences` or Keystore on Android. Use PKCE, rotate on every refresh, and treat reuse-detection invalidation as a hard signal: your token was lifted from the device.

**MCP clients.** See [Protecting an MCP server](#protecting-an-mcp-server) for the full picture. Short version: same rotation rules apply, store the refresh token in an OS-appropriate keychain (or a passphrase-encrypted file on Linux), and request `offline_access` if you want the agent to keep working past the 5-minute access-token TTL.

## Reading user info

Two questions get conflated. The answers diverge, so they're worth separating up front:

1. **What did the user look like when they signed in?** — anything in your id_token stays valid for the life of the grant. Decode it locally, or call `/userinfo`. Both return the same thing.
2. **What does the user look like *right now*?** — there's no live "read identity" endpoint exposed to relying parties. You re-run the auth flow. See [Getting fresh user info](#getting-fresh-user-info).

The reason is structural. User info lives in two places:

- **Kratos** owns the identity record — email, `email_verified`, and whatever traits the operator's identity schema declares (typically `name.first`, `name.last`).
- **Forseti's own database** owns everything else surfaced as claims — the extended profile (avatar, website, bio, pronouns, links) and org memberships.

Hydra owns none of it. At consent time, Forseti reads from both stores, folds the result into a claims object, and hands it to Hydra as the consent session payload (`src/oauth/consent.rs`, `build_id_token_claims`). Hydra caches that snapshot alongside the grant and replays it for every id_token and `/userinfo` call until the user consents again. The snapshot doesn't update when the user edits their profile in Forseti — that's the whole crux of the freshness question.

### Reading the consent-time snapshot

The data is already in two places by the time your app holds tokens: in the id_token you got at login, and behind Hydra's `/userinfo` endpoint. Pick based on what token you hold:

| You hold                            | Use                                       | Why                                                              |
| ----------------------------------- | ----------------------------------------- | ---------------------------------------------------------------- |
| id_token (JWT)                      | Decode it locally.                        | Already signed, already validated, no network call.              |
| JWT access token (default)          | Decode it. Same JWKS as the id_token.     | Same trust path; `/userinfo` is redundant.                       |
| Opaque access token (operator opt-in) | `GET /userinfo` with the bearer token.  | The token is opaque to you — `/userinfo` is the read-out.        |

`/userinfo` shape:

```http
GET /userinfo HTTP/1.1
Host: hydra.example.com
Authorization: Bearer <access_token>
```

Response is a JSON document with the same scope-gated claims as the id_token (`sub`, `email`, `email_verified`, `name`, `picture`, `org`, `groups`, …). Discovery surfaces the endpoint as `userinfo_endpoint`; libraries find it automatically.

No freshness difference between the two paths. They're both the consent-time snapshot.

### Getting fresh user info

If the user updated their email, name, or profile in Forseti *after* consenting, none of the snapshot paths see it. You trigger a new consent acceptance — that's what re-reads Kratos and Forseti DB.

Three patterns, ranked by user-visible friction:

1. **Silent re-auth (SSO).** Redirect to `/oauth2/auth` again, no `prompt=login`. If the user still has a live Forseti session — which they almost always do for the lifetime of the cookie — Hydra round-trips through Forseti silently and hands you a freshly-built id_token. With `skip_consent: true` on your client (first-party apps), the user sees nothing but a brief redirect chain. This is the right pattern when you want fresh claims on a specific page load (account settings, billing, anything that displays the user's own info back to them).
2. **`prompt=login`.** Forces a full re-auth (password, 2FA if enrolled). Use when you actually want the user to reauthenticate for a sensitive operation, not when you just want fresh claims — the friction is significant.
3. **Refresh-token exchange.** **Does not refresh claims** in the playground config. Hydra reuses the cached consent session payload, so the new id_token carries the same `email_verified` / `name` / `picture` as the old one, with only `iat` / `exp` advanced. Hydra exposes an `oauth2.refresh_token_hook` that lets Forseti repopulate claims on every refresh, but `infra/hydra/hydra.yml` doesn't wire it. If your operator has configured one (ask them), refresh becomes the cleanest path; otherwise treat refresh as token-lifetime extension only.

### Freshness cheatsheet

| Token / call         | What you get                                            | Reflects Forseti edits?                          |
| -------------------- | ------------------------------------------------------- | ----------------------------------------------- |
| `id_token` (held)    | Claims from when the user consented.                    | No.                                             |
| `/userinfo` call     | Claims from when the user consented.                    | No.                                             |
| Refresh-token grant  | New id_token; same claims as the old one.               | No (unless operator wired a refresh hook).      |
| Silent re-auth (SSO) | New id_token built from a fresh Kratos + Forseti read.  | Yes.                                            |
| `prompt=login`       | Same, but interactive.                                  | Yes.                                            |

### What about push notifications on profile change?

Nothing exists today. Forseti only pushes RISC `account-purged` (see [Account deletion webhooks](#account-deletion-webhooks)) — not `profile.updated` or `email.verified`. If your app needs near-real-time sync, poll `/userinfo` on a cadence that matters to you, or run a silent re-auth whenever the user lands on a page that displays their own info.

## Logout

Two patterns. Use one or both.

### Local logout

Destroy your app's local session. Do nothing with the IdP. The user remains signed in at `accounts.example.com` and can return to your app via SSO without re-authenticating.

Appropriate when the user is logging out of *your app specifically* and you do not want to terminate their other federated sessions.

### Global logout via RP-initiated logout

Redirect the user to Hydra's end-session endpoint:

```
https://hydra.example.com/oauth2/sessions/logout
  ?id_token_hint=<the id_token from login>
  &post_logout_redirect_uri=https://yourapp.com/
  &state=<random>
```

Hydra forwards the user to Forseti's `/oauth/logout`, which destroys the Kratos session, then redirects back to your `post_logout_redirect_uri`. The URL must be registered on the client at creation time (see [Registering your app](#registering-your-app)).

### Global logout via back-channel

When the user signs out at `accounts.example.com` (or any other RP triggers a global logout), Hydra POSTs a logout token to every registered `backchannel_logout_uri` for that user's active sessions.

Request shape:

```http
POST /auth/backchannel-logout HTTP/1.1
Host: yourapp.com
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIs...
```

The `logout_token` is a JWT signed by Hydra. Required claims (per [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)):

| Claim    | Required | Notes                                                                              |
|----------|----------|------------------------------------------------------------------------------------|
| `iss`    | yes      | Must match Hydra's issuer URL.                                                     |
| `aud`    | yes      | Must contain your `client_id`.                                                     |
| `iat`    | yes      | Reject if older than your accepted window (60s is typical).                        |
| `jti`    | yes      | Unique token ID. Deduplicate against a short-lived cache to prevent replay.        |
| `events` | yes      | Must contain the key `http://schemas.openid.net/event/backchannel-logout` mapping to an empty JSON object. |
| `sub`    | one of   | The user's stable subject ID.                                                      |
| `sid`    | one of   | The specific session ID. At least one of `sub`/`sid` must be present.              |

Critically, the logout token must NOT contain a `nonce` claim — the spec forbids it.

> **Library support is patchy here.** `openid-client` (Node) has first-class back-channel logout support; `go-oidc` exposes the primitives but you wire the handler yourself; `authlib` has helpers; many smaller libraries don't cover it at all. If yours doesn't, the validation below is what you need to implement.

Validation pseudocode (Rust shape):

```rust
async fn handle_backchannel_logout(form: Form<LogoutForm>) -> Response {
    let token = &form.logout_token;

    // 1. Decode header, find kid, fetch JWKS from Hydra, verify signature (RS256).
    let claims = match verify_logout_token_signature(token).await {
        Ok(c) => c,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // 2. Validate claims.
    if claims.iss != "https://hydra.example.com" { return StatusCode::BAD_REQUEST.into_response(); }
    if !claims.aud.contains(&client_id()) { return StatusCode::BAD_REQUEST.into_response(); }
    if (now() - claims.iat).abs() > 60 { return StatusCode::BAD_REQUEST.into_response(); }
    if !claims.events.contains_key("http://schemas.openid.net/event/backchannel-logout") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if claims.sub.is_none() && claims.sid.is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if claims.nonce.is_some() { return StatusCode::BAD_REQUEST.into_response(); }

    // 3. Replay defence.
    if seen_jti(&claims.jti).await {
        return StatusCode::BAD_REQUEST.into_response();
    }
    remember_jti(&claims.jti, Duration::from_secs(600)).await;

    // 4. Destroy matching local sessions.
    if let Some(sid) = claims.sid {
        destroy_sessions_by_sid(&sid).await;
    } else if let Some(sub) = claims.sub {
        destroy_sessions_by_sub(&sub).await;
    }

    // 5. Respond.
    (StatusCode::OK, [(header::CACHE_CONTROL, "no-store")]).into_response()
}
```

Implementation notes:

- The handler is invoked server-to-server, with no user cookies. Do not depend on session state in this endpoint.
- Prefer `sid` over `sub` when present. A user can be signed in from multiple devices; `sid` lets you destroy one without affecting the others.
- Return 200 on success, 400 on any validation failure. The spec discourages 5xx for validation errors.
- Cache JWKS but be prepared to refetch on `kid` miss; Hydra rotates signing keys.

See the [README's Logout integration section](../README.md#logout-integration) for the original short-form summary.

## AAL step-up

When your app exposes operations that warrant a second factor (delete account, change billing, manage API keys), force a step-up at the OIDC layer:

```
https://hydra.example.com/oauth2/auth
  ?client_id=<your client_id>
  &response_type=code
  &scope=openid+email
  &redirect_uri=https://yourapp.com/auth/callback
  &state=<random>
  &acr_values=aal2
```

Forseti observes the `acr_values` request, looks at the user's current Kratos session, and:

- If the session is already `aal2`, accepts immediately.
- If the session is `aal1` and the user has a second factor enrolled, prompts for the second factor before accepting.
- If the user has no second factor, returns an error (or, depending on the operator's `acr_values` strictness setting, accepts at `aal1` — check the returned id_token's `acr` claim).

Your app must inspect the returned id_token's `acr` claim and reject `aal1` for the sensitive operation. Do not assume `acr_values=aal2` was honored; verify.

**Note on enrolled users.** When the operator enforces 2FA (the recommended config — `session.whoami.required_aal: highest_available` in Kratos), any user who has a second factor enrolled is forced through the step-up on *every* login through Forseti, even when your app didn't send `acr_values=aal2`. So for those users the returned `acr` is `aal2` regardless. You can't rely on the *absence* of a step-up to mean a user has no second factor — only that they hadn't enrolled one, or the operator hasn't enabled enforcement. Still verify the `acr` claim when you need AAL2; don't infer it from the flow's behavior.

## Enterprise SSO (SAML)

If the operator has enabled Enterprise SAML SSO (a commercial feature), some users sign in through their company's corporate IdP instead of with a Forseti password. **This is transparent to your app.** You keep doing plain OIDC against Forseti — an SSO'd user arrives as an ordinary session and `id_token`, with the same claims as any other user. There's nothing SAML-specific to handle on your side.

A few things worth knowing:

- **"Sign in with your company" links.** SAML is per-org, and each connected org has a deep-link of the form `https://<forseti>/sso/{org-slug}`. If you want to offer a company-branded entry point, you can link users straight to it — the operator gives each org its URL. Otherwise users just sign in normally and Forseti routes them.
- **Org-aware authz is the `orgs` claim, same as always.** SSO doesn't introduce a new authz mechanism: an SSO'd user is a member of the org they signed in through, and that membership shows up in the `org` / `orgs` claims exactly like any other member's. Use those for tenant scoping — see the [scope reference](#scope-reference) and [Organizations](./commercial/organizations.md).
- **SSO sessions are AAL1.** The second factor happens at the corporate IdP; Forseti doesn't see it and doesn't reflect it in `acr`. If your app gates a sensitive operation on `acr`/AAL2 (see [AAL step-up](#aal-step-up)), an SSO'd user will need a second factor enrolled in Kratos to clear it — the IdP's MFA doesn't count.

The operator-side setup, JIT provisioning, and linking semantics live in [`commercial/saml.md`](./commercial/saml.md).

## Forseti discovery document

Everything OAuth/OIDC-shaped lives on Hydra's `/.well-known/openid-configuration`. Forseti-specific surfaces — deep-link entry, account-management URI, the JWKS that signs outbound webhooks — are advertised on a separate document Forseti serves itself:

```
GET https://accounts.example.com/.well-known/forseti-configuration
```

```json
{
  "issuer": "https://accounts.example.com",
  "forseti_version": "0.x.y",
  "account_management_uri": "https://accounts.example.com/settings",
  "handoff_endpoint": "https://accounts.example.com/handoff",
  "handoff_actions_supported": [
    "2fa", "password", "profile", "sessions",
    "linked-providers", "authorized-apps"
  ],
  "webhook_jwks_uri": "https://accounts.example.com/.well-known/webhook-jwks.json",
  "webhook_events_supported": [
    "https://schemas.openid.net/secevent/risc/event-type/account-purged"
  ]
}
```

Cached for an hour at the receiver. Use it to:

- Drive a "manage account" link without hardcoding `/settings` (read `account_management_uri`).
- Build handoff URLs without hardcoding the action whitelist (read `handoff_actions_supported`, fall back gracefully if a verb your code expects isn't listed).
- Locate the SET-signing JWKS for [Account deletion webhooks](#account-deletion-webhooks) (read `webhook_jwks_uri`).
- Decide which RISC events your receiver should expect (read `webhook_events_supported`).

The document is deliberately *not* spliced into Hydra's OIDC discovery doc — mixing the two muddles the contract and ties Forseti discoverability to Hydra's response shape. RPs fetch this URL by convention.

## Account self-service deep-links

When your app wants to send the user into Forseti to perform identity self-service — set up two-factor auth, change their password, manage active sessions — link them at `/handoff` rather than reverse-engineering Forseti's internal routes. Forseti validates the request, sets a short-lived banner cookie, and lands the user on the right page with a "Return to <your app>" banner above the navigation so they don't feel stranded.

```
https://idp.example.com/handoff
  ?referrer=<your client_id>
  &referrer_uri=<absolute URL to return the user to>
  &action=<verb>
```

Drop this in an anchor on your account page:

```html
<a href="https://idp.example.com/handoff?referrer=bankapp&referrer_uri=https://bank.app/account&action=2fa">
  Set up two-factor auth
</a>
```

### Parameters

| Param          | Required        | Notes                                                                                              |
| -------------- | --------------- | -------------------------------------------------------------------------------------------------- |
| `referrer`     | with `referrer_uri` | Your OAuth `client_id`. Must be a real Hydra client; Forseti looks it up to read `client_name` and `logo_uri` for the banner. |
| `referrer_uri` | with `referrer`     | Absolute URL the "Return to <App>" button targets. Its **origin** (scheme + host + port) must match one of the client's registered `redirect_uris` or its `client_uri`. Origin-binding is the trust gate — it confines the banner's exit URL to URIs your client legitimately controls. |
| `action`       | optional        | Public verb mapped to an internal route (see below). Missing / unknown → `/settings` (the hub). |

`referrer` and `referrer_uri` are co-required. If both are absent, the endpoint still works as a stable deep-link target (action → settings route) but no banner is shown. Useful for Forseti-internal emails ("verify your address" links).

### Action whitelist

| `action`                              | Forseti route                 |
| ------------------------------------- | ----------------------------- |
| `2fa` / `totp` / `mfa`                | `/settings/2fa`               |
| `password`                            | `/settings/password`          |
| `profile`                             | `/settings/profile`           |
| `sessions`                            | `/settings/sessions`          |
| `linked_providers` / `linked-providers` | `/settings/linked-providers`  |
| `authorized_apps` / `authorized-apps` | `/settings/authorized-apps`   |
| anything else (or omitted)            | `/settings`                   |

Account deletion is **intentionally** not in the whitelist — users navigate there from inside Forseti's settings nav, in a context they chose. Sending a user there from an external app would be a confusing UX at best and a social-engineering vector at worst.

The verb → path mapping is the public contract. Internal routes can be renamed without breaking your integration; the action names won't change. The current verb list is also machine-readable as `handoff_actions_supported` on the [Forseti discovery document](#forseti-discovery-document).

### What the user sees

A bar above Forseti's navigation:

> 🏦  Continuing from **Bank**.  &nbsp;&nbsp; \[Return to Bank ↗\] \[×\]

The banner persists on every settings page they navigate to during the session (cookie TTL: 1 hour). Clicking **Return to <App>** clears the cookie and 302s back to the `referrer_uri`. The **×** dismisses globally (cookie is dropped — banner doesn't come back unless the user re-enters via `/handoff`).

### Validation errors

The endpoint returns `400 Bad Request` with a plain-text message in these cases:

- `referrer` doesn't resolve to a Hydra client.
- `referrer_uri`'s origin doesn't appear in the client's `redirect_uris` or `client_uri`.
- `referrer` is set without `referrer_uri`.

Validation failures are audited (`app.referrer.entered` at `warning` severity with a `failed` reason) so operators can spot misconfigured integrations on `/admin/audit`. A successful "Return to <App>" click emits `app.referrer.returned` on the same trail.

### What about `verify_email`?

Email verification lives on a different surface (`/verification`) that uses the unauthenticated card layout, so the banner doesn't render there in v1. If your app needs the user to verify an email, send them through the standard OAuth flow with `prompt=login` — Forseti nags about unverified addresses during sign-in, and Kratos's `default_browser_return_url` already brings them back to you on completion.

## Protecting an MCP server

If you expose a Model Context Protocol server (so Claude Desktop, Claude Code, or claude.ai can call your tools), Hydra is a natural fit as its authorization server. The MCP 2025-06-18 spec aligns with OAuth 2.1 + OIDC — most of this guide already applies; only the resource-server bits and a handful of client settings are MCP-specific.

### Roles

- Your **MCP server** is the OAuth2 *resource server*. It accepts a bearer access token on each request and enforces scopes per tool.
- **Hydra** is the *authorization server*. It mints access tokens after the user signs in at Forseti and consents.
- **The MCP client** (Claude Desktop, Claude Code, claude.ai) is a public OAuth2 client. It runs the auth-code + PKCE flow against Hydra exactly like a browser app would.

Nothing Forseti-specific in the topology — this is just OAuth with an MCP-shaped resource server on the end.

### How many Hydra clients do I need?

Short answer: **one Hydra client per MCP server**, regardless of how many Claude hosts (Desktop, Code, claude.ai) connect to it.

Worked examples:

| What you're building                              | Hydra clients | Notes                                                                  |
|---------------------------------------------------|---------------|------------------------------------------------------------------------|
| App A with a web UI, no MCP                       | 1             | The web client. Confidential, `client_secret_post`.                    |
| App A with a web UI **and** an MCP server         | 2             | Web client + MCP client. Different auth methods, scopes, audiences.    |
| Apps A and B, each with web UI + MCP              | 4             | One per surface. Don't share an MCP client between apps.               |
| App A, MCP only (no web UI)                       | 1             | Just the MCP client.                                                   |

The MCP **server** is a resource server, not a Hydra client — it doesn't need its own registration.

Two reasons not to share one MCP client across multiple apps:

- **Consent leaks.** One client = one consent grant. The user would grant App A's and App B's scopes together; revoking access to one revokes both.
- **Audience leaks.** A token Claude minted for App A's MCP server could be re-requested for App B's without re-consent, because both audiences live on one client.

Multiple Claude hosts (Desktop, Code, claude.ai) hitting **the same** MCP server don't even need that: each Claude surface identifies itself by its own CIMD URL (see below), so its client comes into existence on first use and you pre-create nothing. The table above is about clients **you** ship, not about Claude.

### Enrolling your MCP server: one registry row

Your MCP server itself needs exactly one thing from the operator: a row in Forseti's **resource registry** (`/admin/resources`) naming your canonical resource URI, e.g. `https://mcp.yourapp.com/mcp`. That row is what lets consent bind your URI into access tokens' `aud` — without it, every token comes back with `aud: []` no matter what the client requests, because Hydra ignores RFC 8707 `resource=` and Forseti default-denies unregistered audiences.

Details that matter:

- **Exact string.** The `aud` your server validates must match the registry row (URI rows tolerate a trailing-slash difference; the no-slash canonical form is what lands in the token). Agree on the canonical form with the operator and use it everywhere: registry row, your `resource` value in the RFC 9728 document, your server's expected audience.
- **No restart, no config edit.** The row takes effect on the next consent. The operator can disable it (tokens stop carrying your audience on new consents) or delete it.
- **Corroboration badge.** On create and re-check, Forseti fetches your `/.well-known/oauth-protected-resource` document and compares `resource` + `authorization_servers` against the row and its issuer. It's advisory — an `unreachable` badge before you've deployed is normal — but a green `corroborated` badge is a cheap sanity check that both sides agree.
- **Org scoping.** If your operator contact is an org-scoped admin (not a Forseti-wide one), they can only register resources on a domain their org has verified.
- **Scopes** — define a custom set scoped to your MCP server, convention `<app>:<resource>:<verb>` (e.g. `formshive:forms:read`). Have the operator add descriptions under `[oauth.scope_descriptions]` so the consent screen reads naturally.

### The two client paths: CIMD and pre-registered

Clients reach Hydra one of two ways. Neither involves a registration endpoint — RFC 7591 Dynamic Client Registration is retired (no `registration_endpoint` is advertised, Hydra's `/oauth2/register` is disabled).

**Path 1 — CIMD (Claude Code, claude.ai, any CIMD-capable client; zero coordination).** The client's `client_id` is an HTTPS URL pointing at a JSON metadata document the client's vendor hosts (Claude Code uses `https://claude.ai/oauth/claude-code-client-metadata`). Forseti advertises `client_id_metadata_document_supported: true` in the AS discovery document and serves the `authorization_endpoint` itself: on each authorize request with a URL-shaped `client_id`, it fetches the document (SSRF-guarded, cached), validates it (the document's `client_id` must equal its own URL; `token_endpoint_auth_method: "none"` only; code flow only; https or loopback redirect URIs), upserts the matching Hydra client, and forwards into Hydra's `/oauth2/auth`. Nobody registers anything; the client exists because its metadata URL answered.

What this means for you as an MCP-server author: **there is no client-side setup step**. A user runs `claude mcp add yourapp https://mcp.yourapp.com/mcp --transport http`, authenticates, and the flow works — provided your registry row (above) and RFC 9728 document (below) are in place.

Properties worth knowing:

- CIMD clients are public clients with PKCE, always. Confidential CIMD (`private_key_jwt`) is not supported.
- The consent screen shows the client URL's **host** (e.g. `claude.ai`) as the primary identity — the document's self-asserted `client_name` is secondary — and consent is always rendered, never skipped.
- A CIMD client's record is never audience policy: your registry row is the only thing that grants your `aud`. A malicious CIMD document cannot mint itself an audience.
- Ephemeral loopback callback ports (Claude Code picks one per login) are handled server-side; you don't care.

**Path 2 — Pre-registered client (everything else).** For clients that aren't CIMD-capable, or that you ship yourself: the operator creates a Hydra client via the admin UI's **MCP server** preset on `/admin/clients/new` — `authorization_code` + `refresh_token`, auth method `none`, PKCE enforced, your redirect URIs, your scopes, and optionally your audience directly on the client (an admin-created client's registered `audience` counts as consent policy on its own). Claude Code also supports this shape (`claude mcp add ... --client-id <id> --callback-port 8080`, ≥ v2.1.30), but with CIMD available there's rarely a reason.

### What end users see

Every OAuth2 client carries a verification state the operator manages in a Forseti-owned table (`oauth_client_metadata`) — deliberately out of any client's own reach.

- **CIMD clients** are permanently `unverified` and the consent screen leads with the client host (`claude.ai`) as the identity line, plus the caution banner; the "Reviewed by your administrator" checkmark is never shown for them. The host is the trust signal: it's what the operator of that URL provably controls, unlike the self-asserted display name.
- **Pre-registered clients** (admin-created) land **Verified**: a subtle green checkmark, no banner. The operator can revoke verification later (**Revoke verification** on the client's show page), which flips the consent screen back to the caution banner.

Users consent to your scopes either way; scope descriptions from `[oauth.scope_descriptions]` are what they actually read. Keep your advertised `scopes_supported` minimal (see below) so the first consent doesn't ask for admin.

### What your MCP server needs to implement

Two HTTP endpoints + one header. That's the entire OAuth surface; everything else is MCP protocol.

**1. `GET /.well-known/oauth-protected-resource`** — a static JSON document advertising your authorization server and the scopes you accept. Detail and sample document in [Resource discovery](#resource-discovery) below. Two things worth getting right on first try:

- **Publish `offline_access` in `scopes_supported`** (the OIDC Core 1.0 §11 standard name), not Hydra's legacy `offline` alias. Claude Code requests exactly what this list contains (it does not add `openid` on its own) and the requested scopes are unioned into the CIMD client's scope ceiling; publishing the wrong name earns you `invalid_scope` from Hydra. Keep the list minimal — read scopes only; clients that see no scope hint request everything in it, so an advertised admin scope makes every first connect an admin prompt. We hit both of these in our end-to-end tests — costs nothing to get right up front.
- **`bearer_methods_supported: ["header"]`** — `Authorization: Bearer <token>` is the only method modern clients use. The other RFC 6750 methods (query param, form body) are deprecated and discouraged.

**2. Your MCP endpoint** (path is yours; the convention is `POST /mcp`). On every request:

- **No `Authorization` header → 401** with `WWW-Authenticate: Bearer realm="<your-realm>", resource_metadata="<absolute URL to your /.well-known/oauth-protected-resource>"`. The client reads this to find your AS and start the OAuth dance.
- **Bearer token present → validate it locally** by verifying the JWT signature against Hydra's JWKS (see [Token validation](#token-validation-in-the-mcp-server) below for the full checklist: signature, `aud`, `exp`, `scope`). Invalid token → 401 with the same `WWW-Authenticate` header. Insufficient scope → 403 with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<required>"`.
- **Valid → process the MCP request** (`initialize`, `tools/list`, `tools/call`, etc).

**3. MCP protocol over the same endpoint.** Use whichever MCP SDK fits your language (TypeScript, Python — Anthropic ships both) or implement the JSON-RPC subset directly. The OAuth layer is independent of the protocol layer; they just share the endpoint.

That's the full implementation footprint. A working reference exists — we built one in ~150 lines of stdlib Python during this project's testing (`POST /mcp` + the well-known doc + JWKS-based bearer validation + one echo tool). Production servers add observability, real tools, and persistence on top, but the OAuth/discovery surface stays exactly this size.

### Resource discovery

Claude needs to find the authorization server. The MCP spec uses Protected Resource Metadata (RFC 9728): when an unauthenticated request hits your MCP server, respond with `401` and a `WWW-Authenticate: Bearer resource_metadata="https://mcp.yourapp.com/.well-known/oauth-protected-resource/mcp"` header.

Two RFC 9728 details that bite in practice: the well-known path is **path-aware** — for a resource identifier with a path (`https://mcp.yourapp.com/mcp`) the document lives at `/.well-known/oauth-protected-resource/mcp`, and a conformant client discards a document whose `resource` doesn't match the URL it was fetched from. And the document must be readable **cross-origin** (`Access-Control-Allow-Origin: *`) — claude.ai fetches it from the browser.

That metadata document points at the issuer:

```json
{
  "resource": "https://mcp.yourapp.com/mcp",
  "authorization_servers": ["https://accounts.example.com/hydra"],
  "scopes_supported": ["formshive:forms:read", "formshive:forms:write"],
  "bearer_methods_supported": ["header"]
}
```

The client resolves the issuer's AS metadata via RFC 8414 path insertion (`/.well-known/oauth-authorization-server/hydra` on the issuer host) — which Forseti serves, augmented with the CIMD flag and its shim `authorization_endpoint` — and runs the standard auth-code + PKCE flow from there, sending your resource URI as RFC 8707 `resource=`.

### Token validation in the MCP server

**Hydra issues JWT access tokens by default, with a 5-minute TTL.** You validate them locally by verifying the JWT signature against Hydra's JWKS — no network call to the AS on the hot path, no admin-API reachability needed.

Why JWT + local validation is the recommended path:

- **Resource servers can live anywhere.** All you need is a public reach to `https://hydra.example.com/.well-known/jwks.json`. Serverless, third-party VPC, customer-hosted — doesn't matter.
- **Revocation lag is bounded to 5 minutes.** The short TTL is the whole point. Once a user revokes Claude's grant at Forseti, the refresh exchange fails and the worst-case window before the agent stops working is the access-token TTL.
- **Same validation shape as the id_token** — fetch JWKS, cache by `kid`, verify RS256, validate `iss` / `aud` / `exp` / `nbf`. If you've already implemented [Validating the id_token](#validating-the-id_token), you've already implemented this.

Verification checklist:

1. **Signature** — verify against Hydra's JWKS (`<issuer>/.well-known/jwks.json`). Cache the keyset with a ~24h TTL; refetch on unknown `kid`.
2. **`iss`** — equals the `issuer` configured in `hydra.yml` (`urls.self.issuer`). Pin this value; don't trust the JWT body to tell you who signed it.
3. **`aud`** — contains your MCP server URL (the audience bound at consent from your registry row; see [Audience binding](./operator-guide.md#audience-binding-rfc-8707-resource-and-hydras-non-standard-audience) in the operator guide).
4. **`exp`** — not in the past (with a few seconds of clock skew).
5. **Scopes** — cover what the tool requires. Mind the spelling: Hydra emits the granted scopes as a **`scp` claim holding a JSON array**, not RFC 9068's space-delimited `scope` string. Accept either name in either shape, or every scoped tool 403s while the token looks valid.

Reject with `401` and `WWW-Authenticate: Bearer error="invalid_token"` on signature / aud / exp failures; reject with `403` and `error="insufficient_scope", scope="<required>"` on scope failures. Claude reads these and either refreshes or prompts the user to re-consent.

Hydra emits `typ: JWT` today, not RFC 9068's `typ: at+jwt`. If you use a strict validator, configure it to accept `JWT` here.

A typical Hydra-issued JWT access token payload:

```json
{
  "iss": "https://accounts.example.com/hydra",
  "sub": "f8c9d0e1-...",
  "aud": ["https://mcp.yourapp.com/mcp"],
  "scp": ["formshive:forms:read", "formshive:forms:write"],
  "exp": 1700000300,
  "iat": 1700000000,
  "jti": "5d7c3a91-2f04-4d8b-9e2c-a3b1d6f0e842",
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "acr": "aal1",
  "ext": { /* portal-injected extras, if any */ }
}
```

Cache `jti` for the token's lifetime on high-value endpoints — RFC 9068 mandates `jti` precisely so resource servers can detect replay of a captured token (defence beyond just `exp`).

#### Alternative: opaque + introspection (private-network only)

If you need true sub-minute revocation — e.g. a regulated environment where a 5-minute revocation lag is unacceptable — ask the operator to flip `strategies.access_token: opaque` in `hydra.yml`. Be clear-eyed about what you're signing up for:

> **Opaque token validation requires calling Hydra's introspection endpoint on the admin API (`/admin/oauth2/introspect` on `:4445`). The admin API is private and MUST NOT be exposed to the public internet.** Your MCP server therefore needs a route into the operator's internal network — service mesh, private link, VPC peering, whichever your platform calls it.

That constraint is the reason JWT is the default. If your MCP server runs on Cloudflare Workers, Vercel, a third-party SaaS, or anywhere else without a tunnel into the operator's admin network, opaque tokens **are not an option for you** — and the operator can't just "open up the admin API" to fix it, because that endpoint isn't authenticated at the application layer; the private network IS the auth boundary.

If you do have admin-network access, the introspection call looks like this:

```http
POST /admin/oauth2/introspect HTTP/1.1
Host: hydra-admin.internal:4445
Content-Type: application/x-www-form-urlencoded

token=<the access token>
```

Response is RFC 7662 standard; checklist is the same as for JWT but you replace "verify signature + iss" with "verify `active == true`". Cache positive responses for 5–30 seconds if you need throughput, but be conservative — caching defeats the immediate-revocation benefit that's the entire reason to pick opaque in the first place.

### Step-up for high-risk tools (experimental)

> **Best-effort, not verified.** As of January 2026, none of the major MCP clients (Claude Desktop, Claude Code, claude.ai, ChatGPT) publicly document RFC 9470 challenge handling. The pattern below is what the spec asks for; whether *your* client honours it is the open question. Implement it as defense-in-depth, but don't assume it'll trigger a fresh auth flow without testing against the specific client.

For destructive or irreversible MCP tools (delete data, transfer funds, manage credentials), pair the scope check with an AAL check. If the token's `acr` is `aal1`, reject with `401` and a [RFC 9470](https://datatracker.ietf.org/doc/html/rfc9470)-shaped challenge:

```
WWW-Authenticate: Bearer error="insufficient_user_authentication",
  error_description="A second factor is required for this tool",
  acr_values="aal2"
```

A spec-compliant client reads `acr_values` from the challenge and re-runs the auth-code flow with `acr_values=aal2`, which Forseti honors per [AAL step-up](#aal-step-up). The returned token's `acr` is now `aal2` and the tool call succeeds. A non-compliant client treats the 401 as a generic auth failure and may simply give up — fall back to a clear `error_description` that an end user can act on.

### Things not to do

- **Don't accept opaque secrets in headers** as a substitute for OAuth tokens. If your MCP server takes an API key, you've opted out of the user's portal identity and lost every benefit (revocation, audit, consent, AAL).
- **Don't trust `sub` for authorization** beyond identity. The user's *current* permissions belong in scopes; `sub` is just the stable identifier.
- **Don't skip `aud` validation.** Without it, any Hydra-issued access token works at your MCP server, including tokens minted for unrelated resources.
- **Don't filter `tools/list` by the token's granted scopes.** It deadlocks incremental consent: the first consent grants read scopes, a filtered list hides the write tools, the client never calls one, so it never receives the `403` + `insufficient_scope` challenge that would prompt the step-up. List every tool, note the required scope in the description of the ones the token can't use yet, and refuse at call time with the HTTP-level challenge.

### Known issues and further reading

- **Scope names come straight from your `scopes_supported`.** Claude Code requests exactly what your RFC 9728 document advertises (no `openid` added on its own). Publish `offline_access` (the OIDC standard name), not Hydra's legacy `offline` alias, or Hydra rejects with `invalid_scope` ([anthropics/claude-code#4540](https://github.com/anthropics/claude-code/issues/4540) — same Hydra-backed AS as ours). If your server can validate tokens against other IdPs too, advertising `openid` keeps those portable.
- **DCR-only clients don't work.** Cursor and other MCP clients that only implement RFC 7591 can't onboard — there is no registration endpoint. They'll work when they ship CIMD.
- **`FAST_JWT_MALFORMED` (or any "not a valid JWT") on token validation.** Means the operator has switched Hydra to opaque access tokens (`strategies.access_token: opaque`) but your MCP server is still trying to verify them as JWTs. Either switch your server to use Hydra's admin introspection endpoint (private network only — see [the opaque alternative above](#alternative-opaque--introspection-private-network-only)), or ask the operator to revert to the JWT default.
- **`active: false` on introspection of every token.** The inverse: operator is on the JWT default but your MCP server is calling introspection. Stop introspecting; verify the JWT against `<issuer>/.well-known/jwks.json` instead.
- **Testing without a browser.** Hydra's admin API lets you accept login and consent challenges programmatically (`PUT /admin/oauth2/auth/requests/login/accept` and `PUT /admin/oauth2/auth/requests/consent/accept`) with a synthetic subject. Useful for end-to-end tests of your MCP server's token flow without standing up a real Kratos identity.

Further reading:

- [Ory: Securing AI Agents with Ory Hydra and MCP](https://www.ory.com/blog/mcp-server-oauth-with-ory-hydra-authentication-ai-agent-integration-guide) — the canonical integration walkthrough from Ory.
- [getlarge.eu: Securing MCP Servers with OAuth2 — Ory Hydra + Claude Code + ChatGPT](https://getlarge.eu/blog/securing-mcp-servers-with-oauth2-ory-hydra-claude-code-chatgpt/) — community deep-dive with debugging tips for Claude Code and ChatGPT clients.
- [MCP Authorization spec (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) — the spec the section above implements.

## Account deletion webhooks

If you store a local copy of user data keyed by the `sub` claim, Forseti will tell you when a user self-deletes so you can clear your copy.

### How it works

When a signed-in user deletes their account from `/settings/account/delete`, Forseti:

1. Enumerates every OAuth2 client they have an active consent grant with.
2. For each client whose `metadata.forseti.account_deletion_url` is set, Forseti POSTs an RFC 8417 [Security Event Token](https://datatracker.ietf.org/doc/html/rfc8417) (a signed JWT, EdDSA / Ed25519 per [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)) carrying a single RISC `account-purged` event to that URL.
3. Retries on failure with exponential backoff (`1m × 2^attempt`, ±25 % jitter, capped at 6 h). Up to 12 attempts or 72 h total — whichever fires first marks the row dead-lettered.

Direction is one-way: portal → app. Apps cannot initiate identity deletion; only the user (from Forseti) or an operator (via `/admin/identities`) can.

The wire format and event vocabulary match Google's [Cross-Account Protection](https://developers.google.com/identity/protocols/risc) — if you already verify RISC events from Google, you can point the same handler at Forseti and the only thing that changes is the issuer URL on the JWT and the JWKS to verify against.

### Registering a deletion endpoint

1. Ask the operator to set `account_deletion_url` on your OAuth2 client at `/admin/clients/{id}`. The field accepts an HTTPS URL — that's the only knob.
2. Stand up an HTTPS endpoint that:
   - Accepts POSTs from Forseti's egress address. Forseti validates `account_deletion_url` at save time — `http://`, hostnames that resolve to loopback / link-local / RFC1918 / IMDS addresses, and anything reachable only via redirect through such ranges are rejected.
   - Reads the body as a compact JWS (`Content-Type: application/secevent+jwt`), verifies the signature against Forseti's JWKS, and validates the claims (see below).
   - Returns 2xx on success. Anything else triggers a retry. 3xx responses are not followed — the worker disables redirects.

There's no shared secret to mint or exchange. Forseti owns one Ed25519 signing key per installation; receivers verify with the matching public JWK, exactly like Hydra-issued id_tokens.

### Payload shape

The body is a compact JWS. Header:

```json
{ "alg": "EdDSA", "typ": "secevent+jwt", "kid": "<stable per-portal>" }
```

Decoded claims:

```json
{
  "iss": "https://portal.example.com",
  "aud": "<receiver client_id>",
  "iat": 1747824225,
  "jti": "f0c8a9e2-3b5d-4e1c-8f9a-1234567890ab",
  "events": {
    "https://schemas.openid.net/secevent/risc/event-type/account-purged": {
      "subject": {
        "subject_type": "iss-sub",
        "iss": "https://portal.example.com",
        "sub": "<kratos identity id, matches `sub` in id_tokens>"
      }
    }
  }
}
```

`iss` is Forseti's own externally reachable URL — same value Hydra puts on id_tokens for its issuer. `aud` is your client_id, so you can validate it with the same value you already pin for token verification.

### Validating the SET

On each delivery:

1. Fetch Forseti's signing JWKS from `https://portal.example.com/.well-known/webhook-jwks.json` (also advertised as `webhook_jwks_uri` on the [Forseti discovery document](#forseti-discovery-document)). The endpoint advertises `Cache-Control: max-age=86400`; cache locally by `kid` and refetch on miss.
2. Read the `kid` from the incoming JWT header, look it up in your cached JWKS, and verify the signature with EdDSA (Ed25519).
3. Check claims:
   - `iss` equals Forseti's URL you've configured (pin this string; don't trust the JWT body to tell you who it's from).
   - `aud` equals your OAuth2 client_id.
   - `events` carries the key `https://schemas.openid.net/secevent/risc/event-type/account-purged`.
   - `events[..].subject.sub` is the subject you want to purge.
4. Dedupe on `jti` — it's the event id, stable across retries.

### Verifying the SET (Node example)

Use a library. The example below uses [`jose`](https://github.com/panva/jose), which ships JWKS fetching, caching, and JWT verification in a single function call:

```javascript
import * as jose from "jose";

const PORTAL = "https://portal.example.com";
const AUDIENCE = "<your-client-id>";
const ACCOUNT_PURGED =
  "https://schemas.openid.net/secevent/risc/event-type/account-purged";

const JWKS = jose.createRemoteJWKSet(
  new URL(`${PORTAL}/.well-known/webhook-jwks.json`)
);

export async function handleAccountPurged(req, body) {
  const { payload } = await jose.jwtVerify(body, JWKS, {
    issuer: PORTAL,
    audience: AUDIENCE,
    typ: "secevent+jwt",
    algorithms: ["EdDSA"],
  });
  const event = payload.events?.[ACCOUNT_PURGED];
  if (!event) throw new Error("not an account-purged SET");
  const sub = event.subject?.sub;
  if (!sub) throw new Error("missing subject.sub");
  // Dedupe on jti — same event_id repeats across retries.
  if (await alreadyProcessed(payload.jti)) return 200;
  await purgeUser(sub);
  await recordProcessed(payload.jti);
  return 200;
}
```

Every other ecosystem has a comparable library — Python's [`PyJWT`](https://pyjwt.readthedocs.io/) with `PyJWKClient`, Go's [`github.com/golang-jwt/jwt`](https://github.com/golang-jwt/jwt) plus a JWKS fetcher, Java's `nimbus-jose-jwt`. Match the same shape: fetch JWKS by URL, cache by `kid`, verify EdDSA (Ed25519), validate `iss` + `aud` + the RISC event URI.

### Headers

Each delivery carries one portal-specific header:

- `X-Portal-Event: <jti>` — for body-less dedupe across retries, mirrors the `jti` claim inside the SET. Use whichever is more convenient.

The body itself is the compact JWS; there's no separate transport-level signature. Replay protection lives inside the SET (signature binds `iat` + `jti`).

### Idempotency and retries

- `jti` is a UUIDv4 unique per delete event, repeated across retries of that same event. Dedupe on it server-side.
- Receivers should be idempotent: if you've seen the `jti` before, return 2xx immediately.
- Forseti retries until it gets a 2xx, exhausts attempts, or hits the 72 h max age.

### Signing key rotation

Forseti-side signing key is operator-managed — drop a fresh PEM at `[webhook].signing_key_path` and restart. Receivers don't need to do anything special: cache JWKS by `kid` and refetch on miss. Same pattern you already use for id_token JWKS.

### Eventual-consistency fallback

If you don't register a webhook, or your webhook ultimately dead-letters, you'll still notice eventually: Hydra rejects token-refresh attempts for deleted subjects (Forseti revokes consent sessions as part of the delete saga). Webhooks are the *active* notification; refresh-failure is the passive safety net.

## Local fallback during IdP outage

Treat the IdP as a hard dependency for sign-in, not for *every* user action. When `accounts.example.com` is unreachable:

- Users who already have a session in your app continue working until their session expires.
- Users who need to sign in are blocked.

Mitigations to keep your app usable during an IdP outage:

- Long-lived application sessions (refresh proactively, but tolerate refresh failures within a grace window).
- Alternative auth paths: API keys, signed magic links, or a break-glass admin login that does not depend on the IdP.
- Cache the JWKS aggressively. Token verification keeps working even if Hydra is briefly unreachable.

Forseti is not a single point of failure if your app degrades gracefully.

## Scope reference

### Standard OIDC scopes

| Scope     | Effect                                                                    |
|-----------|---------------------------------------------------------------------------|
| `openid`  | Required for OIDC. Causes Hydra to return an id_token.                    |
| `email`   | Adds `email` and `email_verified` claims.                                 |
| `profile` | Adds `name`, `given_name`, `family_name` (if present in the identity), plus `preferred_username` and `updated_at` when the user set a handle. |
| `offline_access` | Adds a `refresh_token` to the token response. Hydra also accepts the bare `offline` alias for back-compat — prefer `offline_access` (OIDC Core 1.0 §11). |
| `org`     | Adds an `org` claim — `{ id, slug, role, name }`. When the auth request carries `organization_id=<id>`, the claim is pinned to that org (or omitted entirely if the user isn't a member — see below); otherwise it reflects the user's currently-active org (the signed `active_org` cookie, else their first membership). |
| `orgs`    | Adds an `orgs` claim — an array of `{ id, slug, role, name }` — listing every org the user belongs to. Capped at 32 entries. Apps that show a tenant picker request this. |
| `groups`  | Adds a `groups` claim, a flat array of the user's team slugs in their active org, for apps that map group names to roles (Parseable, Grafana, Argo CD). Empty array when the user has no teams. Capped at 200 with a `groups_truncated` flag. Scoped to the active org. |
| `profile` (extended) | When `[profiles].enabled = true` on Forseti, `profile` additionally surfaces `picture` (avatar URL) and `website` from the user's portal-owned profile. Standard OIDC slots — apps already requesting `profile` pick these up with no client-side change. Missing/empty fields are simply omitted. |
| `extended_profile` | Portal-owned non-standard claims: `bio`, `pronouns`, and `links` (array of `{label, url}`). Only added when `[profiles].enabled` is on AND the user filled the fields. Request alongside `profile` when you want the full profile block. Revocation is whole-grant — see `/settings/authorized-apps`. |

#### Active-org selection (`org` scope)

When a downstream app needs to scope an authentication to a specific org, it includes `organization_id=<id-or-slug>` on the `/oauth2/auth` URL alongside the usual OAuth2 parameters: either the org's stable id or its human-friendly slug works, Forseti resolves whichever you send to the same canonical org. It's a plain query parameter, so it survives Hydra's redirect chain untouched and reaches Forseti at the login and consent steps. `organization_id` is a private-use, Forseti-specific extension parameter, not part of the OIDC spec; treat it that way if you're building your own authorize URL rather than relying on a library default.

What happens next depends on the signed-in subject's membership in the pinned org:

1. **Already a member**: the `org` (and `groups`) claim is pinned to that org for this token, and the login step pre-selects it via the signed `active_org` cookie, regardless of which org the user last switched to in the portal. No extra step, no prompt.
2. **Not a member, and the org is public** (access mode `external` with public login enabled): before the login completes, Forseti shows a one-time "Join `<Org>`?" confirmation page. The user can confirm (they join as a member, then the login finishes with the `org` claim pinned to that org) or continue without joining (the login finishes with no `org`/`groups` claim for that org). This also covers a brand-new registrant who followed a pinned link: they land in the Default org first, then hit this same confirmation on their way back into the flow. Once a user has joined, they're never prompted again for that org.
3. **Not a member, and the org is private (invite-only) or the reference doesn't resolve**: the pin is silently ignored, no error UX, no interstitial, login proceeds with no `org`/`groups` claim for that org. Placement into a private org still only happens via invite acceptance or domain auto-join, unaffected by this parameter.

With no `organization_id` on the request, the claim reflects the user's currently-active org (the `active_org` cookie, else their first membership).

**When to pin, and when not to.** The pin only sets the singular `org`/`groups` (active-org) claim and can trigger the join interstitial. It does **not** narrow the plural `orgs` claim, which always carries the user's full membership list. So the pin is the right tool for a **single-tenant** app, or an app deployed once per tenant, where every login should be scoped to one org and new users funneled into it. It is the **wrong** tool for a **multi-tenant** app that reads the full `orgs` list and manages org context itself (its own org switcher, per-workspace routing, and so on): there the pin does nothing useful for the app (the app derives memberships from the full `orgs` claim and picks the active org its own way), and it actively adds friction, since every user who is not already a member of the pinned org sees a one-time "Join `<Org>`?" prompt on login, and if they accept, they are moved out of their Default org. Such apps should omit `organization_id` and consume the `orgs` list. If you build a client library or SDK that sets this parameter, default it to unset and document it as a single-tenant knob.

Example auth URL:

```
https://hydra.example.com/oauth2/auth?\
  client_id=acme-app\
  &response_type=code\
  &scope=openid%20email%20org\
  &redirect_uri=https://app.example.com/callback\
  &organization_id=acme\
  &state=...
```

The resulting `id_token` carries:

```json
{
  "iss": "https://hydra.example.com/",
  "sub": "01234567-...",
  "email": "alice@acme.example.com",
  "org": {
    "id": "acme",
    "slug": "acme",
    "role": "owner",
    "name": "Acme Co"
  }
}
```

Apps that need the full picker (e.g. "switch tenant" dropdown) request `org orgs` together.

#### Group-based roles (`groups` scope)

Apps that derive roles from group membership (Parseable, Grafana, Argo CD, Kubernetes) request `groups`. Forseti emits a flat array of the user's team slugs in the active org:

```json
{
  "groups": ["platform", "sre"]
}
```

Create teams in Forseti (Organizations, then Teams) and a matching role per slug in the downstream app. The claim is scoped to the active org, so a `groups`-only token carries no org discriminator; request `org` alongside it if the app needs to know which org the slugs belong to. Slugs are unique only within an org, not globally, so for a user in multiple orgs the same slug can map to different teams in different orgs. An app that derives roles from bare slugs should request `org` and key its role mapping on the (org, slug) pair, or restrict the client to a single org. Group changes propagate on the user's next sign-in or app authorization; they are not refreshed mid-session via the refresh-token grant.

### Custom scopes

Operators can register additional scopes when creating the client. Use them for app-specific permission grants (e.g. `formshive:forms:read`, `formshive:mcp:write`).

Custom scope semantics are opaque to Hydra and Forseti — they appear in the issued access token's `scope` claim, and your resource server is responsible for enforcing them. Document the meaning of each custom scope on your side; the consent screen shows them with whatever description the operator configured under `[oauth.scope_descriptions]` in Forseti config (see [operator-guide.md](./operator-guide.md#oauthscope_descriptions)).

## Further reading

- [`../README.md`](../README.md) — project overview, includes the original Logout integration summary
- [`operator-guide.md`](./operator-guide.md) — operator-side configuration
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [RFC 6749 — OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636) (for public clients)
- [Ory Hydra client docs](https://www.ory.sh/docs/hydra)
