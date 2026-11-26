# Built-in OAuth server

For operators running a build with the built-in OAuth server (`oauth-native`), which needs no Hydra. It covers what differs from the Hydra build: building it, its required settings, the issuer and endpoints, the signing key, clients, CIMD, device sign-in, logout, tokens, what it doesn't serve, and its background cleanup. Everything the builds share is in the [operator guide](./operator-guide.md); the identity side is in [Kratos identity backend](./operator-guide-kratos.md) or [Native identity backend](./operator-guide-native.md), depending on which one you build with.

The built-in server is an OAuth 2.0 and OpenID Connect authorization server inside Forseti. Clients, consent grants, login sessions, codes, refresh tokens and signing keys live in Forseti's own database, and the login and consent pages are the same `/oauth/login` and `/oauth/consent` handlers the Hydra build uses. Built together with the native identity backend, an install is one binary and one database. It's for fresh installs: there is no import of Hydra clients, consents or tokens.

## Building and running it

```bash
cargo build --release --locked --no-default-features --features identity-native,oauth-native
make check-matrix         # cargo check + clippy on all four backend combinations
make run-native-oauth     # debug run with both native backends against config.toml
```

Every build names one identity feature and one OAuth feature. The four valid builds are `identity-ory,oauth-ory` (the default), `identity-native,oauth-ory`, `identity-ory,oauth-native` and `identity-native,oauth-native`. `--all-features` does not build, and neither does a build that names only one axis: `--no-default-features --features identity-native` stops with a compile error that lists the four combinations.

With `identity-ory,oauth-native` Kratos stays: `[kratos]` and `[audit].webhook_token` are read as on the default build, and only Hydra drops out.

## What it serves and what it leaves out

Served:

- The authorization code flow (`response_type=code`), with `response_mode` `query` or `form_post`.
- PKCE with `S256` only. Public clients (`token_endpoint_auth_method: none`) must send a `code_challenge`; confidential clients may.
- The `authorization_code`, `refresh_token` and device code (`urn:ietf:params:oauth:grant-type:device_code`, RFC 8628) grants at the token endpoint, with client authentication `none`, `client_secret_basic` or `client_secret_post`.
- `prompt` values `none`, `login`, `consent` and `create`; `select_account` is accepted and ignored. `max_age`, `acr_values=aal2`, `login_hint`, `ui_locales` and `idp_hint` reach the login handler as on the Hydra build.
- RFC 8707 `resource=` and Hydra's `audience=`, both read. A requested `audience` must be on the client's registered `audience`; a `resource` is granted or not by consent, through the resource registry, as on the Hydra build.
- `iss` on every authorization response, success or error (RFC 9207).
- Userinfo, discovery and the JWKS.
- CIMD: a URL-shaped `client_id` at the authorization endpoint (see [CIMD](#cimd)).
- Device authorization at `/oauth2/device/auth`, which serves Linux device sign-in through PAM (see [Linux device sign-in](#linux-device-sign-in)).
- Token revocation (RFC 7009) and, on the internal listener, introspection (RFC 7662).
- RP-initiated logout and back-channel logout (see [Logout](#logout)).
- Signing key rotation with `forseti rotate-oauth-key`.

Not served, so these answer an error or have no route:

- The `client_credentials` grant. The admin UI's machine-to-machine preset is refused (see [Clients](#clients)).
- The `/hydra` front proxy and the path-insertion discovery routes (`/.well-known/oauth-authorization-server/hydra`).
- Request objects (`request`, `request_uri`), implicit and hybrid flows, and dynamic client registration.
- Pairwise subjects. `sub` is the identity id for every client.

Against the Hydra build as Forseti sets it up, that leaves the `/hydra` front proxy and `client_credentials` missing, plus request objects, which Hydra accepts.

Discovery advertises only what is served: `revocation_endpoint`, `device_authorization_endpoint` with the device code grant in `grant_types_supported`, `end_session_endpoint`, `backchannel_logout_supported` and `backchannel_logout_session_supported` (both `true`), and `client_id_metadata_document_supported: true`. There is no `introspection_endpoint` and no `registration_endpoint`.

## Configuration

`[hydra]` is not read. Two settings carry more weight than on the Hydra build, and Forseti refuses to boot without them:

- `[self].url` is the issuer. It must be an `http` or `https` origin with no path, query, fragment or userinfo (`https://accounts.example.com`, a trailing slash is fine); anything else is a boot error. Changing it later changes `iss` in every token and every endpoint in discovery, so treat it as fixed once clients are registered.
- `[security].cookie_secret` is key material (below).

`[oauth].login_session_remember_for` keeps its meaning: how long a sign-in at the authorization server is remembered, in seconds, default `86400`. The built-in server caps it at 30 days, and `0` or a negative value means those 30 days.

`[posix].hydra_issuer` only logs a warning at boot: it has no meaning where the issuer is `[self].url`, and device sign-in checks the ID token against `[self].url` whatever it says. `[posix].pam_client_id` and `pam_client_secret` work as on the Hydra build.

`[oauth.cimd]` works as on the Hydra build (see [CIMD](#cimd)). Its `allow_private_targets` also governs back-channel logout delivery (see [Logout](#logout)).

## Endpoints and issuer

The endpoints keep Hydra's paths, so a client that hardcoded them only needs the new origin. All of them are on `[self].url`, at the root of Forseti's host.

| Path | What |
|---|---|
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | Discovery, the same document at both paths, `Access-Control-Allow-Origin: *` |
| `/.well-known/jwks.json` | Public signing keys, active and retired, `Cache-Control: private, no-cache, no-store, must-revalidate` |
| `/oauth2/authorize` (advertised), `/oauth2/auth` | Authorization endpoint, GET or POST |
| `/oauth2/auth/resume/{flow_id}?verifier=...` | Where the login and consent handlers hand the browser back; not for clients |
| `/oauth2/token` | Token endpoint |
| `/oauth2/device/auth` | Device authorization, POST |
| `/oauth2/revoke` | Token revocation, POST |
| `/oauth2/sessions/logout` | RP-initiated logout, GET or POST |
| `/userinfo` | Userinfo, GET or POST |

Introspection, `POST /oauth2/introspect`, is on the internal listener (`[internal].bind`), not on `[self].url`, and discovery doesn't advertise it (see [Introspection](#introspection)).

Every pending authorization request gets its own binding cookie, `forseti_flow`, with `Path=/oauth2/auth/resume/{flow_id}` and `Max-Age` 1800 (the 30 minutes a request has). The resume step accepts the request only from the browser that holds it, and the final response clears it. Device sign-in requests carry none (see [Linux device sign-in](#linux-device-sign-in)).

Discovery lists `idp_hints_supported` from the identity backend's providers, as on the Hydra build.

## `cookie_secret` and the signing key

`[security].cookie_secret` is required on every build with a native backend. On this build the RS256 signing key (RSA 2048, `kid` is its RFC 7638 thumbprint) is generated on first boot and stored in `oauth_signing_keys`, its private half sealed under a key derived from the secret. The secret also signs the `forseti_op` and `forseti_flow` cookies.

A stored key that doesn't open under the current secret is a hard boot error:

```
the sealed OAuth signing key <kid> does not open under the current [security].cookie_secret; restore the cookie secret it was sealed with
```

Forseti never generates a replacement over a key it can't open. Changing or losing the secret means one of two things:

- restore the secret the key was sealed with, or
- delete the rows in `oauth_signing_keys`, after which the next boot generates a new key. That changes the JWKS and makes every token issued so far fail verification, and with the native identity backend the secret change also costs everything listed under [`cookie_secret` is key material](./operator-guide-native.md#cookie_secret-is-key-material).

Back the secret up with the database.

`forseti rotate-oauth-key` retires the active key and stores a new one in one transaction. It prints `rotate-oauth-key: retired <kid>, active <kid>` and a line saying running instances switch at their next key reload, within an hour, and exits 0; on failure it prints the reason to stderr and exits 1. It refuses when a stored key doesn't open under the current secret, when there is no active key, and when another rotation changed the active key first; nothing changes then.

Rotation is not revocation. Retired keys stay published in the JWKS and keep verifying the tokens they signed, and nothing deletes them. To remove a leaked key, rotate, then delete its row from `oauth_signing_keys`; running instances drop it at their next reload.

Running instances pick up a rotation without a restart. Each reloads the keys from the database hourly, on a JWKS request whose stored key list differs from the loaded one, and on a token whose `kid` it doesn't know, at most once per 2 seconds. Until an instance reloads, it signs with the retired key, for up to an hour. An instance that reloaded less than 2 seconds before the rotation refuses tokens signed with the new key for about those 2 seconds, and its JWKS lacks the new key for as long.

The JWKS answers `no-store` and sits behind a per-IP limit (300 per minute, 3000 per hour), so relying parties should cache it and refetch on an unknown `kid`.

## Clients

Clients are managed on the same admin pages (`/admin/clients`), with the same app templates. The store follows Hydra's client shape, with these rules:

- **Redirect URIs match exactly**, byte for byte. The one exception is `http` on `localhost`, `127.0.0.1` or `[::1]`, where the port is ignored (RFC 8252), so a native app can pick a port per login. URIs with a fragment, userinfo or a `javascript`, `data`, `vbscript`, `file` or `blob` scheme are refused at registration.
- **Auth method**: `none`, `client_secret_basic` (the default when none is set) or `client_secret_post`. A client authenticates with exactly its registered method.
- **Secrets** are generated (`posix-init-client` uses `[posix].pam_client_secret` when it is set), stored as Argon2id hashes and shown once, on create and on rotate. There is no way to read one back.
- **Grant types** must be within `authorization_code`, `refresh_token` and `urn:ietf:params:oauth:grant-type:device_code`; an empty list means `authorization_code` only. A client needs `refresh_token` in its grant types to get refresh tokens. The admin UI's machine-to-machine preset (`client_credentials`) is refused with "Failed to create client: invalid OAuth client: grant_types must be within authorization_code, refresh_token and urn:ietf:params:oauth:grant-type:device_code".
- **Response types** must be within `code` and `id_token`; the authorization endpoint still requires `code`.
- **`client_uri`, `logo_uri`, `backchannel_logout_uri` and `frontchannel_logout_uri`** must be absolute `http` or `https` URIs without whitespace, fragment or userinfo, or empty.
- A client stored with values outside these rules can't be saved in the admin form until its lists are fixed.
- Deleting a client deletes its pending requests, grants, codes and refresh tokens.

Consent is skipped when the newest remembered grant of the user to the client covers the requested scopes and audiences and the request doesn't carry `prompt=consent`. For a public client the earlier grant only counts when the redirect URI is `https` or loopback `http`. `skip_consent` on the client works as on the Hydra build, with one difference: a grant made without the consent screen because of `skip_consent` never counts as an earlier grant, so after `skip_consent` is turned off users see the consent screen.

## CIMD

A URL-shaped `client_id` (`https://`, or `http://` under `[oauth.cimd].allow_private_targets`) at `/oauth2/authorize` or `/oauth2/auth` is resolved as on the Hydra build, before the request is validated: the document is fetched and checked, and the client is created or updated in `oauth_clients` with its trust row in `oauth_client_metadata`. The checks, scope ceiling, host policy, ceilings, global limit, audit events and consent display are the ones in [CIMD: zero-config client onboarding](./operator-guide.md#cimd-zero-config-client-onboarding). What differs:

- The client stores exactly the document's redirect URIs. There is no loopback literal: loopback ports are ignored when the redirect URI is matched (see [Clients](#clients)), so a new ephemeral port doesn't write to the client.
- A `client_uri` or `logo_uri` from the document that the client store refuses is dropped. A document redirect URI the store refuses fails the request with `502` ("cimd: client registration unavailable").
- `[oauth.cimd].ip_rate_per_minute` and `ip_rate_per_hour` (defaults 10 and 100) limit authorization requests that name a CIMD client, per client IP, inside the authorization endpoint's own limit. A request without a client IP is refused. Both at `0` turn the limit off.
- Other failures answer as on the Hydra build: a plain-text `400` naming the reason, `429` with `Retry-After`, or `503`.

In an RFC 9728 document, `authorization_servers` names `[self].url`; discovery is at its root, so no path-insertion route is needed.

## Linux device sign-in

Device authorization (`POST /oauth2/device/auth`, RFC 8628) and the device code grant at the token endpoint serve the Linux PAM sign-in described in [Enabling PAM login](./operator-guide.md#enabling-pam-login-device-auth); the setup is the same, `forseti posix-init-client` included. The verification page `/oauth/device` approves only a device session a PAM host started, so a device code from any other client can never be approved even though discovery advertises the endpoint.

- A device code lasts 10 minutes, the poll interval is 5 seconds, and each `slow_down` raises it by 5 seconds. User codes are `XXXX-XXXX` from a 20-consonant alphabet; case, spaces and dashes don't matter when one is typed.
- A client has at most 1000 undecided device codes at a time; past that `/oauth2/device/auth` answers `429 temporarily_unavailable`.
- Every device approval shows the consent screen, whatever the client's `skip_consent` or an earlier grant says.
- A device sign-in request carries no `forseti_flow` cookie and never sets `forseti_op`. It is created only behind a signed-in session that passes the approver check, and the host's poll checks that the token's subject is the account it named.

## Logout

`GET` or `POST /oauth2/sessions/logout` (RP-Initiated Logout 1.0) takes `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`, and ignores `logout_hint` and `ui_locales`.

- With an `id_token_hint`, the hint names the session and the client. It must be an ID token this server signed (its `exp` isn't checked), with one audience and a `sid` and `sub`. A `client_id`, if sent, must be that audience. The session the hint names ends, and so does the browser's current session when it is another session of the same user; a browser session of another user is left alone.
- Without a hint, the `forseti_op` cookie names the session, and a `post_logout_redirect_uri` is refused.
- A `post_logout_redirect_uri` must be an `http` or `https` URI registered on the client, byte for byte. `state` may be up to 2048 bytes and is appended to it.
- Everything else goes to Forseti's error page and never to the client: a request over 16 KiB, a longer `state`, a repeated parameter, an invalid hint, a mismatched `client_id`, an unregistered or non-web redirect URI, and a request with neither a hint nor a cookie naming a live session.

A valid request lands on the confirmation page (`/oauth/logout`), which the user has 30 minutes to confirm. Confirming ends those login sessions and signs the browser out of Forseti, then redirects to the `post_logout_redirect_uri` with `state` if the client still registers it, or to `/signed-out`. Grants stay, so refresh tokens keep working.

**Back-channel logout.** When a login session ends by `sid` (this logout, signing out of Forseti, ending a session on `/settings/sessions` or `/admin/sessions`), every client with a grant under that session and a `backchannel_logout_uri` gets one logout token, at most once per session. It is a `POST` of `logout_token=<jwt>` with a 3 second timeout, no retry; any `2xx` counts as delivered. A failure is logged with the client id and host and audited as `oauth.backchannel_logout.failed`. An admin disable or an identity deletion ends each recorded session by `sid` first, which sends tokens; the subject-wide revoke that follows as a backstop sends none.

The token is RS256 with header `typ: logout+jwt` and the server's `kid`, and carries `iss`, `aud` (the client id, as an array), `iat`, `exp` (`iat` plus 120 seconds), `jti`, `sub`, `sid` and `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`, and no `nonce`. Unlike Hydra's token it has `exp` and `typ: logout+jwt`, so a receiver that pins `typ` to `JWT` refuses it.

Delivery goes through the same outbound guard as CIMD fetches: `https` only, no private or loopback address. `[oauth.cimd].allow_private_targets` lifts both, and Forseti refuses to boot with it on a production-shaped `[self].url` (https on a public host). A production install therefore can't deliver to a `backchannel_logout_uri` on a private address, and without the hatch only `https` targets get a token.

## Tokens and lifetimes

| Token | Shape | Lifetime |
|---|---|---|
| Authorization code | opaque, one use | 10 minutes |
| Access token | RS256 JWT, header `typ: at+jwt` | 5 minutes |
| ID token | RS256 JWT, header `typ: JWT` | 1 hour |
| Refresh token | opaque | 720 hours, counted from each rotation |

The lifetimes are fixed, not configurable; they're the values the Hydra build's reference config sets. An authorization request has 30 minutes from the authorize call to the code.

**Access tokens** follow RFC 9068: `iss`, `sub`, `aud` (an array, possibly empty), `client_id`, `iat`, `nbf`, `exp`, `jti` and a space-separated `scope`. Hydra's shape is kept next to it: `scp` holds the same scopes as an array, `ext` holds the consent handler's access-token claims, and the claims the resource registry promotes are also copied to the top level. `acr` is set when known, and the private `gid` claim names the consent grant. A resource server whose validator pins the header `typ` to `JWT` rejects these tokens; it has to accept `at+jwt`.

**Refresh tokens** are issued only when the grant holds `offline_access` (or `offline`) and the client has the `refresh_token` grant type. Each use returns a new refresh token and ends the old one. A refresh token presented a second time deletes every refresh token descended from the same code exchange, and a code redeemed a second time does the same. Access tokens already issued stay valid until they expire, since resource servers check them locally.

**Subjects** are public: `sub` is the identity id, the same for every client.

Revoking an app at `/settings/authorized-apps` deletes the grant with its codes and refresh tokens; `/userinfo` refuses access tokens that name it, and resource servers keep accepting those access tokens until they expire.

**Revocation.** `POST /oauth2/revoke` (RFC 7009) takes `token` and authenticates the client as the token endpoint does; a public client sends its `client_id` and revokes its own tokens. `token_type_hint` is ignored. A refresh token of the calling client deletes its family (every refresh token descended from the same code exchange, a rotated one included) and ends the grant's access tokens at `/userinfo` and introspection. An access token of the calling client goes on a denylist by `jti` until it expires, which `/userinfo` and introspection honour. A resource server that validates the JWT locally sees neither and accepts the token until its `exp`, at most 5 minutes. Unknown, expired, malformed and other clients' tokens answer `200` and change nothing.

### Introspection

`POST /oauth2/introspect` (RFC 7662) is on the internal listener only and isn't advertised. Only confidential clients may call it, authenticated as at the token endpoint; a request without a secret is `401 invalid_client`. Any authenticated confidential client may introspect any token.

An access token is active while it verifies, its `exp` is ahead, its `jti` isn't denied, its grant still exists for the same subject and client, and that grant's tokens weren't revoked. The answer is `active: true` with `scope`, `client_id`, `sub`, `exp`, `iat`, `nbf`, `aud`, `iss`, `jti` and `token_type: bearer`. A refresh token is active while it is stored, unused and unexpired; the answer carries `scope`, `client_id`, `sub`, `exp`, `iat`, `aud` and `iss`. Anything else is `{"active": false}`.

Every call runs an Argon2 check of the client secret. Those checks share one limit with the token, revocation and device authorization endpoints (one per CPU at a time), so introspecting on every request costs a hash each and can push all of them into `503` (see [Rate limits](#rate-limits)). The endpoint has its own per-IP limit (below), keyed by `[internal].trust_forwarded_for`.

## `form_post` and `form-action`

The `form_post` page allows form submission to the redirect URI's origin only. A client callback that answers the POST with a redirect to another origin can be blocked by the browser's `form-action` enforcement (Chrome and Safari check every hop of the redirect chain). Callbacks that finish on their own origin aren't affected.

## Rate limits

Per client IP, resolved through `[proxy]`; past a bucket the answer is a `429` with `Retry-After`.

| Endpoint | Limit |
|---|---|
| `/oauth2/authorize`, `/oauth2/auth`, `/oauth2/auth/resume/*`, together | 120 per minute, 1200 per hour |
| Authorization requests naming a CIMD client, within the above | `[oauth.cimd].ip_rate_per_*`, default 10 per minute, 100 per hour |
| `/oauth2/sessions/logout` | 120 per minute, 1200 per hour |
| `/oauth2/token` | 300 per minute, 3000 per hour |
| `/oauth2/device/auth` | 300 per minute, 3000 per hour |
| `/oauth2/revoke` | 300 per minute, 3000 per hour |
| `/oauth2/introspect` (internal listener, client IP through `[internal]`) | 300 per minute, 3000 per hour |
| `/userinfo` | 300 per minute, 3000 per hour |
| `/.well-known/jwks.json` | 300 per minute, 3000 per hour |

Each row is a bucket of its own. Client secret checks at the token, device authorization, revocation and introspection endpoints share one limit of one Argon2 run per CPU at a time; a request that waits longer than 3 seconds for a slot gets `503 temporarily_unavailable` with `Retry-After: 3`.

## Maintenance

A minute after boot and then hourly, Forseti reloads the signing keys and deletes:

- authorization requests, login sessions, device codes and logout requests a day after they expired;
- authorization codes an hour after they expired, used ones included, so a replay is still recognised until then;
- refresh tokens once they expire unused, and used ones 7 days after their use. A used token replayed after those 7 days is refused as unknown and no longer ends the rest of its chain;
- denylisted access tokens an hour after their stored expiry;
- grants that were not remembered or came from a skipped consent, a day after they were given, once no refresh token refers to them and their login session is gone.

Remembered grants stay until revoked, and signing keys are never deleted.

## Admin status and configuration

`/admin/status` shows the server as "OAuth (built in, alive)" and "OAuth (built in, ready)" (ready runs a database query and needs the signing keys loaded), and the build row labelled "Hydra" shows `native <version>`. `/admin/configuration` shows the issuer, endpoints and capabilities from the built-in discovery document and the stored signing keys.

## Tables

The built-in server owns ten tables in Forseti's database: `oauth_signing_keys`, `oauth_clients`, `oauth_authorize_requests`, `oauth_login_sessions`, `oauth_consent_grants`, `oauth_authorization_codes`, `oauth_refresh_tokens`, `oauth_revoked_tokens`, `oauth_device_codes` and `oauth_logout_requests`. Codes, device codes, refresh tokens, challenges and client secrets are stored as hashes, the private signing keys sealed. The migrations create the tables on every build; they stay empty on the Hydra build. Back them up with the rest of Forseti's database (see [Backups](./operator-guide.md#backups)), together with `cookie_secret`.

## Reverse proxy

There is no Hydra to route. `/oauth2/*`, `/userinfo` and `/.well-known/*` belong to Forseti at the root of its host, and `/oauth2/introspect` stays on the internal listener; see [Built-in OAuth build](./operator-guide-proxy.md#built-in-oauth-build) in the proxy guide.

## Development

- `make check-matrix`: `cargo check` and clippy on all four combinations.
- `make stack-up-native-oauth`: Mailcrab and the mock OIDC upstream only, no Kratos and no Hydra.
- `make run-native-oauth`: Forseti with both native backends.
- `make seed-admin-native-oauth`: the deterministic admin (password and TOTP) in `forseti.db`, then `posix-init-client` for the `forseti-linux-pam` client; start Forseti once first so the database exists.
- `make test-integration-native-oauth`: the integration suite against that running Forseti, with `config.ci.native-oauth.toml`.
