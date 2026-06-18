# Proxy Layout

## Shape sketches

### Example (1) — single host, path-prefixed upstreams

```
accounts.example.com

Forseti
  /login
  /settings
  /...
  /.well-known/webhook-jwks.json

Hydra                    (iss = https://accounts.example.com/hydra)
  /hydra/.well-known/openid-configuration
  /hydra/.well-known/jwks.json
  /hydra/oauth2/auth
  /hydra/oauth2/token
  /hydra/oauth2/register
  /hydra/oauth2/sessions/logout
  /hydra/userinfo
  /hydra/...

Kratos                   (server-to-server from Forseti; browser hits webauthn.js)
  /kratos/.well-known/ory/webauthn.js
  /kratos/self-service/...
  /kratos/sessions/whoami
  /kratos/...
```

Proxy must rewrite `/hydra/*` and `/kratos/*` to the upstream root path — Hydra and Kratos do not honour subpath mounting ([hydra#352](https://github.com/ory/hydra/issues/352), [kratos#1152](https://github.com/ory/kratos/issues/1152)).

### Example (2) — Forseti at root, Hydra/Kratos on subdomains

```
accounts.example.com           (Forseti)
  /login
  /settings
  /...
  /.well-known/webhook-jwks.json

hydra.accounts.example.com     (iss = https://hydra.accounts.example.com)
  /.well-known/openid-configuration
  /.well-known/jwks.json
  /oauth2/auth
  /oauth2/token
  /oauth2/register
  /oauth2/sessions/logout
  /userinfo
  /...

kratos.accounts.example.com    (server-to-server from Forseti; browser hits webauthn.js)
  /.well-known/ory/webauthn.js
  /self-service/...
  /sessions/whoami
  /...
```

No path rewrites. Each upstream serves at its own root. Wildcard TLS cert (`*.accounts.example.com`) covers all three names.

### Example (3) — single host, distinct ports

```
accounts.example.com:443       (Forseti)
accounts.example.com:8443      (Hydra, iss = https://accounts.example.com:8443)
accounts.example.com:9443      (Kratos)
```

Same well-known paths as Example (2) on each port. One TLS cert reused across ports.

---

## Feasibility & tradeoffs (per Ory docs)

TL;DR: ship Shape (1), reserve (2) for when you outgrow it, do not ship (3).

| # | Topology                                  | Feasible per Ory docs? | Cookie mode | CORS mode | Verdict |
|---|-------------------------------------------|------------------------|-------------|-----------|---------|
| 1 | Single host, path-prefixed                | Yes — explicitly endorsed by Hydra's prod guide (Kong `strip_request_path=true` + `preserve_host=true`) | Same-origin. Cookies default to host-only on `accounts.example.com`. `SameSite=Lax`. No `Domain=` needed. CSRF "just works" | Not required for browsers (everything is same-origin). Hydra `allowed_cors_origins` only needed for RP-side token/userinfo XHR | **Production-recommended** |
| 2 | Forseti at root, Hydra/Kratos on subdomains | Yes — matches the canonical `accounts.example.com` / `oauth2.example.com` examples | Cross-subdomain. Top-level navigation flows still work with `SameSite=Lax`; avoid widening with `cookies.domain` unless you have a reason | Required if Forseti ever calls Kratos/Hydra from the browser. Kratos `cors.allowed_origins` and Hydra global CORS must include `https://accounts.example.com` | **Workable** |
| 3 | Single host, distinct ports               | Technically works (Kratos docs: "HTTP Cookies ignore ports") but no Ory example uses this shape and Hydra's CSRF debug guide flags host/port inconsistency | Cookies shared across ports — but browsers treat `:443` and `:8443` as different *origins* (origin = scheme + host + port), so XHR between them is cross-origin | Same-origin per spec only when scheme+host+port match — any browser-side call needs full CORS, defeating the point | **Don't ship** |

### Shape (1) details

**Feasibility.** Hydra's production guide explicitly endorses this:

> "If you use the Mashape Kong API gateway, you can achieve this by setting `strip_request_path=true` and `preserve_host=true`. This ensures Hydra correctly computes consent challenge values."
> — *Hydra self-hosted production*

Set:

```yaml
# hydra
urls:
  self:
    issuer: https://accounts.example.com/hydra
    public: https://accounts.example.com/hydra
# kratos
serve:
  public:
    base_url: https://accounts.example.com/kratos
```

Forseti's `/.well-known/webhook-jwks.json` does **not** collide with Hydra's `/.well-known/jwks.json` — from the browser's perspective Hydra's is at `/hydra/.well-known/jwks.json`. Hydra's published discovery doc will (correctly) advertise `jwks_uri: https://accounts.example.com/hydra/.well-known/jwks.json` because the issuer is set with the prefix.

**Cookies & CSRF.** Everything is same-origin. Three cookies coexist:

- Forseti session/CSRF (`Path=/`, host-only, `SameSite=Lax`, `Secure`, `HttpOnly`)
- Hydra `ory_hydra_session`, `ory_hydra_login_csrf_<hash>`, `ory_hydra_consent_csrf_<hash>` (host-only, `Lax`, `Secure`)
- Kratos `ory_kratos_session`, `csrf_token_<hash>` (host-only, `Lax`, `Secure`)

**Do not set `cookies.domain`** on either Hydra or Kratos in this shape. Host-only is tighter and there's no cross-subdomain traffic to enable.

Per the Hydra CSRF debug doc, path rewrites in proxies can interfere with cookie handling. Mitigation: haproxy doesn't strip `Cookie`, and the path rewrite happens before the upstream sees the request, so cookie path matching works on both sides — browsers see `Path=/` cookies (Hydra default) sent for any URL on the host.

**CORS.** Not required for any browser flow — login/consent are top-level navigations, Forseti calls Kratos/Hydra server-to-server, and `/.well-known/ory/webauthn.js` is a same-origin `<script>` load. `allowed_cors_origins` on individual OAuth2 clients is still needed for RPs that make browser-side token/userinfo XHR, but that's RP-determined, not topology-determined.

**Gotchas.**

- `X-Forwarded-Proto: https` is mandatory — without it, Hydra/Kratos emit `http://` URLs and CSRF cookies without `Secure`. The CSRF debug doc is explicit about this.
- `X-Forwarded-Host` must reflect the public hostname so issuer/return-to URLs stay consistent.
- Path rewrite must be exact: `/hydra/oauth2/auth` → upstream `/oauth2/auth`. Off-by-one (`/hydra/hydra/oauth2/auth`) is the #1 source of "consent challenge invalid" errors.
- No double-slashes after rewrite — some haproxy versions emit `//oauth2/auth` if you naively replace.
- Admin APIs of Hydra (`:4445`) and Kratos (`:4434`) must not be exposed through the public proxy. Bind to loopback and either keep them off haproxy or expose on a separate internal listener.

### Shape (2) details

**Feasibility.** This is the canonical Ory example shape (`accounts.example.com` for Kratos, `oauth2.example.com` for Hydra). Both deploy guides use it verbatim. Fully supported.

**Cookies & CSRF.** Three eTLD+1 siblings sharing `accounts.example.com` as parent. To make Forseti's session cookie reachable when Hydra's consent endpoint redirects back, two options:

1. **Host-only cookies, redirect-based flows.** Each service sets its own host-only cookie. Cross-subdomain hops are top-level navigations, so `SameSite=Lax` allows the cookies on the GET that lands at each upstream. **Right answer.**
2. **`cookies.domain=accounts.example.com` on Hydra and Kratos.** Per the Kratos multi-domain doc: *"Subdomains can set HTTP Cookies for parent domains."* Don't do this unless you have a concrete reason — widens scope unnecessarily and collides if Forseti cookie names overlap.

The Kratos multi-domain doc also notes:

> "Setting up Ory Kratos in a way where you get session cookies running on two separate top level domains... is supported only on Ory Network or Ory Kratos Enterprise."

Stay under one eTLD+1.

**CORS.** Now genuinely cross-origin if Forseti ever fetches Kratos from the browser. You don't today (server-to-server), and `/.well-known/ory/webauthn.js` via `<script>` tag is not a CORS request — but any future browser-side `whoami` polling or JS-driven flow becomes one. Configure Kratos:

```yaml
serve:
  public:
    cors:
      enabled: true
      allowed_origins: ["https://accounts.example.com"]
      allowed_methods: [POST, GET, PUT, PATCH, DELETE]
      allowed_headers: [Authorization, Cookie, Content-Type]
      exposed_headers: [Content-Type, Set-Cookie]
      allow_credentials: true
```

Hydra hard rule from its CORS doc:

> "The authorization endpoint (`/oauth2/auth`) never supports CORS."

Fine — it's a navigation, not an XHR. Token/userinfo CORS is per-client via `allowed_cors_origins` plus global config for OPTIONS preflight.

**Gotchas.** Wildcard TLS cert or three SANs. Three DNS records. HSTS preload covers the parent — fine, but means no plaintext on any subdomain forever.

### Shape (3) details

**Feasibility.** Kratos docs confirm cookies cross ports: *"HTTP Cookies ignore ports."* So cookies flow across `:443`/`:8443`/`:9443`. But Hydra's CSRF debug guide treats host/port inconsistency as a top failure mode, and no Ory example uses this shape.

**Cookies & CSRF.** Same-host, same-domain — cookies shared across ports. In practice:

- Some browsers and proxies normalise `:443` away but not `:8443`, leading to `issuer` mismatches in OIDC discovery.
- `Secure` cookies on non-443 HTTPS ports work, but some corporate proxies / WAFs only understand 443.

**CORS.** Browsers treat `https://accounts.example.com:443` and `https://accounts.example.com:8443` as **different origins** (origin = scheme + host + port). XHR between them is cross-origin and needs full CORS — you get cookie-sharing of Shape (1) *and* CORS pain of Shape (2), with non-default ports that break corporate egress and look like a self-hosted toy.

**Verdict.** Don't ship. No upside over (1).

---

## haproxy sketches

**Strip inbound `X-Forwarded-*` before setting your own.** Forseti's per-IP rate limiters (DCR proxy, handoff, claim-email) and the audit middleware default to keying on the TCP peer IP (`proxy.trust_forwarded_for = false`) — secure but, behind a proxy, every caller shares one bucket. To restore per-real-client buckets, operators set `proxy.trust_forwarded_for = true` *and* must guarantee the proxy strips client-sent `X-Forwarded-*` headers before re-adding its own; without the strip, a caller forges `X-Forwarded-For: <random>` and bypasses the limit (and spoofs their audited IP). The sketches below delete the inbound headers before `set-header`; operators using a different proxy (nginx, caddy, envoy) must do the equivalent before turning the flag on.

### Shape (1) — path-prefixed

```haproxy
frontend fe_accounts
    bind *:443 ssl crt /etc/haproxy/certs/accounts.example.com.pem alpn h2,http/1.1
    http-request redirect scheme https code 301 unless { ssl_fc }

    # Drop anything the client may have sent — only our values are trusted.
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host

    # Forwarded headers — Hydra/Kratos rely on these to emit https URLs
    # and to compute consent challenges (preserve_host equivalent).
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]
    http-request set-header X-Real-IP         %[src]
    http-request set-header X-Forwarded-For   %[src]

    acl is_hydra  path_beg /hydra/
    acl is_kratos path_beg /kratos/

    # Strip the prefix BEFORE upstream sees it. Hydra/Kratos serve at root.
    http-request replace-path ^/hydra/?(.*)  /\1 if is_hydra
    http-request replace-path ^/kratos/?(.*) /\1 if is_kratos

    use_backend be_hydra  if is_hydra
    use_backend be_kratos if is_kratos
    default_backend be_forseti

backend be_forseti
    server forseti 127.0.0.1:3000 check

# DO NOT add backends for Hydra :4445 or Kratos :4434 here.
# Admin APIs must stay on loopback. If you need remote access,
# expose them via a separate internal listener with its own auth.
backend be_hydra
    # Hydra public port; admin (4445) bound to loopback, never proxied.
    server hydra  127.0.0.1:4444 check

backend be_kratos
    # Kratos public port; admin (4434) bound to loopback, never proxied.
    server kratos 127.0.0.1:4433 check
```

### Shape (2) — subdomain ACLs

```haproxy
frontend fe_accounts
    bind *:443 ssl crt /etc/haproxy/certs/accounts.example.com-wildcard.pem alpn h2,http/1.1
    http-request redirect scheme https code 301 unless { ssl_fc }

    # Drop anything the client may have sent — only our values are trusted.
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host

    # Same forwarded headers — each upstream sees its own subdomain.
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]
    http-request set-header X-Real-IP         %[src]

    acl host_hydra  req.hdr(host) -i hydra.accounts.example.com
    acl host_kratos req.hdr(host) -i kratos.accounts.example.com
    acl host_forseti req.hdr(host) -i accounts.example.com

    use_backend be_hydra  if host_hydra
    use_backend be_kratos if host_kratos
    use_backend be_forseti if host_forseti

backend be_forseti
    server forseti 127.0.0.1:3000 check

# DO NOT add backends for Hydra :4445 or Kratos :4434 here.
# Admin APIs must stay on loopback. If you need remote access,
# expose them via a separate internal listener with its own auth.
backend be_hydra
    server hydra  127.0.0.1:4444 check

backend be_kratos
    server kratos 127.0.0.1:4433 check
```

### Shape (3) — port-based (illustrative only — do not ship)

```haproxy
frontend fe_forseti
    bind *:443 ssl crt /etc/haproxy/certs/accounts.example.com.pem
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]
    http-request set-header X-Real-IP         %[src]
    default_backend be_forseti

frontend fe_hydra
    bind *:8443 ssl crt /etc/haproxy/certs/accounts.example.com.pem
    # Hydra issuer must include :8443 — every RP integration sees it.
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]:8443
    http-request set-header X-Real-IP         %[src]
    default_backend be_hydra

frontend fe_kratos
    bind *:9443 ssl crt /etc/haproxy/certs/accounts.example.com.pem
    http-request del-header X-Forwarded-For
    http-request del-header X-Forwarded-Proto
    http-request del-header X-Forwarded-Host
    http-request set-header X-Forwarded-Proto https
    http-request set-header X-Forwarded-Host  %[req.hdr(host)]:9443
    http-request set-header X-Real-IP         %[src]
    default_backend be_kratos

# DO NOT add backends for Hydra :4445 or Kratos :4434 here.
# Admin APIs must stay on loopback. If you need remote access,
# expose them via a separate internal listener with its own auth.
backend be_forseti
    server forseti 127.0.0.1:3000 check
backend be_hydra
    server hydra  127.0.0.1:4444 check
backend be_kratos
    server kratos 127.0.0.1:4433 check
```

---

## Forseti's internal listener

Separate from the public frontends above, Forseti binds a second HTTP listener on `[internal].bind` (no default — operator-configured). It exists for one purpose today: receiving Kratos's webhook events at `POST /internal/audit/kratos`, authenticated with a shared bearer (`[audit].webhook_token`).

Bind it to loopback when Kratos and Forseti share a host, or to a private interface (or pod-network address inside a container) when they don't. **Never expose this on a public interface, and never add it to the haproxy frontends above** — the public proxy must not route to it. CSRF middleware is not applied on this listener; the bearer token is the trust boundary.

`/healthz` and `/readyz` stay on the public listener, so load balancers don't need to know about the second port.

---

## Recommendation

Ship Shape (1). It's the only one that:

- Keeps everything same-origin (no CORS to configure, no cookie-domain widening)
- Uses host-only cookies (tightest scope)
- Survives corporate networks (only 443 exposed)
- Lets you serve `https://accounts.example.com` as the single URL users see — `oauth2.accounts.example.com` leaks implementation detail
- Is explicitly endorsed in Hydra's production guide

Migrate to (2) only when there's a concrete need — different rate-limit tiers per service, independent WAF rules, splitting Hydra to its own cluster. Until then the extra DNS records and CORS config buy you nothing. Skip (3) entirely.

---

## Content-Security-Policy

Forseti does not set a `Content-Security-Policy` itself. If you add one at the
proxy, it must allow Forseti's inline `<head>` scripts: a pre-paint theme
resolver (reads the saved light/dark/system choice and sets the `dark` class
before first paint) and a couple of input-handling helpers. Either permit
inline scripts (`script-src 'unsafe-inline'`) or, if you need a strict policy,
inject a per-request nonce. The pre-paint theme script is the one inline script
that cannot be moved to an external file without reintroducing a flash of the
wrong theme on load.
