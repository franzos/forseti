---
name: ory-up
description: Bring up the Kratos + Hydra playground stack under infra/, register an OAuth2 client, and walk the user through a full login + token exchange. Use when the user says "set up the stack", "start ory", "give me a login URL", or otherwise wants to try the playground end-to-end.
---

# ory-up

Goal: get a user from "fresh clone" to "valid id_token in hand" with as little friction as possible.

## What this stack is

The compose file lives at `infra/docker-compose.yml`. Services:

- `postgres` — shared DB (two databases via `infra/init-db.sh`)
- `kratos` + `kratos-migrate` — identity service (login/registration/verification)
- `kratos-ui` — Ory's reference self-service UI (used as a fallback / sanity check until the Forseti at `:3000` covers all flows)
- `hydra` + `hydra-migrate` — OAuth2/OIDC server
- `mailslurper` — catches verification emails (compose service name kept for Kratos's SMTP URI; actually runs Mailcrab)

The login/consent bridge is now provided by the Rust `forseti` app in this repo root — `cargo run` from the repo root starts it at `http://127.0.0.1:3000`. Hydra's `hydra.yml` points `login_url`, `consent_url`, and `logout_url` at that port. There is no Go bridge any more.

## Steps

### 1. Pick a container runtime

```bash
command -v docker >/dev/null && docker compose version >/dev/null 2>&1 && echo docker
command -v podman-compose >/dev/null && echo podman-compose
```

### 2. Bring up the playground

From the repo root:

```bash
docker compose -f infra/docker-compose.yml up -d --build
# or:
podman-compose -f infra/docker-compose.yml up -d --build
```

First run pulls ~1GB of images. ~1-3 minutes.

### 3. Start Forseti

```bash
cp config.example.toml config.toml   # one-time
make dev                              # cargo run + tailwind --watch
```

Forseti listens on `http://127.0.0.1:3000`.

### 4. Verify health

All containers should be running. The two `*-migrate` services exit successfully (status `Exited (0)`) — that's normal.

```bash
podman ps --filter name=infra_ --format "table {{.Names}}\t{{.Status}}"
curl -s http://127.0.0.1:3000/healthz   # → "ok"
```

If `kratos` or `hydra` is restarting, check logs — usually a postgres race on first boot. `podman start` the migrate container, then the service.

### 5. Register an OAuth2 client

State must be ≥8 chars; capture the full JSON response for `client_id` and `client_secret`:

```bash
podman exec infra_hydra_1 hydra create client \
  --endpoint http://127.0.0.1:4445 \
  --name "explore-client" \
  --grant-type authorization_code,refresh_token \
  --response-type code,id_token \
  --scope openid,offline,email \
  --redirect-uri http://127.0.0.1:5555/callback \
  --token-endpoint-auth-method client_secret_post \
  --format json
```

(Replace `podman exec` with `docker compose -f infra/docker-compose.yml exec hydra` for docker.)

### 6. Give the user a URL

```
http://localhost:4444/oauth2/auth?client_id=<ID>&response_type=code&scope=openid+offline+email&redirect_uri=http://127.0.0.1:5555/callback&state=explore-xyz
```

Use `localhost`, not `127.0.0.1`, for the Hydra origin — `hydra.yml` sets `urls.self.issuer: http://localhost:4444`, so Hydra redirects the post-login callback back to `localhost:4444`. If you start the flow on `127.0.0.1:4444`, the browser won't send the CSRF cookie (different origin) and the consent step fails with `request_forbidden: No CSRF value available in the session cookie`. The `redirect_uri` can stay on `127.0.0.1:5555` since the client was registered against that exact value.

Tell the user:
1. Paste URL in browser → Forseti `/login` appears at `:3000` (or kratos-ui at `:4455` until the M1 flows land)
2. **Sign up** with any email (Mailcrab catches mail at http://127.0.0.1:4436)
3. Verify email by clicking the link in Mailcrab, or use the code
4. Browser redirects to `http://127.0.0.1:5555/callback?code=...` → **connection refused is expected** — grab the `code` param from the URL bar
5. Exchange it:

```bash
curl -s -X POST http://localhost:4444/oauth2/token \
  -d grant_type=authorization_code \
  -d client_id=<ID> \
  -d client_secret=<SECRET> \
  -d redirect_uri=http://127.0.0.1:5555/callback \
  -d code=<CODE> | python3 -m json.tool
```

Decode the `id_token` (jwt.io). Its `sub` matches the Kratos identity UUID — that's the whole point.

## Common breakage

### SMTP timeout / no verification email

The compose service is named `mailslurper` for historical reasons but actually runs Mailcrab (`marlonb/mailcrab`) on plaintext SMTP at :1025. `infra/kratos/kratos.yml` uses:

```yaml
courier:
  smtp:
    connection_uri: smtp://mailslurper:1025/?disable_starttls=true
```

If you see `i/o timeout` in `podman logs infra_kratos_1`, check that the `mailslurper` service is up — `podman ps | grep mailslurper`.

### `state must be at least 8 characters`

Hydra enforces this. Use `state=explore-xyz` not `state=test`.

### Forseti won't compile / fonts look wrong

The standalone Tailwind binary needs glibc + libgcc_s. On GUIX the `Makefile` wraps it in `guix shell` automatically. If `make css` fails, run `./.bin/tailwindcss --help` once outside `make` to see the actual error.

### Bridge can't restart because migrate is stopped

`podman-compose` doesn't fully honor `depends_on: condition: service_completed_successfully` on restart. To restart kratos/hydra cleanly:

```bash
podman start infra_kratos-migrate_1   # will exit immediately, that's fine
podman start infra_kratos_1
```

## Endpoints cheatsheet

| Service             | URL                                                  |
|---------------------|------------------------------------------------------|
| Forseti (Rust)      | http://127.0.0.1:3000                                |
| Kratos public API   | http://127.0.0.1:4433                                |
| Kratos admin API    | http://127.0.0.1:4434                                |
| Kratos UI (ref)     | http://127.0.0.1:4455                                |
| Hydra OAuth2        | http://127.0.0.1:4444                                |
| Hydra admin API     | http://127.0.0.1:4445                                |
| Mailcrab UI         | http://127.0.0.1:4436                                |
| OIDC discovery      | http://127.0.0.1:4444/.well-known/openid-configuration |

## Teardown

```bash
podman-compose -f infra/docker-compose.yml down -v   # -v wipes postgres volume
```

## What to suggest after success

Once the user has a valid `id_token` in hand, offer:

- Continuing M1 implementation in `forseti` (real Kratos flow rendering)
- Adding a social provider (Google/GitHub) to Kratos
- MFA via TOTP

Don't do these unsolicited — ask which thread interests them.
