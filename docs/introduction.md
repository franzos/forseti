# Forseti

Forseti is a self-service UI and OAuth2 login / consent / logout bridge. It runs on [Ory Kratos](https://www.ory.sh/kratos/) or on its own native identity backend, with [Ory Hydra](https://www.ory.sh/hydra/) for OAuth2 and OIDC either way. It gives your identity stack the pages it's missing: login, registration, account recovery, MFA, consent, and admin tooling, all server-rendered in Rust.

These docs are split by what you're here to do:

- [User guide](./user-guide.md) — for people using an account: signing in, registering, recovery, MFA, and account settings.
- [Operator guide](./operator-guide.md) — deployment topology, shared configuration, Hydra, secrets, backups.
- [Identity: Kratos](./operator-guide-kratos.md) — what only the Kratos build needs: `kratos.yml`, 2FA enforcement, the `forseti-config` tooling.
- [Identity: native](./operator-guide-native.md) — the build without Kratos: building it, sessions, throttles, upstream providers.
- [Reverse proxy](./operator-guide-proxy.md) — proxy topology, cookies, CSRF, CORS.
- [Integration guide](./integration-guide.md) — consuming Forseti as an OIDC provider.
- [Commercial features](./commercial/index.md) — organizations, enterprise SAML SSO, and observability.

The source lives on [GitHub](https://github.com/franzos/forseti). Forseti is AGPL-3.0 with a commercial option.
