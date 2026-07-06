# Observability (Prometheus metrics)

> Commercial feature: requires a license that includes the `observability` capability. See [Commercial features](./index.md) for the licensing model.

A Prometheus-format `/metrics` endpoint, served on the internal listener only. It's meant for a stock Prometheus, Grafana Agent, or OTel Collector Prometheus receiver to scrape as-is; no exporter or bridge to run yourself.

## Prerequisites

- A commercial license that includes the `observability` feature (activate at `/admin/license`).
- The internal listener configured (`[internal].bind` in `config.toml`): `/metrics` is never served on the public listener.
- A scrape token (see below).

## Enabling it

1. Activate a license carrying `observability` at `/admin/license`.
2. Set a scrape token in `config.toml`:

```toml
[metrics]
scrape_token = "change-me"
```

`FORSETI_METRICS__SCRAPE_TOKEN` overrides it via environment, same as any other Figment-backed setting. Leave the table out (or the token unset) and `/metrics` stays disabled, 404, even on a licensed deployment.

See `config.example.toml` for the `[internal]` and `[metrics]` entries side by side.

## What it exposes

| Metric | Type | Meaning |
|---|---|---|
| `http_requests_total{method,path,status}` | counter | Request count across all listeners (public, internal, admin), labeled by method, matched route template, and status code. |
| `http_request_duration_seconds` | histogram | Request latency, same labels as above. |
| `forseti_audit_write_failures_total` | counter | Audit log write failures, bridged from the in-process audit writer. |
| `forseti_last_kratos_webhook_timestamp_seconds` | gauge | Unix timestamp of the last Kratos webhook Forseti processed. |

Labels are bounded by design: `method` is drawn from an allowlist (anything else collapses to `OTHER`), `path` is the matched route template (e.g. `/orgs/:slug`, never the raw URL), and `status` is the numeric HTTP status. There are no per-tenant, per-org, or per-identity labels, so cardinality stays fixed regardless of how many orgs or users you run.

## Scraping it

Point a standard Prometheus at the internal bind with the bearer token:

```yaml
scrape_configs:
  - job_name: forseti
    scheme: http
    static_configs:
      - targets: ["forseti-internal:8081"]
    authorization:
      type: Bearer
      credentials: "change-me"
```

Swap the target for wherever `[internal].bind` actually listens in your deployment, and the credentials for the configured `scrape_token`. No other Prometheus-side config is needed; the endpoint is plain text exposition format (`text/plain; version=0.0.4`).

## Access control and exposure

The endpoint fails closed at every gate: only a licensed feature AND a matching token together return data.

| Condition | Response |
|---|---|
| Feature not Active or Grace (unlicensed, wrong license, past grace) | 404 |
| No `scrape_token` configured | 404 |
| Token configured but request has no/wrong `Authorization: Bearer` | 401 |
| Feature licensed AND token matches | 200, metrics body |

The two 404 cases are deliberate: an unlicensed or untokened deployment doesn't reveal that the feature exists at all. The bearer comparison is constant-time (SHA-256 then a `subtle` equality check), so there's no length or timing oracle on the token.

The token is defence-in-depth, not the only control. `/metrics` is bound to the internal listener, which is meant to stay off the public network path, but in some container setups the internal bind can still be reachable from other containers or the host network. Keep it network-restricted (firewall, container network policy, or a proxy that only your scraper can reach) rather than relying on the token alone.

## Grace period

Metrics are read-only telemetry, so during the fixed 30-day grace window after license expiry, `/metrics` keeps serving like any other read path. Past grace, it 404s the same as an unlicensed deployment.

## Related

- [Operator guide → Metrics](../operator-guide.md#metrics): where this fits alongside Hydra's and Kratos's own admin-port metrics.
- [Commercial features](./index.md): the licensing model, grace period, and what else a license unlocks.
