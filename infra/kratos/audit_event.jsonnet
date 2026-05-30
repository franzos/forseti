// Normalised audit payload for the portal's /internal/audit/kratos
// receiver. Shared by every flow hook; per-hook `action` is selected
// via the `?action=...` query parameter on the webhook URL, so the
// jsonnet doesn't have to branch on hook identity.
//
// `ctx` is whatever Kratos passes to the hook. Fields we care about:
//
//   ctx.identity       — the freshly-completed identity (registration,
//                        settings, recovery, verification, login)
//   ctx.identity.id    — UUID
//   ctx.identity.traits — typed traits object (we read .email)
//   ctx.flow.id        — flow UUID for correlation
//
// All field accesses are defensive — older Kratos versions sometimes
// omit `flow` on certain hooks.

function(ctx) {
  actor_id:
    if std.objectHas(ctx, 'identity') && std.objectHas(ctx.identity, 'id')
    then ctx.identity.id
    else null,
  actor_email:
    if std.objectHas(ctx, 'identity')
       && std.objectHas(ctx.identity, 'traits')
       && std.objectHas(ctx.identity.traits, 'email')
    then ctx.identity.traits.email
    else null,
  target_id:
    if std.objectHas(ctx, 'identity') && std.objectHas(ctx.identity, 'id')
    then ctx.identity.id
    else null,
  // Surfaced to the receiver as a freshness lower bound — see
  // `src/audit/kratos_webhook.rs`. Kratos's `web_hook` action can't
  // compute an HMAC over the body, so the receiver leans on this
  // RFC3339 timestamp (5-min window) plus a per-`flow_id` dedupe to
  // neutralise replay of intercepted bearer + body pairs.
  issued_at:
    if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'issued_at')
    then ctx.flow.issued_at
    else null,
  metadata: {
    source: 'kratos',
    flow_id:
      if std.objectHas(ctx, 'flow') && std.objectHas(ctx.flow, 'id')
      then ctx.flow.id
      else null,
  },
}
