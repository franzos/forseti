// Mailcrab API client. Mailcrab UI + JSON API live on the same port (4436).
// `GET /api/messages` returns metadata only; `GET /api/message/{id}` returns
// the full body. See `tests/integration/common.rs::read_mailcrab_inbox` for
// the shape we're mirroring.
import type { APIRequestContext } from '@playwright/test';

const MAILCRAB_BASE = process.env.MAILCRAB_BASE || 'http://host.containers.internal:4436';

interface MailMeta {
  id: string;
  to: Array<{ email: string }>;
  subject: string;
  date: string;
}

interface MailBody {
  text?: string;
  html?: string;
}

export interface MailItem {
  id: string;
  subject: string;
  body: string;
  date: string;
}

async function fetchInbox(request: APIRequestContext, toEmail: string): Promise<MailItem[]> {
  const res = await request.get(`${MAILCRAB_BASE}/api/messages`);
  if (!res.ok()) return [];
  const list = (await res.json()) as MailMeta[];
  const needle = toEmail.toLowerCase();
  const matches = list.filter((m) =>
    (m.to ?? []).some((t) => (t.email ?? '').toLowerCase().includes(needle)),
  );
  const out: MailItem[] = [];
  for (const m of matches) {
    const bodyRes = await request.get(`${MAILCRAB_BASE}/api/message/${m.id}`);
    let body = '';
    if (bodyRes.ok()) {
      const j = (await bodyRes.json()) as MailBody;
      body = j.text ?? j.html ?? '';
    }
    out.push({ id: m.id, subject: m.subject, body, date: m.date });
  }
  // Newest first.
  out.sort((a, b) => (b.date > a.date ? 1 : -1));
  return out;
}

/**
 * Poll Mailcrab for an email matching `toEmail` whose subject contains
 * `subjectContains`. Resolves to the first match within `timeoutMs`,
 * throws on timeout. Polls every 500 ms.
 */
export async function waitForMail(
  request: APIRequestContext,
  toEmail: string,
  subjectContains: string,
  timeoutMs = 15_000,
): Promise<MailItem> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const inbox = await fetchInbox(request, toEmail);
    const hit = inbox.find((m) => m.subject.includes(subjectContains));
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(
    `Mailcrab: no mail to ${toEmail} with subject containing "${subjectContains}" within ${timeoutMs}ms`,
  );
}

/** Extract the first 6-digit code from an email body. */
export function extractSixDigitCode(body: string): string {
  const m = body.match(/\b(\d{6})\b/);
  if (!m) throw new Error(`no 6-digit code in body: ${body.slice(0, 200)}`);
  return m[1];
}
