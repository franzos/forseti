import { defineConfig } from '@playwright/test';

// Playground stack lives on the host. From inside the Playwright container,
// `host.containers.internal` (added via `--add-host …:host-gateway`)
// resolves to the host's gateway IP. The OAuth scenarios MUST hit Hydra at
// `host.containers.internal:4444` because Hydra's `issuer` is set there and
// the CSRF cookie scopes on the issuer's hostname (see
// `.claude/skills/e2e-review/SKILL.md`, "Known traps").
export default defineConfig({
  // Mirror the Rust suite's `--test-threads=1`: the playground (Kratos +
  // Hydra + portal DB) is shared state.
  workers: 1,
  fullyParallel: false,
  // Browsers are flake-prone; one retry catches transient hiccups without
  // hiding real regressions.
  retries: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: process.env.BASE_URL || 'http://host.containers.internal:3000',
    // Trace on first retry: failing tests come with a viewable trace, green
    // tests pay nothing.
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 15_000,
    navigationTimeout: 30_000,
  },
  // The OAuth scenarios point `redirect_uri` at localhost:9876 and read the
  // `code` off the outgoing request. Left dead, that navigation ends in
  // `chrome-error://chromewebdata/`, which commits asynchronously and races
  // whatever portal navigation the spec does next — the flake the specs used
  // to absorb with `retries: 1`. Answering the callback keeps
  // `waitForRequest` working and leaves the browser on a real document.
  webServer: {
    command:
      "node -e \"require('http').createServer((_,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end('<!doctype html><title>callback</title>ok')}).listen(9876)\"",
    port: 9876,
    reuseExistingServer: true,
  },
  // Three buckets keyed on the portal's license state. The Makefile picks
  // which project to run via `--project=<name>` and gates the non-default
  // buckets on a sqlite pre-check (see `make e2e-expired` / `make e2e-licensed`).
  projects: [
    { name: 'unlicensed', testDir: './tests/unlicensed' },
    { name: 'expired', testDir: './tests/expired' },
    { name: 'licensed', testDir: './tests/licensed' },
  ],
});
