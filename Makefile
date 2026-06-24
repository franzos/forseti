# Forseti — local dev tasks
#
# The standalone Tailwind CLI is dynamically linked against glibc + libgcc_s,
# neither of which are on the FHS path on GUIX. We wrap each invocation in
# `guix shell` to provide those shared objects via LD_LIBRARY_PATH.

TAILWIND      := ./.bin/tailwindcss
TAILWIND_IN   := assets/input.css
TAILWIND_OUT  := static/styles.css

# GUIX wrapper for the Tailwind binary. No-op outside GUIX.
ifeq ($(shell command -v guix 2>/dev/null),)
TAILWIND_RUN  := $(TAILWIND)
else
TAILWIND_RUN  := guix shell glibc gcc-toolchain -- bash -c 'export LD_LIBRARY_PATH=$$LIBRARY_PATH:$$LD_LIBRARY_PATH; $(TAILWIND) $$0 "$$@"' --
endif

.PHONY: css css-watch dev build check clean run test-integration \
	stack-up stack-up-saml stack-wait stack-down stack-reset stack-logs seed-admin \
	e2e e2e-expired e2e-licensed e2e-trace license-fixtures \
	test-linux-host linux-test-seed linux-test-unseed linux-test-build

# Compose engine. Defaults to podman-compose for local GUIX dev; CI overrides
# with `COMPOSE="docker compose"`.
COMPOSE      ?= podman-compose
COMPOSE_FILE := infra/docker-compose.yml

# One readiness probe per Ory service is enough to know the stack is live.
# Kratos and Hydra have no compose healthcheck (only the Postgres services do),
# so `up -d` returns before they serve — poll these before running anything.
ORY_READY_URLS := http://127.0.0.1:4433/health/ready http://127.0.0.1:4445/health/ready

# seed-admin.sh needs curl + jq. On GUIX neither is on the default PATH, so
# wrap as we do Tailwind; no-op (bare invocation) elsewhere, e.g. in CI.
ifeq ($(shell command -v guix 2>/dev/null),)
SEED_RUN := bash infra/seed-admin.sh
else
SEED_RUN := guix shell bash curl jq -- bash infra/seed-admin.sh
endif

css: ## Build static/styles.css once (minified)
	$(TAILWIND_RUN) -i $(TAILWIND_IN) -o $(TAILWIND_OUT) --minify

css-watch: ## Rebuild styles.css on template changes
	$(TAILWIND_RUN) -i $(TAILWIND_IN) -o $(TAILWIND_OUT) --watch

dev: ## Run cargo + tailwind --watch in parallel
	@$(MAKE) -j2 css-watch _dev-run

_dev-run:
	cargo run

build: css ## Release build (CSS first, then cargo)
	cargo build --release --locked

check: ## cargo check + clippy
	cargo check
	cargo clippy --all-targets -- -D warnings

clean:
	cargo clean
	rm -f $(TAILWIND_OUT)

run: ## Run the portal (debug) against the local playground stack
	cargo run

test-integration: ## Rust integration suite (stack + Forseti must already be running)
	cargo test --test integration -- --test-threads=1

# --- Playground stack lifecycle --------------------------------------------
#
# Brings the Ory playground (Kratos, Hydra, Mailcrab, Postgres) up and down.
# Forseti itself runs on the host (`make run`), not in compose. `stack-down`
# wipes ALL state — volumes + the sqlite DB — so every bring-up is a clean
# slate. That clean-slate-per-run is what keeps CI deterministic; the suites
# lean on unique-per-run emails rather than between-test cleanup.

stack-up: ## Bring the playground up and block until Kratos + Hydra are ready
	$(COMPOSE) $(COMPOSE_PROFILE_FLAGS) -f $(COMPOSE_FILE) up -d
	@$(MAKE) stack-wait

# podman-compose 1.5.0 ignores the COMPOSE_PROFILES env var, so pass the
# profile as a flag — works for both podman-compose and docker compose.
stack-up-saml: ## stack-up plus the Jackson + mock-saml SAML bridge
	$(MAKE) stack-up COMPOSE_PROFILE_FLAGS="--profile saml"

stack-wait: ## Block until Kratos + Hydra report ready (90s timeout per service)
	@for url in $(ORY_READY_URLS); do \
		printf 'waiting for %s ' "$$url"; \
		deadline=$$(($$(date +%s) + 90)); \
		until curl -fsS "$$url" >/dev/null 2>&1; do \
			if [ $$(date +%s) -ge $$deadline ]; then echo "TIMEOUT"; exit 1; fi; \
			printf '.'; sleep 2; \
		done; \
		echo "ready"; \
	done

stack-down: ## Tear the playground down, wiping volumes + the sqlite DB
	$(COMPOSE) -f $(COMPOSE_FILE) down -v
	rm -f $(FORSETI_DB)

stack-reset: stack-down stack-up ## Full clean slate: wipe everything, bring back up

stack-logs: ## Follow playground container logs
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=100

seed-admin: ## Seed a deterministic admin (password + planted TOTP) into the playground Kratos
	COMPOSE="$(COMPOSE)" COMPOSE_FILE="$(COMPOSE_FILE)" $(SEED_RUN)

# --- Playwright e2e --------------------------------------------------------
#
# Runs `tests/e2e/` inside Microsoft's Playwright Docker image. Same wrapper
# pattern as Tailwind: keeps the browser binaries off the host (GUIX-friendly)
# without forcing every dev to install Node.
#
# Requirements: the playground stack + Forseti must already be running on the
# host (this target only runs the test suite — it does NOT bring up the
# stack). A named podman volume caches `node_modules/` between runs so the
# slow `npm i` (~30s) only happens once.

PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v1.60.0-noble
PLAYWRIGHT_VOL   ?= forseti-e2e-node-modules

# Forseti-owned sqlite (default backend). The license pre-checks for
# `e2e-expired` / `e2e-licensed` read the singleton `forseti_license` row
# directly — operator activates the matching blob via `/admin/license`
# before invoking the target.
FORSETI_DB ?= forseti.db

# Issuer lives in a sibling repo. Override with `LICENSE_ISSUER_DIR=...`
# if you keep it elsewhere.
LICENSE_ISSUER_DIR ?= $(HOME)/git/ory-frontend-license

# `--network host` so the container shares the host's loopback +
# /etc/hosts. This matters for two reasons:
#  1. Forseti binds to 0.0.0.0:3000 on the host; from inside a
#     bridge-networked container, `host.containers.internal` resolves
#     to the gateway IP — but the Playwright base image ALSO ships
#     `/etc/hosts` entries that hard-code `127.0.0.1 host.containers.internal`,
#     and Chromium happens to pick the wrong one. `--network host`
#     sidesteps the duplicate entirely.
#  2. Hydra's issuer is `http://host.containers.internal:4444` (see
#     `infra/hydra/hydra.yml`); with `--network host` the host's
#     `/etc/hosts` (where `host.containers.internal -> 127.0.0.1`)
#     applies and the browser's OAuth dance hits the same hostname
#     Hydra issued the CSRF cookie under.
define PLAYWRIGHT_RUN
	podman run --rm -t \
		--network host \
		-v "$(CURDIR)/tests/e2e:/work" \
		-v "$(PLAYWRIGHT_VOL):/work/node_modules" \
		-w /work \
		-e BASE_URL=http://localhost:3000 \
		-e MAILCRAB_BASE=http://localhost:4436 \
		-e FORSETI_ADMIN_TEST_EMAIL \
		-e FORSETI_ADMIN_TEST_PASSWORD \
		-e FORSETI_ADMIN_TEST_TOTP_SECRET \
		$(PLAYWRIGHT_IMAGE) \
		bash -c "npm ci --no-audit --no-fund && npx playwright test --project=$(1)"
endef

define FORSETI_HEALTH_CHECK
	@if ! curl -fsS http://localhost:3000/healthz >/dev/null 2>&1; then \
		echo "ERROR: Forseti not reachable at http://localhost:3000/healthz."; \
		echo "Bring the stack up first:"; \
		echo "  podman-compose -f infra/docker-compose.yml up -d"; \
		echo "  ./target/debug/forseti &"; \
		exit 1; \
	fi
endef

e2e: ## Run unlicensed-bucket Playwright e2e against the locally running stack
	$(call FORSETI_HEALTH_CHECK)
	$(call PLAYWRIGHT_RUN,unlicensed)

# License-state pre-checks for the two gated buckets. `forseti_license` is a
# singleton row written by `/admin/license`; `expires_at` is an RFC 3339
# string (or NULL = lifetime). RFC 3339 sorts lexicographically so plain
# string comparison against `date -u +%Y-%m-%dT%H:%M:%S+00:00` works without
# pulling in GNU-date assumptions.
e2e-expired: ## Run expired-bucket Playwright e2e (requires expired license activated)
	$(call FORSETI_HEALTH_CHECK)
	@exp=$$(sqlite3 $(FORSETI_DB) "SELECT COALESCE(expires_at,'') FROM forseti_license LIMIT 1" 2>/dev/null); \
	now=$$(date -u +%Y-%m-%dT%H:%M:%S+00:00); \
	if [ -z "$$exp" ]; then \
		echo "ERROR: no license row in $(FORSETI_DB) (or no expires_at)."; \
		echo "Activate tests/fixtures/license/expired.blob via /admin/license first."; \
		echo "Mint it with: make license-fixtures"; \
		exit 1; \
	fi; \
	if [ "$$exp" \> "$$now" ]; then \
		echo "ERROR: license in $(FORSETI_DB) is not expired (expires_at=$$exp, now=$$now)."; \
		echo "Activate tests/fixtures/license/expired.blob via /admin/license first."; \
		exit 1; \
	fi
	$(call PLAYWRIGHT_RUN,expired)

e2e-licensed: ## Run licensed-bucket Playwright e2e (requires active license activated)
	$(call FORSETI_HEALTH_CHECK)
	@row=$$(sqlite3 $(FORSETI_DB) "SELECT COALESCE(expires_at,'lifetime') FROM forseti_license LIMIT 1" 2>/dev/null); \
	now=$$(date -u +%Y-%m-%dT%H:%M:%S+00:00); \
	if [ -z "$$row" ]; then \
		echo "ERROR: no license row in $(FORSETI_DB)."; \
		echo "Activate tests/fixtures/license/active.blob via /admin/license first."; \
		echo "Mint it with: make license-fixtures"; \
		exit 1; \
	fi; \
	if [ "$$row" != "lifetime" ] && [ ! "$$row" \> "$$now" ]; then \
		echo "ERROR: license in $(FORSETI_DB) is expired (expires_at=$$row, now=$$now)."; \
		echo "Activate tests/fixtures/license/active.blob via /admin/license first."; \
		exit 1; \
	fi
	$(call PLAYWRIGHT_RUN,licensed)

# Mint the two test blobs by shelling out to the issuer CLI. First run
# compiles the issuer (release profile, takes a moment); subsequent runs
# are instant. The blobs are sensitive — anyone with one can paste it into
# any Forseti sharing the same pubkey — so `tests/fixtures/license/` is
# .gitignored.
license-fixtures: ## Mint tests/fixtures/license/{active,expired}.blob via the issuer CLI
	@mkdir -p tests/fixtures/license
	cd $(LICENSE_ISSUER_DIR) && cargo run --release --quiet -- \
		issue --tier business --feature orgs --feature saml \
		--customer "E2E Test" --email "e2e@example.com" \
		> $(CURDIR)/tests/fixtures/license/active.blob
	cd $(LICENSE_ISSUER_DIR) && cargo run --release --quiet -- \
		issue --tier business --feature orgs --feature saml \
		--customer "E2E Test" --email "e2e@example.com" \
		--expires 2024-01-01 \
		> $(CURDIR)/tests/fixtures/license/expired.blob
	@echo "Wrote tests/fixtures/license/{active,expired}.blob"

e2e-trace: ## Open the Playwright trace viewer for the most recent run
	podman run --rm -it \
		--network host \
		-v "$(CURDIR)/tests/e2e:/work" \
		-v "$(PLAYWRIGHT_VOL):/work/node_modules" \
		-w /work \
		$(PLAYWRIGHT_IMAGE) \
		bash -c "npx playwright show-report --host 0.0.0.0"

# ---------------------------------------------------------------------------
# Real-Linux NSS/PAM/sshd harness (forseti-unix client)
#
# A Debian container with the forseti-unix client installed talks to the
# host's Forseti internal resolver and asserts the whole NSS/PAM/ssh chain
# works (+ fail-open when the daemon is down). This is the foreign-distro /
# M4 path; Guix-System wiring is a separate marionette test (future).
#
# PREREQ (same convention as `make e2e`): the playground + Forseti must
# ALREADY be running on the host, with the internal resolver bound to
# 0.0.0.0:8081 (config.toml `[internal] bind`). Bring them up with:
#   podman-compose -f infra/docker-compose.yml up -d
#   guix shell -m manifest.scm -- cargo run        # serves :3000 + :8081
#
# `make` isn't on PATH outside a guix shell here, so invoke as:
#   guix shell make -- make test-linux-host
# ---------------------------------------------------------------------------
LINUX_TEST_IMAGE   ?= forseti-linux-test
LINUX_TEST_CONT    ?= forseti-linux-test-run
LINUX_TEST_ENV     := infra/linux-test/.seed.env
# host-gateway lets the container reach the host's 0.0.0.0:8081 resolver.
LINUX_TEST_SERVER  ?= http://host.containers.internal:8081

linux-test-build: ## Build the Debian NSS/PAM/sshd test image (context = repo root)
	podman build -f infra/linux-test/Containerfile -t $(LINUX_TEST_IMAGE) .

linux-test-seed: ## Seed host enrollment + posix account + ssh key into forseti.db
	bash infra/linux-test/seed.sh $(FORSETI_DB)

linux-test-unseed: ## Remove the seeded rows + ephemeral keys
	bash infra/linux-test/unseed.sh $(FORSETI_DB)

test-linux-host: ## Build + run the containerized NSS/PAM/ssh harness against the running host Forseti
	$(call FORSETI_HEALTH_CHECK)
	@echo "==> seeding forseti.db"
	@bash infra/linux-test/seed.sh $(FORSETI_DB)
	@echo "==> building $(LINUX_TEST_IMAGE)"
	@podman build -f infra/linux-test/Containerfile -t $(LINUX_TEST_IMAGE) .
	@echo "==> running harness container"
	@set -a; . $(LINUX_TEST_ENV); set +a; \
	rc=0; \
	podman run --rm --name $(LINUX_TEST_CONT) \
		--add-host=host.containers.internal:host-gateway \
		-v "$$PRIVKEY_PATH:/test/id_key:ro" \
		-e SERVER_URL="$(LINUX_TEST_SERVER)" \
		-e HOST_ID="$$HOST_ID" \
		-e HOST_SECRET="$$HOST_SECRET" \
		-e TEST_USER="$$TEST_USER" \
		-e TEST_UID="$$TEST_UID" \
		-e TEST_GID="$$TEST_GID" \
		-e TEST_HOME="$$TEST_HOME" \
		-e TEST_SHELL="$$TEST_SHELL" \
		$(LINUX_TEST_IMAGE) || rc=$$?; \
	echo "==> harness exited rc=$$rc; unseeding"; \
	bash infra/linux-test/unseed.sh $(FORSETI_DB); \
	exit $$rc
