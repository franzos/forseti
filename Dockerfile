# syntax=docker/dockerfile:1

# --- CSS stage: build static/styles.css with the Tailwind v4 standalone CLI.
FROM debian:trixie-slim AS css
WORKDIR /src
ARG TAILWIND_VERSION=v4.1.16
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /usr/local/bin/tailwindcss \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64" \
    && chmod +x /usr/local/bin/tailwindcss
COPY assets ./assets
COPY templates ./templates
RUN tailwindcss -i assets/input.css -o /styles.css --minify

# --- Rust build stage.
# Debian (glibc), not alpine/musl: pq-sys links dynamically against libpq and
# libsqlite3-sys compiles bundled C, both of which are painful to static-link
# under musl. reqwest/lettre use rustls, so no OpenSSL is needed.
FROM rust:1-trixie AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY migrations ./migrations
# `include_dir!` captures static/ at compile time, so the freshly built CSS
# must be in place before `cargo build`.
COPY static ./static
COPY --from=css /styles.css ./static/styles.css
RUN cargo build --release --locked

# --- Runtime image.
FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 forseti
WORKDIR /app
COPY --from=build /src/target/release/forseti /usr/local/bin/forseti
USER forseti
# Forseti reads ./config.toml (override with FORSETI_CONFIG_PATH); static
# assets are compiled into the binary.
EXPOSE 3000
ENTRYPOINT ["forseti"]
