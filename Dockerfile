# --- CSS stage: build static/styles.css with the Tailwind v4 standalone CLI.
FROM alpine:3.20 AS css
WORKDIR /src
RUN apk add --no-cache curl libgcc libstdc++
ARG TAILWIND_VERSION=v4.3.0
RUN curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/${TAILWIND_VERSION}/tailwindcss-linux-x64-musl" \
    && chmod +x /usr/local/bin/tailwindcss
COPY assets ./assets
COPY templates ./templates
RUN tailwindcss -i assets/input.css -o /styles.css --minify

# --- Rust build stage.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev pkgconfig openssl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY templates ./templates
RUN cargo build --release --locked

# --- Runtime image.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /src/target/release/forseti /forseti
COPY templates /templates
COPY --from=css /styles.css /static/styles.css
EXPOSE 3000
ENTRYPOINT ["/forseti"]
