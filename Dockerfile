# syntax=docker/dockerfile:1
# The StatusTick agent with Chromium and the pinned Playwright sandbox. No port is exposed.
#   docker build -t statustick-agent:dev .
# The static binary alone, per platform (dist/<os>_<arch>/statustick-agent):
#   docker buildx build --target binary-export --platform linux/amd64,linux/arm64 --output type=local,dest=dist .
FROM --platform=$BUILDPLATFORM rust:1-alpine AS binary
ARG TARGETARCH
RUN apk add --no-cache musl-dev perl make linux-headers zig \
    && cargo install --locked cargo-zigbuild \
    && case "$TARGETARCH" in amd64) echo x86_64-unknown-linux-musl ;; arm64) echo aarch64-unknown-linux-musl ;; *) exit 1 ;; esac > /target \
    && rustup target add "$(cat /target)"
WORKDIR /src
COPY Cargo.toml Cargo.lock version.txt ./
COPY sandbox/package.json sandbox/
COPY crates crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo zigbuild --release --locked -p statustick-agent --target "$(cat /target)" \
    && cp "target/$(cat /target)/release/statustick-agent" /statustick-agent

FROM scratch AS binary-export
COPY --from=binary /statustick-agent /statustick-agent

FROM node:24-trixie-slim@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe

# The Playwright version comes from sandbox/package.json; Chromium is its headless shell.
# tini runs as PID 1 and reaps the processes that browser runs leave behind.
# statustick-run-as starts each browser run as one of the run users; only the agent's group may use it.
WORKDIR /runner
COPY sandbox/package.json sandbox/package-lock.json ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping libcap2-bin tini \
    && npm ci --omit=dev --ignore-scripts \
    && PLAYWRIGHT_BROWSERS_PATH=/ms-playwright node node_modules/@playwright/test/cli.js install --with-deps --only-shell chromium \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/* /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
       /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /root/.npm /tmp/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent \
    && mkdir -p /var/lib/statustick && chown 10001 /var/lib/statustick \
    && for n in 1 2 3 4 5 6 7 8; do useradd --uid $((10100 + n)) --user-group --no-create-home --shell /usr/sbin/nologin "run$n"; done \
    && install -o root -g 10001 -m 0750 /usr/bin/setpriv /usr/local/bin/statustick-run-as \
    && setcap cap_setuid,cap_setgid+ep /usr/local/bin/statustick-run-as
COPY sandbox/playwright.config.ts sandbox/run.mts sandbox/vitals.cts sandbox/guard.cts ./
COPY --from=binary /statustick-agent /usr/local/bin/statustick-agent

USER 10001
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
ENTRYPOINT ["/usr/bin/tini", "--", "statustick-agent"]
