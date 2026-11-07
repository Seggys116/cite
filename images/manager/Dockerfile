ARG NODE_MAJOR=22
ARG NODE_IMAGE=docker.io/library/node:22-bookworm-slim@sha256:5ec23b7c622b00547753bc6ffd78085dd868a68aeb41c8e0a1418f033e13d96d
ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG BUN_VERSION=1.4.4
ARG BUN_SHA256_AMD64=bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c
ARG BUN_SHA256_ARM64=baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e

FROM ${RUST_IMAGE} AS build

ARG BUN_VERSION
ARG BUN_SHA256_AMD64
ARG BUN_SHA256_ARM64
ARG TARGETARCH

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p cite-manager

# Downloads stay in this stage: the final image has no curl or wget.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) arch=x64; sha="${BUN_SHA256_AMD64}" ;; \
      arm64) arch=aarch64; sha="${BUN_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bun.zip \
      "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-${arch}.zip"; \
    echo "${sha}  /tmp/bun.zip" | sha256sum -c -; \
    unzip -q /tmp/bun.zip -d /tmp; \
    install -m 0755 "/tmp/bun-linux-${arch}/bun" /usr/local/bin/bun; \
    rm -rf /tmp/bun.zip "/tmp/bun-linux-${arch}"

ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS runtime

ARG NODE_MAJOR=22
ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-manager" \
      org.opencontainers.image.description="Cite manager: poll, fetch, build, promote" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke" \
      cite.node.major="${NODE_MAJOR}"

# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates libssl3; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
    corepack enable; \
    corepack prepare pnpm@12.18.0 --activate; \
    groupadd --system --gid 10002 citebuild; \
    useradd --system --uid 10002 --gid 10002 --home-dir /var/lib/cite/work --no-create-home citebuild; \
    mkdir -p /var/lib/cite/releases /var/lib/cite/control /var/lib/cite/status \
             /var/lib/cite/state /var/lib/cite/work /var/lib/cite/cache /run/cite; \
    chown 65532:65532 /var/lib/cite/status; \
    if command -v git >/dev/null; then exit 1; fi; \
    if command -v curl >/dev/null; then exit 1; fi; \
    if command -v wget >/dev/null; then exit 1; fi

COPY --from=build /src/target/release/cite-manager /usr/local/bin/cite-manager
COPY --from=build /usr/local/bin/bun /usr/local/bin/bun
RUN ln -sf /usr/local/bin/cite-manager /usr/local/bin/cite \
 && chmod 0755 /usr/local/bin/cite-manager /usr/local/bin/bun

# hadolint ignore=DL3064
ENV CITE_DATA_DIR=/var/lib/cite \
    CITE_RELEASES_DIR=/var/lib/cite/releases \
    CITE_CONTROL_DIR=/var/lib/cite/control \
    CITE_STATUS_DIR=/var/lib/cite/status \
    CITE_STATE_DIR=/var/lib/cite/state \
    CITE_WORK_DIR=/var/lib/cite/work \
    CITE_CACHE_DIR=/var/lib/cite/cache \
    CITE_SOCKET=/run/cite/manager.sock \
    CITE_BUILD_ENV_FILE=/run/cite/build.env \
    CITE_NODE=${NODE_MAJOR} \
    RUST_LOG=info \
    PATH=/usr/local/bin:/usr/bin:/bin

# hadolint ignore=DL3002
USER 0
WORKDIR /var/lib/cite

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["cite-manager", "healthcheck"]

ENTRYPOINT ["cite-manager"]
CMD ["daemon"]
