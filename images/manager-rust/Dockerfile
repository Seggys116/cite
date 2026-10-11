ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

FROM ${RUST_IMAGE} AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p cite-manager

ARG RUST_IMAGE
FROM ${RUST_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-manager-rust" \
      org.opencontainers.image.description="Cite manager: poll, fetch, cargo-build, promote" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

RUN set -eux; \
    groupadd --system --gid 10002 citebuild; \
    useradd --system --uid 10002 --gid 10002 --home-dir /var/lib/cite/work --no-create-home citebuild; \
    mkdir -p /var/lib/cite/releases /var/lib/cite/control /var/lib/cite/status \
             /var/lib/cite/state /var/lib/cite/work /var/lib/cite/cache /run/cite; \
    chown 65532:65532 /var/lib/cite/status

COPY --from=build /src/target/release/cite-manager /usr/local/bin/cite-manager
RUN ln -sf /usr/local/bin/cite-manager /usr/local/bin/cite \
 && chmod 0755 /usr/local/bin/cite-manager

ENV CITE_DATA_DIR=/var/lib/cite \
    CITE_RELEASES_DIR=/var/lib/cite/releases \
    CITE_CONTROL_DIR=/var/lib/cite/control \
    CITE_STATUS_DIR=/var/lib/cite/status \
    CITE_STATE_DIR=/var/lib/cite/state \
    CITE_WORK_DIR=/var/lib/cite/work \
    CITE_CACHE_DIR=/var/lib/cite/cache \
    CITE_SOCKET=/run/cite/manager.sock \
    CITE_BUILD_ENV_FILE=/run/cite/build.env \
    CITE_RUNTIME=rust \
    RUST_LOG=info

# hadolint ignore=DL3002
USER 0
WORKDIR /var/lib/cite

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["cite-manager", "healthcheck"]

ENTRYPOINT ["cite-manager"]
CMD ["daemon"]
