ARG NODE_MAJOR=22
ARG EXECUTOR_IMAGE=gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG DEBIAN_IMAGE=docker.io/library/debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p cite-executor \
 && mkdir -p /cite-var/releases/blue /cite-var/releases/green /cite-var/control /cite-var/status \
 && chown 65532:65532 /cite-var/status

# Overlay bookworm-security libssl3 because the pinned distroless base ships a vulnerable one.
FROM ${DEBIAN_IMAGE} AS openssl
ARG TARGETARCH
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libssl3; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH}" in \
      amd64) multiarch=x86_64-linux-gnu ;; \
      arm64) multiarch=aarch64-linux-gnu ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    mkdir -p "/openssl-out/usr/lib/${multiarch}" /openssl-out/var/lib/dpkg/status.d; \
    cp "/usr/lib/${multiarch}/libssl.so.3" "/usr/lib/${multiarch}/libcrypto.so.3" \
      "/openssl-out/usr/lib/${multiarch}/"; \
    awk 'BEGIN{p=0} /^Package: libssl3$/{p=1} p{print} p && /^$/{exit}' \
      /var/lib/dpkg/status > /openssl-out/var/lib/dpkg/status.d/libssl3

ARG EXECUTOR_IMAGE
FROM ${EXECUTOR_IMAGE} AS runtime

ARG NODE_MAJOR=22
ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-executor-node" \
      org.opencontainers.image.description="Cite executor: shell-less Node hosting + blue-green" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke" \
      cite.node.major="${NODE_MAJOR}"

COPY --from=build --chown=65532:65532 /src/target/release/cite-executor /cite-executor
COPY --from=build /cite-var/ /var/lib/cite/
COPY --from=build --chown=65532:65532 /cite-var/status/ /var/lib/cite/status/
COPY --from=openssl /openssl-out/usr/ /usr/
COPY --from=openssl /openssl-out/var/ /var/

ENV CITE_DATA_DIR=/var/lib/cite \
    CITE_RELEASES_DIR=/var/lib/cite/releases \
    CITE_CONTROL_DIR=/var/lib/cite/control \
    CITE_STATUS_DIR=/var/lib/cite/status \
    CITE_LISTEN=0.0.0.0:8080 \
    CITE_NODE=${NODE_MAJOR} \
    CITE_NODE_BIN=/nodejs/bin/node \
    RUST_LOG=info

USER 65532:65532
WORKDIR /var/lib/cite

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/cite-executor", "healthcheck"]

ENTRYPOINT ["/cite-executor"]
CMD ["daemon"]
