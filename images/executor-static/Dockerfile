ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG STATIC_IMAGE=gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

FROM ${RUST_IMAGE} AS build
# distroless/static needs a musl target; TARGET defaults from TARGETARCH when unset.
ARG TARGET
ARG TARGETARCH
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && if [ -z "${TARGET}" ]; then \
      case "${TARGETARCH}" in \
        amd64) TARGET=x86_64-unknown-linux-musl ;; \
        arm64) TARGET=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
      esac; \
    fi \
 && echo "musl target=${TARGET}" \
 && rustup target add "${TARGET}" \
 && printf '%s' "${TARGET}" > /tmp/cite-musl-target

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN TARGET="$(cat /tmp/cite-musl-target)" \
 && cargo build --locked --release -p cite-executor --target "${TARGET}" \
 && cp "target/${TARGET}/release/cite-executor" /cite-executor \
 && mkdir -p /cite-var/releases/blue /cite-var/releases/green /cite-var/control /cite-var/status \
 && chown 65532:65532 /cite-var/status

FROM ${STATIC_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-executor-static" \
      org.opencontainers.image.description="Cite executor: shell-less static-site hosting" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --from=build --chown=65532:65532 /cite-executor /cite-executor
COPY --from=build /cite-var/ /var/lib/cite/
COPY --from=build --chown=65532:65532 /cite-var/status/ /var/lib/cite/status/

ENV CITE_DATA_DIR=/var/lib/cite \
    CITE_RELEASES_DIR=/var/lib/cite/releases \
    CITE_CONTROL_DIR=/var/lib/cite/control \
    CITE_STATUS_DIR=/var/lib/cite/status \
    CITE_LISTEN=0.0.0.0:8080 \
    CITE_RUNTIME=static \
    RUST_LOG=info

USER 65532:65532
WORKDIR /var/lib/cite

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/cite-executor", "healthcheck"]

ENTRYPOINT ["/cite-executor"]
CMD ["daemon"]
