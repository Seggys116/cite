ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG BUN_IMAGE=docker.io/oven/bun:1-distroless@sha256:1a0c31c7c5f9d193aedf60fe1cebdeb76ac8f6e29f24be8dd8cbd6df72df26ec

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# The bun distroless base has libc but not libgcc_s: link it statically and copy the shared one below.
ENV RUSTFLAGS="-C link-arg=-static-libgcc"
RUN cargo build --locked --release -p cite-executor \
 && mkdir -p /cite-var/releases/blue /cite-var/releases/green /cite-var/control /cite-var/status \
 && chown 65532:65532 /cite-var/status
RUN multiarch="$(gcc -print-multiarch)" \
 && mkdir -p "/cite-libs/${multiarch}" \
 && cp "$(gcc -print-file-name=libgcc_s.so.1)" "/cite-libs/${multiarch}/libgcc_s.so.1"

FROM ${BUN_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-executor-bun" \
      org.opencontainers.image.description="Cite executor: shell-less Bun hosting + blue-green" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --from=build --chown=65532:65532 /src/target/release/cite-executor /cite-executor
COPY --from=build /cite-var/ /var/lib/cite/
COPY --from=build --chown=65532:65532 /cite-var/status/ /var/lib/cite/status/
COPY --from=build /cite-libs/ /usr/lib/

ENV CITE_DATA_DIR=/var/lib/cite \
    CITE_RELEASES_DIR=/var/lib/cite/releases \
    CITE_CONTROL_DIR=/var/lib/cite/control \
    CITE_STATUS_DIR=/var/lib/cite/status \
    CITE_LISTEN=0.0.0.0:8080 \
    CITE_RUNTIME=bun \
    RUST_LOG=info

USER 65532:65532
WORKDIR /var/lib/cite

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/cite-executor", "healthcheck"]

ENTRYPOINT ["/cite-executor"]
CMD ["daemon"]
