ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim

FROM ${RUST_IMAGE} AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p cite-dashboard

ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-dashboard" \
      org.opencontainers.image.description="Cite dashboard: web console for Cite nodes" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --from=build /src/target/release/cite-dashboard /usr/local/bin/cite-dashboard
RUN set -eux; \
    chmod 0755 /usr/local/bin/cite-dashboard; \
    mkdir -p /config; \
    chown 10001:10001 /config; \
    chmod 0750 /config

ENV CITE_DASHBOARD_CONFIG=/config/dashboard.json \
    CITE_DASHBOARD_LISTEN=0.0.0.0:8088 \
    RUST_LOG=info

WORKDIR /config
USER 10001:10001

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["cite-dashboard", "healthcheck"]

ENTRYPOINT ["cite-dashboard"]
CMD ["run"]
