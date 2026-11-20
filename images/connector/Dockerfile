ARG RUST_IMAGE=docker.io/library/rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea
ARG HAPROXY_IMAGE=docker.io/library/haproxy:3.2-bookworm

FROM ${RUST_IMAGE} AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p cite-connector

ARG HAPROXY_IMAGE
FROM ${HAPROXY_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-connector" \
      org.opencontainers.image.description="Cite node connector: edge API, HAProxy control, optional site orchestration" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --chmod=0755 --from=build /src/target/release/cite-connector /usr/local/bin/cite-connector

ENV RUST_LOG=info

USER 0
WORKDIR /conf
# A fresh cite-backups volume copies this ownership on first mount; backups and staged dumps are private to the connector.
RUN mkdir -p /backups && chown 10001:10001 /backups && chmod 0700 /backups
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["cite-connector", "healthcheck"]

ENTRYPOINT ["cite-connector"]
CMD ["run"]
