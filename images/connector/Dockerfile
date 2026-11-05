ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG HAPROXY_IMAGE=docker.io/library/haproxy:3.0-bookworm

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
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["cite-connector", "healthcheck"]

ENTRYPOINT ["cite-connector"]
CMD ["run"]
