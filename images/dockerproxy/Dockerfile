ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${RUST_IMAGE} AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

RUN cargo build --locked --release -p cite-dockerproxy

ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-dockerproxy" \
      org.opencontainers.image.description="Cite Docker proxy: deny-by-default filter in front of the Docker Engine socket" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --chmod=0755 --from=build /src/target/release/cite-dockerproxy /usr/local/bin/cite-dockerproxy

ENV CITE_PROXY_LISTEN=0.0.0.0:2375 \
    CITE_PROXY_SOCKET=/var/run/docker.sock \
    RUST_LOG=info

# The socket belongs to the host's docker group: compose adds that gid with group_add (DOCKER_GID).
USER 10001:10001

EXPOSE 2375

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["cite-dockerproxy", "healthcheck"]

ENTRYPOINT ["cite-dockerproxy"]
CMD ["run"]
