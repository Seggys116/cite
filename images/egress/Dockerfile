ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
ARG STATIC_IMAGE=gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

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
 && cargo build --locked --release -p cite-egress --target "${TARGET}" \
 && cp "target/${TARGET}/release/cite-egress" /cite-egress

FROM ${STATIC_IMAGE} AS runtime

ARG VERSION
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="cite-egress" \
      org.opencontainers.image.description="Cite egress proxy: public-internet-only forward proxy for site executors" \
      org.opencontainers.image.source="https://github.com/seggys116/cite" \
      org.opencontainers.image.url="https://github.com/seggys116/cite" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.vendor="Zak Noble-Clarke"

COPY --from=build /cite-egress /cite-egress

ENV RUST_LOG=info

USER 65532:65532

EXPOSE 3128

ENTRYPOINT ["/cite-egress"]
