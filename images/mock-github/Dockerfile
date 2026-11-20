ARG RUST_IMAGE=docker.io/library/rust:1.100-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea

FROM ${RUST_IMAGE} AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p cite-mock-github

FROM docker.io/library/debian:bookworm-slim
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cite-mock-github /usr/local/bin/cite-mock-github
ENV CITE_MOCK_LISTEN=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["cite-mock-github"]
