ARG RUST_IMAGE=docker.io/library/rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

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
