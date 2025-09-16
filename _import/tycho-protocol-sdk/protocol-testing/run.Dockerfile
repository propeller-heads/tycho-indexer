# Install cargo-chef
FROM rust:1.89-bookworm AS cargo-chef
WORKDIR /app
RUN cargo install cargo-chef

# =========== Tycho Indexer ===========
# Stage 1: Prepare tycho-indexer dependencies
FROM rust:1.89-bookworm AS tycho-indexer-prepare
WORKDIR /build/tycho-indexer
RUN apt-get update && apt-get install -y git
RUN git clone --depth 1 --branch "0.83.4" https://github.com/propeller-heads/tycho-indexer.git .
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Cook tycho-indexer dependencies
FROM rust:1.89-bookworm AS tycho-indexer-cook
WORKDIR /build/tycho-indexer
COPY --from=tycho-indexer-prepare /build/tycho-indexer/ ./
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Build tycho-indexer
FROM rust:1.89-bookworm AS tycho-indexer-builder
WORKDIR /build/tycho-indexer
COPY --from=tycho-indexer-cook /build/tycho-indexer/ ./
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
RUN cargo build --release --bin tycho-indexer

# =========== Protocol SDK ===========
# Stage 1: Prepare protocol-sdk dependencies
FROM rust:1.89-bookworm AS protocol-sdk-prepare
WORKDIR /build/tycho-protocol-sdk
COPY . .
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Cook protocol-sdk dependencies
FROM rust:1.89-bookworm AS protocol-sdk-cook
WORKDIR /build/tycho-protocol-sdk
COPY --from=protocol-sdk-prepare /build/tycho-protocol-sdk/ ./
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Build protocol-sdk
FROM rust:1.89-bookworm AS protocol-sdk-builder
WORKDIR /build/tycho-protocol-sdk
COPY --from=protocol-sdk-cook /build/tycho-protocol-sdk/ ./
COPY --from=cargo-chef /usr/local/cargo/bin/cargo-chef /usr/local/cargo/bin/cargo-chef
WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo build --release

WORKDIR /build/tycho-protocol-sdk/substreams
COPY ./substreams/target/wasm32-unknown-unknown/release/*.wasm ./target/wasm32-unknown-unknown/release/
COPY ./substreams/target/wasm32-unknown-unknown/release/*.d ./target/wasm32-unknown-unknown/release/

WORKDIR /build/tycho-protocol-sdk/evm
COPY ./evm/out ./out

# =========== Third Party ===========
# Stage 1: Get substreams CLI
FROM ghcr.io/streamingfast/substreams:v1.16.4 AS substreams-cli

# Stage 2: Install Foundry (Forge)
FROM debian:bookworm AS foundry-builder
WORKDIR /build
RUN apt-get update && apt-get install -y curl git
RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup

# =========== Final Image ===========
FROM debian:bookworm

RUN apt-get update && apt-get install -y ca-certificates libssl-dev libpq-dev

# Copy binaries from previous stages
COPY --from=tycho-indexer-builder /build/tycho-indexer/target/release/tycho-indexer /usr/local/bin/tycho-indexer
RUN chmod +x /usr/local/bin/tycho-indexer
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/target/release/protocol-testing /usr/local/bin/tycho-protocol-sdk
RUN chmod +x /usr/local/bin/tycho-protocol-sdk
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/substreams /app/substreams
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/proto /app/proto
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/evm /app/evm
COPY --from=substreams-cli /app/substreams /usr/local/bin/substreams
RUN chmod +x /usr/local/bin/substreams
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=foundry-builder /root/.foundry/bin/cast /usr/local/bin/cast

# Entrypoint script to run tests
WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
