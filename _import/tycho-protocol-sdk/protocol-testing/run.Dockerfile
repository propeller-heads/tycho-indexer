# Stage 1: Build tycho-indexer
FROM rust:1.89-bookworm AS tycho-indexer-builder

WORKDIR /build
RUN apt-get update && apt-get install -y git

RUN git clone --depth 1 --branch "0.82.0" https://github.com/propeller-heads/tycho-indexer.git
WORKDIR /build/tycho-indexer
RUN cargo build --release --bin tycho-indexer

# Stage 2: Get substreams CLI
FROM ghcr.io/streamingfast/substreams:v1.16.4 AS substreams-cli

# Stage 3: Install Foundry (Forge)
FROM debian:bookworm AS foundry-builder

WORKDIR /build
RUN apt-get update && apt-get install -y curl git
RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup

# Stage 4: Build protocol-testing and substreams
FROM rust:1.89-bookworm AS protocol-sdk-builder

WORKDIR /build
RUN apt-get update && apt-get install -y git

RUN git clone --depth 1 https://github.com/propeller-heads/tycho-protocol-sdk.git

WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo build --release

WORKDIR /build/tycho-protocol-sdk/substreams
RUN cargo build --target wasm32-unknown-unknown --release

WORKDIR /build/tycho-protocol-sdk/evm
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
RUN chmod +x /usr/local/bin/forge
RUN forge install
RUN forge build

# Stage 5: Final image
FROM debian:bookworm

RUN apt-get update && apt-get install -y ca-certificates libssl-dev libpq-dev

# Copy binaries from previous stages
COPY --from=tycho-indexer-builder /build/tycho-indexer/target/release/tycho-indexer /usr/local/bin/tycho-indexer
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/target/release/protocol-testing /usr/local/bin/tycho-protocol-sdk
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/substreams /app/substreams
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/proto /app/proto
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/evm /app/evm
COPY --from=substreams-cli /app/substreams /usr/local/bin/substreams
RUN chmod +x /usr/local/bin/substreams
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=foundry-builder /root/.foundry/bin/cast /usr/local/bin/cast

# Verify binaries
RUN tycho-indexer --version && tycho-protocol-sdk --version && substreams --version && forge --version && cast --version

# Entrypoint script to run tests
WORKDIR /app
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
