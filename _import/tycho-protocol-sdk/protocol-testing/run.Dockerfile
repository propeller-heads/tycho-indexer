# Stage 1: Build tycho-indexer
FROM rust:1.89-bookworm AS tycho-indexer-builder

WORKDIR /build
RUN apt-get update && apt-get install -y git

RUN git clone --depth 1 --branch "0.82.0" https://github.com/propeller-heads/tycho-indexer.git
WORKDIR /build/tycho-indexer
RUN cargo build --release --bin tycho-indexer

# Stage 2: Build protocol-testing and substreams
FROM rust:1.89-bookworm AS protocol-sdk-builder

WORKDIR /build
RUN apt-get update && apt-get install -y git

RUN git clone --depth 1 https://github.com/propeller-heads/tycho-protocol-sdk.git

WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo build --release

WORKDIR /build/tycho-protocol-sdk/substreams
RUN cargo build --target wasm32-unknown-unknown --release

# Stage 3: Install substreams CLI
FROM debian:bookworm AS substreams-cli-builder

WORKDIR /build
RUN apt-get update && apt-get install -y curl

# Download and install Substreams CLI
RUN curl -L https://github.com/streamingfast/substreams/releases/download/v1.16.4/substreams_linux_arm64.tar.gz \
    | tar -zxf -

# Stage 3: Install Foundry (Forge)
FROM debian:bookworm AS foundry-builder

WORKDIR /build
RUN apt-get update && apt-get install -y curl git
RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup

# Stage 4: Final image
FROM debian:bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates libssl-dev libpq-dev

# Copy binaries from previous stages
COPY --from=tycho-indexer-builder /build/tycho-indexer/target/release/tycho-indexer /usr/local/bin/tycho-indexer
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/target/release/protocol-testing /usr/local/bin/tycho-protocol-sdk
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/substreams /app/substreams
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/proto /app/proto
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/evm /app/evm
COPY --from=substreams-cli-builder /build/substreams /usr/local/bin/substreams
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=foundry-builder /root/.foundry/bin/cast /usr/local/bin/cast

# Entrypoint script to run tests
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
