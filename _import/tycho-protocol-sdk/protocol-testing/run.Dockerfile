# =========== Third Party ===========
# Get substreams CLI
FROM ghcr.io/streamingfast/substreams:v1.16.4 AS substreams-cli

# Install Foundry (Forge)
FROM debian:bookworm AS foundry-builder
WORKDIR /build
RUN apt-get update && apt-get install -y curl git
RUN curl -L https://foundry.paradigm.xyz | bash
RUN /root/.foundry/bin/foundryup

# =========== Tycho Indexer ===========
FROM rust:1.89-bookworm AS tycho-indexer-builder
WORKDIR /build
RUN apt-get update && apt-get install -y git
RUN git clone --depth 1 --branch "0.83.4" https://github.com/propeller-heads/tycho-indexer.git
WORKDIR /build/tycho-indexer
RUN cargo build --release --bin tycho-indexer

# =========== Protocol SDK ===========
FROM rust:1.89-bookworm AS protocol-sdk-builder
ARG PROTOCOLS=""
WORKDIR /build/tycho-protocol-sdk
COPY . .

# Build EVM contracts first (protocol-testing depends on the runtime JSON files)
WORKDIR /build/tycho-protocol-sdk/evm
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
RUN chmod +x /usr/local/bin/forge
RUN forge build

# Build substreams (wasm targets only - source not needed in final image)
WORKDIR /build/tycho-protocol-sdk/substreams
RUN if [ -n "$PROTOCOLS" ]; then \
        echo "Building only specified protocols: $PROTOCOLS"; \
        for protocol in $PROTOCOLS; do \
            protocol_clean=${protocol%%=*}; \
            if [ -d "$protocol_clean" ]; then \
                echo "Building $protocol_clean..."; \
                cd "$protocol_clean" && cargo build --target wasm32-unknown-unknown --release && cd ..; \
            fi; \
        done; \
    else \
        echo "Building all protocols..."; \
        cargo build --target wasm32-unknown-unknown --release; \
    fi

# Build protocol-testing binary (after EVM contracts are built)
WORKDIR /build/tycho-protocol-sdk/protocol-testing
RUN cargo build --release

# =========== Substreams Filter Stage ===========
FROM debian:bookworm-slim AS substreams-filter
ARG PROTOCOLS=""
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/substreams /source
RUN mkdir -p /filtered/target/wasm32-unknown-unknown/release && \
    if [ -n "$PROTOCOLS" ]; then \
        echo "Filtering for protocols: $PROTOCOLS"; \
        for protocol in $PROTOCOLS; do \
            protocol_clean=${protocol%%=*}; \
            if [ -d "/source/$protocol_clean" ]; then \
                echo "Including $protocol_clean..."; \
                cp -r "/source/$protocol_clean" "/filtered/"; \
                protocol_wasm=$(echo "$protocol_clean" | tr '-' '_'); \
                if [ -f "/source/target/wasm32-unknown-unknown/release/${protocol_wasm}.wasm" ]; then \
                    cp "/source/target/wasm32-unknown-unknown/release/${protocol_wasm}.wasm" \
                       "/filtered/target/wasm32-unknown-unknown/release/"; \
                fi; \
            fi; \
        done; \
    else \
        echo "Including all protocols..."; \
        cp -r /source/* /filtered/; \
    fi && \
    echo "Filter stage complete. Size:" && du -sh /filtered 2>/dev/null || echo "Filter stage complete"

# =========== Final Runtime Image ===========
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 libpq5 && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /usr/share/doc/* /usr/share/man/* /usr/share/locale/* && \
    find /usr/lib -name "*.a" -delete && \
    find /usr/lib -name "*.la" -delete

# Copy essential binaries only
COPY --from=tycho-indexer-builder /build/tycho-indexer/target/release/tycho-indexer /usr/local/bin/tycho-indexer
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/target/release/protocol-testing /usr/local/bin/tycho-protocol-sdk
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/protocol-testing/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create minimal directory structure
RUN mkdir -p /app/proto /app/evm

# Copy proto files (needed for substreams pack)  
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/proto /app/proto

# Copy EVM directory
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/evm/out /app/evm/out
COPY --from=protocol-sdk-builder /build/tycho-protocol-sdk/evm/scripts /app/evm/scripts
# Remove unnecessary EVM build artifacts
RUN find /app/evm/out -name "*.json" ! -name "*.runtime.json" -delete && \
    find /app/evm/out -type d -empty -delete 2>/dev/null || true

# Copy filtered substreams from filter stage
COPY --from=substreams-filter /filtered /app/substreams

# Clean up unnecessary files to reduce size
RUN find /app -name "*.rs" -delete && \
    find /app -name "Cargo.toml" -delete && \
    find /app -name "Cargo.lock" -delete && \
    find /app -name "src" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "*.d" -delete && \
    find /app -name "*.rlib" -delete && \
    find /app -name "*.rmeta" -delete && \
    find /app -name ".fingerprint" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "build" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "deps" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -name "incremental" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /app -type d -empty -delete 2>/dev/null || true

# Copy external tools
COPY --from=substreams-cli /app/substreams /usr/local/bin/substreams
RUN chmod +x /usr/local/bin/substreams
COPY --from=foundry-builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=foundry-builder /root/.foundry/bin/cast /usr/local/bin/cast

# Strip binaries to reduce size
RUN strip /usr/local/bin/* 2>/dev/null || true

WORKDIR /app
ENTRYPOINT ["/entrypoint.sh"]
