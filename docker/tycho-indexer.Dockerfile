# Multi-stage build for tycho-indexer in the monorepo workspace.
#
# NOTE: extractors.yaml must be present at crates/tycho-indexer/extractors.yaml.
# It was not imported during Phase 1 git-mv — copy it from the tycho-indexer
# source repo before the first real build.

# ── Stage 1: chef (rust + tools layer, cached) ─────────────────────────────
FROM rust:bookworm AS chef
ARG TARGETPLATFORM=linux/amd64
WORKDIR /build
RUN apt-get update && apt-get install -y libpq-dev jq curl && rm -rf /var/lib/apt/lists/*
# Install substreams CLI for the indexer runtime
RUN ARCH=$(echo "$TARGETPLATFORM" | sed -e 's|/|_|g') && \
    if [ "$ARCH" = "linux_amd64" ]; then ARCH="linux_x86_64"; fi && \
    LINK=$(curl -s https://api.github.com/repos/streamingfast/substreams/releases/latest | \
      jq -r ".assets[] | select(.name | contains(\"$ARCH\")) | .browser_download_url") && \
    curl -L "$LINK" | tar zxf - -C /usr/local/bin/
RUN cargo install cargo-chef
COPY rust-toolchain.toml .
RUN rustup set profile minimal && rustup show

# ── Stage 2: dependency planner ─────────────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 3: build ───────────────────────────────────────────────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Pre-build deps only (cached layer)
RUN cargo chef cook --package tycho-indexer --release --recipe-path recipe.json
# Full build
COPY . .
RUN RUSTFLAGS="--cfg tokio_unstable" cargo build --package tycho-indexer --release

# ── Stage 4: minimal runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim
WORKDIR /opt/tycho-indexer
COPY --from=builder /build/target/release/tycho-indexer ./tycho-indexer
# extractors.yaml ships alongside the binary; mount or override at runtime if needed
COPY --from=builder /build/crates/tycho-indexer/extractors.yaml ./extractors.yaml
RUN apt-get update && apt-get install -y libpq5 libcurl4 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/opt/tycho-indexer/tycho-indexer", \
            "--endpoint", "https://mainnet.eth.streamingfast.io:443", \
            "index"]
