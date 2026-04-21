# Multi-stage build for tycho-indexer in the monorepo workspace.

# ── Stage 1: chef (rust + tools layer, cached) ─────────────────────────────
FROM rust:1.91-bookworm AS chef
WORKDIR /build
RUN apt-get update && apt-get install -y libpq-dev && rm -rf /var/lib/apt/lists/*
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
RUN RUSTFLAGS="--cfg tokio_unstable" cargo build --package tycho-indexer --release && \
    cp crates/tycho-indexer/extractors.yaml extractors.yaml

# ── Stage 4: minimal runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim
WORKDIR /opt/tycho-indexer
COPY --from=builder /build/target/release/tycho-indexer ./tycho-indexer
COPY --from=builder /build/extractors.yaml ./extractors.yaml
RUN apt-get update && apt-get install -y libpq5 libcurl4 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/opt/tycho-indexer/tycho-indexer", \
            "--endpoint", "https://mainnet.eth.streamingfast.io:443", \
            "index"]
