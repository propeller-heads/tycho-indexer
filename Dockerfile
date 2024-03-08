FROM rust:1.74-bookworm AS chef
ARG TARGETPLATFORM
WORKDIR /build
RUN apt-get update && apt-get install -y libpq-dev jq
RUN ARCH=$(echo $TARGETPLATFORM | sed -e 's/\//_/g') && \
    if [ "$ARCH" = "linux_amd64" ]; then \
    ARCH="linux_x86_64"; \
    fi && \
    LINK=$(curl -s https://api.github.com/repos/streamingfast/substreams/releases/latest | jq -r ".assets[] | select(.name | contains(\"$ARCH\")) | .browser_download_url")  && \
    echo ARCH: $ARCH, LINK: $LINK && \
    curl -L  $LINK  | tar zxf - -C /usr/local/bin/
RUN cargo install cargo-workspaces
RUN cargo install cargo-chef 
COPY rust-toolchain.toml .
RUN rustup update 1.74

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --package tycho-indexer --release --recipe-path recipe.json
COPY . .
# the hack below is probably needed because of rust-toolchain.toml
# will fix this later we have time to optimise the build
RUN rustup target add wasm32-unknown-unknown && ./stable-build.sh

FROM debian:bookworm
WORKDIR /opt/tycho-indexer
COPY --from=build /build/target/release/tycho-indexer ./tycho-indexer
COPY --from=build /build/target/release/tycho-client ./tycho-client
COPY --from=build /build/substreams/ethereum-ambient/substreams-ethereum-ambient-v0.4.0.spkg ./substreams/substreams-ethereum-ambient-v0.4.0.spkg
COPY --from=build /build/substreams/ethereum-uniswap-v2/substreams-ethereum-uniswap-v2-v0.1.0.spkg ./substreams/substreams-ethereum-uniswap-v2-v0.1.0.spkg
COPY --from=build /build/substreams/ethereum-uniswap-v3/substreams-ethereum-uniswap-v3-v0.1.0.spkg ./substreams/substreams-ethereum-uniswap-v3-v0.1.0.spkg
RUN apt-get update && apt-get install -y libpq-dev libcurl4 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["/opt/tycho-indexer/tycho-indexer", "--endpoint", "https://mainnet.eth.streamingfast.io:443", "--module", "map_changes", "--spkg", "/opt/tycho-indexer/substreams/substreams-ethereum-ambient-v0.3.0.spkg"]