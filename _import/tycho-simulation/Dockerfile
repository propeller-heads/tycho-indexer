FROM rust:1.82-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --package tycho-integration-test

FROM debian:bookworm-slim
WORKDIR /opt/tycho-integration-test
COPY --from=builder /build/target/release/tycho-integration-test ./tycho-integration-test
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
CMD ["./tycho-integration-test"]