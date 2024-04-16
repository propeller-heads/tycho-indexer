FROM rust:1.74 AS build
WORKDIR /build
ENV CARGO_HOME=/build/.cargo
RUN cargo new --lib protosim_py
RUN apt-get update && apt-get install -y \
    clang \
    libclang-dev
RUN echo "fn main() {}" > dummy.rs
COPY ./.cargo ./.cargo
COPY protosim protosim
COPY Cargo.toml .
COPY Cargo.lock .
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml
COPY . .
RUN cargo build --release


FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y libssl1.1 && apt clean && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/prop-builder ./target/release/prop-builder
ENTRYPOINT ["./target/release/prop-builder"]
