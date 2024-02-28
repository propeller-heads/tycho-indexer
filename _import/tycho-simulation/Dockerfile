FROM rust:1.74 AS build
WORKDIR /build
RUN echo "fn main() {}" > dummy.rs
COPY protosim protosim
COPY Cargo.toml .
COPY Cargo.lock .
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN cargo build --release
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml
COPY . .
RUN cargo build --release


FROM debian:bullseye-slim
COPY --from=build /build/target/release/prop-builder ./target/release/prop-builder
ENTRYPOINT ["./target/release/prop-builder"]
