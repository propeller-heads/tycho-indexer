FROM rust:1.66 AS build
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


FROM debian:buster-slim
COPY --from=build /build/target/release/prop-builder ./target/release/prop-builder
CMD ["./target/release/prop-builder"]
