# Use Ubuntu as the base image
FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /build

# Copy the entire workspace
COPY . .

# Install maturin
RUN pip3 install maturin

# Build the Python package
WORKDIR /build/tycho-client-py
RUN python3 -m maturin build --release

# Move the built wheel to the output directory
RUN mkdir -p /output && mv /build/target/wheels/*.whl /output/

VOLUME /output

# TO RUN:
# docker build -f tycho-client-py/Dockerfile --platform linux/amd64 -t tycho-wheel-builder .
# docker run --platform linux/amd64 -d --name wheel-builder tycho-wheel-builder tail -f /dev/null
# docker cp wheel-builder:/output/. ./dist/
# docker rm -f wheel-builder