# Multi-stage build for MPC standalone node
FROM rust:1.88-bookworm AS builder

# Install dependencies for RocksDB and OpenSSL
RUN apt-get update && apt-get install -y \
    cmake \
    clang \
    libclang-dev \
    librocksdb-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/

# Build release binaries
RUN cargo build --release -p threshold-signer-node -p mpc-cli

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    librocksdb7.8 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /build/target/release/threshold-signer-node /usr/local/bin/
COPY --from=builder /build/target/release/mpc-cli /usr/local/bin/

# Create data directory
RUN mkdir -p /data /config

EXPOSE 10001 3001

ENTRYPOINT ["threshold-signer-node"]
