# Stage 1: Build the extension using pgrx
FROM rust:1-trixie AS builder

# Disable incremental compilation and enable sparse registry to reduce disk usage
ENV CARGO_INCREMENTAL=0 \
    CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

# postgresql-server-dev-17 is available in Debian trixie's default repositories
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-server-dev-17 \
    clang \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-pgrx, then immediately purge the downloaded crate registry to free space
RUN cargo install cargo-pgrx --version 0.17.0 --locked && \
    rm -rf /root/.cargo/registry/src /root/.cargo/registry/cache

WORKDIR /build
COPY . .

# Register system pg17 with pgrx (no download needed), then package the extension.
# Override the release profile to use thin LTO so the linker does not exhaust /tmp.
RUN cargo pgrx init --pg17 /usr/bin/pg_config && \
    CARGO_PROFILE_RELEASE_LTO=thin \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
    cargo pgrx package --pg-config /usr/bin/pg_config --features pg17

# Stage 2: PostgreSQL 17 with the extension installed
FROM postgres:17-trixie

COPY --from=builder \
    /build/target/release/pg_command_fw-pg17/usr/lib/postgresql/17/lib/pg_command_fw.so \
    /usr/lib/postgresql/17/lib/pg_command_fw.so

COPY --from=builder \
    /build/target/release/pg_command_fw-pg17/usr/share/postgresql/17/extension/ \
    /usr/share/postgresql/17/extension/
