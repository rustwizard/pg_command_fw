# Stage 1: Build the extension using pgrx
FROM rust:1-trixie AS builder

# Add the official PostgreSQL apt repository so postgresql-server-dev-17 is available
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    lsb-release \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
       | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] \
       https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
       > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update && apt-get install -y --no-install-recommends \
    postgresql-server-dev-17 \
    clang \
    libclang-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-pgrx --version 0.17.0 --locked

WORKDIR /build
COPY . .

# Register system pg17 with pgrx (no download needed), then package the extension
RUN cargo pgrx init --pg17 /usr/bin/pg_config && \
    cargo pgrx package --pg-config /usr/bin/pg_config --features pg17

# Stage 2: PostgreSQL 17 with the extension installed
FROM postgres:17-trixie

COPY --from=builder \
    /build/target/release/pg_command_fw-pg17/usr/lib/postgresql/17/lib/pg_command_fw.so \
    /usr/lib/postgresql/17/lib/pg_command_fw.so

COPY --from=builder \
    /build/target/release/pg_command_fw-pg17/usr/share/postgresql/17/extension/ \
    /usr/share/postgresql/17/extension/
