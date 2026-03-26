FROM rust:1.88-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY judge-service/ judge-service/

RUN cargo build --release -p judge-service

# Runtime
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    g++ \
    openjdk-21-jdk-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# UID pool range (60000-60099) - one user per concurrent sandbox
RUN for i in $(seq 60000 60099); do \
        groupadd -r -g $i "sandbox-$i" 2>/dev/null || true; \
        useradd -r -u $i -g $i -s /sbin/nologin -d /nonexistent "sandbox-$i" 2>/dev/null || true; \
    done

# Create sandbox state directories
RUN mkdir -p /var/run/rustbox /tmp/rustbox /etc/rustbox

COPY --from=builder /build/target/release/judge-service /usr/local/bin/judge-service
COPY config.json /etc/rustbox/config.json
RUN chmod 644 /etc/rustbox/config.json

EXPOSE 8080

# NOTE: Container runs as root because strict-mode sandbox requires root
# for namespace creation, cgroup attachment, and capability dropping.
# Container-level hardening is via cap_drop/cap_add/no-new-privileges in docker-compose.yml.

ENTRYPOINT ["judge-service"]
