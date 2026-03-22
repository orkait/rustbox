# ============================================================================
# Language build args - set to "false" to exclude from image
# ============================================================================
ARG LANG_PYTHON=true
ARG LANG_C_CPP=true
ARG LANG_JAVA=true
ARG LANG_JAVASCRIPT=true
ARG LANG_TYPESCRIPT=true
ARG LANG_GO=false
ARG LANG_RUST=false
ARG LANG_ZIG=false

# ============================================================================
# Stage 1: Rust builder
# ============================================================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential pkg-config libssl-dev ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable --profile minimal
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build
COPY . .
RUN cargo build --release -p rustbox && cargo build --release -p judge-service

# ============================================================================
# Stage 2: Go toolchain
# ============================================================================
FROM golang:1.22-alpine AS go-toolchain

# ============================================================================
# Stage 3: Rust toolchain (stripped: no cargo, no rustdoc, no source)
# ============================================================================
FROM rust:slim AS rust-toolchain
RUN cp -a "$(rustc --print sysroot)" /rust-sysroot \
    && rm -f /rust-sysroot/bin/rustdoc /rust-sysroot/bin/cargo \
    && rm -rf /rust-sysroot/bin/rust-gdb* /rust-sysroot/bin/rust-lldb \
    && rm -rf /rust-sysroot/lib/rustlib/src \
    && rm -rf /rust-sysroot/share

# ============================================================================
# Stage 4: Runtime
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV BUN_INSTALL=/usr/local

ARG LANG_PYTHON
ARG LANG_C_CPP
ARG LANG_JAVA
ARG LANG_JAVASCRIPT
ARG LANG_TYPESCRIPT
ARG LANG_GO
ARG LANG_RUST
ARG LANG_ZIG

# All apt installs in one layer to minimize size
# JavaScript and TypeScript both use Bun
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && if [ "$LANG_C_CPP" = "true" ]; then \
         apt-get install -y --no-install-recommends g++; \
       fi \
    && if [ "$LANG_PYTHON" = "true" ]; then \
         apt-get install -y --no-install-recommends python3.11 \
         && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
         && ln -sf /usr/bin/python3.11 /usr/bin/python \
         && find /usr/lib/python3.11 -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
         && rm -rf /usr/lib/python3.11/test /usr/lib/python3.11/unittest; \
       fi \
    && if [ "$LANG_JAVA" = "true" ]; then \
         apt-get install -y --no-install-recommends openjdk-21-jdk-headless \
         && jlink --no-header-files --no-man-pages --compress=zip-6 \
              --add-modules java.base,java.logging,java.management,java.naming,java.security.jgss,java.xml,jdk.compiler \
              --output /tmp/java-minimal \
         && rm -rf /usr/lib/jvm \
         && mkdir -p /usr/lib/jvm \
         && mv /tmp/java-minimal /usr/lib/jvm/java-21-openjdk-amd64 \
         && ln -sf /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/default-java \
         && ln -sf /usr/lib/jvm/java-21-openjdk-amd64/bin/java   /usr/bin/java \
         && ln -sf /usr/lib/jvm/java-21-openjdk-amd64/bin/javac  /usr/bin/javac; \
       fi \
    && if [ "$LANG_JAVASCRIPT" = "true" ] || [ "$LANG_TYPESCRIPT" = "true" ]; then \
         apt-get install -y --no-install-recommends unzip \
         && curl -fsSL https://bun.sh/install | bash \
         && apt-get purge -y --auto-remove unzip; \
       fi \
    && rm -rf /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale \
    && rm -rf /var/lib/apt/lists/*

# Go toolchain (only if enabled, ~253MB)
COPY --from=go-toolchain /usr/local/go /tmp/go-stage/
RUN if [ "$LANG_GO" = "true" ] && [ -d /tmp/go-stage/bin ]; then \
      mv /tmp/go-stage /usr/local/go; \
    fi \
    && rm -rf /tmp/go-stage
ENV PATH="/usr/local/go/bin:$PATH"

# Rust toolchain (only if enabled, ~506MB stripped)
COPY --from=rust-toolchain /rust-sysroot /tmp/rust-stage/
RUN if [ "$LANG_RUST" = "true" ] && [ -d /tmp/rust-stage/bin ]; then \
      mv /tmp/rust-stage /usr/local/rust \
      && ln -sf /usr/local/rust/bin/rustc /usr/local/bin/rustc; \
    fi \
    && rm -rf /tmp/rust-stage

# Zig toolchain (only if enabled, ~340MB)
ARG ZIG_VERSION=0.13.0
RUN if [ "$LANG_ZIG" = "true" ]; then \
      curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /usr/local \
      && ln -sf /usr/local/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/local/bin/zig; \
    fi

# Sandbox user
RUN groupadd -r -g 65534 sandbox 2>/dev/null || true \
    && useradd -r -u 65534 -g 65534 -s /sbin/nologin sandbox 2>/dev/null || true

# Rustbox binaries
COPY --from=builder /build/target/release/judge         /usr/local/bin/judge
COPY --from=builder /build/target/release/isolate        /usr/local/bin/isolate
COPY --from=builder /build/target/release/rustbox        /usr/local/bin/rustbox
COPY --from=builder /build/target/release/judge-service  /usr/local/bin/judge-service

# Config and state dirs
RUN mkdir -p /etc/rustbox /var/run/rustbox /tmp/rustbox
COPY config.json /etc/rustbox/config.json

EXPOSE 4096

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=5s \
  CMD curl -f http://localhost:4096/api/health/ready || exit 1

WORKDIR /workspace
ENTRYPOINT ["judge-service"]
