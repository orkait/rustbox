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
# Stage 2: Runtime (single layer for all languages)
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV BUN_INSTALL=/usr/local
ENV PATH="/usr/local/go/bin:/usr/local/rust/bin:$PATH"

ARG LANG_PYTHON
ARG LANG_C_CPP
ARG LANG_JAVA
ARG LANG_JAVASCRIPT
ARG LANG_TYPESCRIPT
ARG LANG_GO
ARG LANG_RUST

# All installs in ONE RUN = one layer = no wasted space from conditional copies
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    #
    # C / C++
    && if [ "$LANG_C_CPP" = "true" ]; then \
         apt-get install -y --no-install-recommends g++ \
         && g++ -std=c++17 -O2 -x c++-header \
              $(find /usr/include -name 'stdc++.h' -path '*/bits/*' 2>/dev/null | head -1) \
              2>/dev/null || true; \
       elif [ "$LANG_RUST" = "true" ]; then \
         apt-get install -y --no-install-recommends gcc libc6-dev; \
       fi \
    #
    # Python
    && if [ "$LANG_PYTHON" = "true" ]; then \
         apt-get install -y --no-install-recommends python3.11 \
         && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
         && ln -sf /usr/bin/python3.11 /usr/bin/python \
         && find /usr/lib/python3.11 -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
         && rm -rf /usr/lib/python3.11/test /usr/lib/python3.11/unittest; \
       fi \
    #
    # Java (install full JDK, jlink to minimal, delete full JDK)
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
    #
    # JavaScript / TypeScript (both use Bun)
    && if [ "$LANG_JAVASCRIPT" = "true" ] || [ "$LANG_TYPESCRIPT" = "true" ]; then \
         apt-get install -y --no-install-recommends unzip \
         && curl -fsSL https://bun.sh/install | bash \
         && apt-get purge -y --auto-remove unzip; \
       fi \
    #
    # Go (download official tarball)
    && if [ "$LANG_GO" = "true" ]; then \
         curl -fsSL "https://go.dev/dl/go1.22.10.linux-amd64.tar.gz" \
         | tar -xz -C /usr/local \
         && mkdir -p /usr/local/go-cache \
         && GOCACHE=/usr/local/go-cache CGO_ENABLED=0 /usr/local/go/bin/go build -a std 2>/dev/null || true; \
       fi \
    #
    # Rust (install rustup, extract sysroot, delete rustup)
    && if [ "$LANG_RUST" = "true" ]; then \
         curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --default-toolchain stable --profile minimal \
         && SYSROOT=$(/root/.cargo/bin/rustc --print sysroot) \
         && cp -a "$SYSROOT" /usr/local/rust \
         && rm -f /usr/local/rust/bin/rustdoc /usr/local/rust/bin/cargo \
         && rm -rf /usr/local/rust/bin/rust-gdb* /usr/local/rust/bin/rust-lldb \
         && rm -rf /usr/local/rust/lib/rustlib/src /usr/local/rust/share \
         && ln -sf /usr/local/rust/bin/rustc /usr/local/bin/rustc \
         && rm -rf /root/.cargo /root/.rustup; \
       fi \
    #
    # Cleanup
    && rm -rf /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale \
    && rm -rf /var/lib/apt/lists/*

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
