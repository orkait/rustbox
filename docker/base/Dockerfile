# ============================================================================
# Stage 1: builder — compiles rustbox/isolate/judge binaries
# ============================================================================
# TODO: Pin to SHA256 digest for production builds
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal

ENV PATH=/root/.cargo/bin:$PATH

# Build QuickJS — not in Ubuntu 22.04 apt repos, compile from source
RUN git clone --depth 1 https://github.com/bellard/quickjs.git /tmp/quickjs \
    && cd /tmp/quickjs \
    && make qjs \
    && cp qjs /usr/local/bin/qjs \
    && rm -rf /tmp/quickjs

WORKDIR /build
COPY . .
RUN cargo build --release

# ============================================================================
# Stage 2: runtime — Ubuntu 22.04 + C++ / Python 3.11 / Java 21
# NOTE: runs as root — required for strict mode (namespaces + cgroup attach)
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/default-java
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y \
    g++ \
    python3.11 \
    openjdk-21-jdk \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# python3 → python3.11
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python

# QuickJS binary (built in builder stage, same Ubuntu 22.04 libc)
COPY --from=builder /usr/local/bin/qjs /usr/local/bin/qjs

# Bun — installed system-wide at /usr/local for TypeScript execution
ENV BUN_INSTALL=/usr/local
RUN curl -fsSL https://bun.sh/install | bash

# UID/GID 65534 (nobody) — rustbox drops payload to this user inside the sandbox
RUN groupadd -r -g 65534 sandbox 2>/dev/null || true \
    && useradd -r -u 65534 -g 65534 -s /sbin/nologin sandbox 2>/dev/null || true

# Copy binaries from builder
COPY --from=builder /build/target/release/judge   /usr/local/bin/judge
COPY --from=builder /build/target/release/isolate /usr/local/bin/isolate
COPY --from=builder /build/target/release/rustbox /usr/local/bin/rustbox

# Config
RUN mkdir -p /etc/rustbox
COPY config.json /etc/rustbox/config.json

# Runtime state dirs
RUN mkdir -p /var/run/rustbox /tmp/rustbox

# Verify all language runtimes
RUN python3 --version \
    && g++ --version \
    && java -version \
    && javac -version \
    && qjs -e 'print("qjs ok")' \
    && bun --version

WORKDIR /workspace
CMD ["/bin/bash"]
