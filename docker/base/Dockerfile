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
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile minimal

ENV PATH=/root/.cargo/bin:$PATH

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
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# python3 → python3.11
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python

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

# Verify
RUN python3 --version \
    && g++ --version \
    && java -version \
    && javac -version

WORKDIR /workspace
CMD ["/bin/bash"]
