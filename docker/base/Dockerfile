# ============================================================================
# Stage 1: builder — compiles rustbox/isolate/judge binaries + QuickJS
# ============================================================================
# TODO: Pin to SHA256 digest for production builds
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
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
# Stage 2: runtime — language runtimes, headless/no-recommends variants
#
# Size budget per language runtime (approximate installed sizes):
#   g++ (--no-install-recommends):  ~130 MB  (was ~250 MB with recommends)
#   python3.11:                     ~60 MB
#   openjdk-21-jdk-headless:        ~280 MB  (was ~450 MB for full JDK)
#   bun binary:                     ~95 MB
#   qjs binary:                     ~1 MB
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/default-java
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Language runtimes — headless + no-recommends to cut ~300 MB vs naive install
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    python3.11 \
    openjdk-21-jdk-headless \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# python3 → python3.11
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python

# QuickJS binary (built in builder stage, same Ubuntu 22.04 libc)
COPY --from=builder /usr/local/bin/qjs /usr/local/bin/qjs

# Bun — install via curl+unzip, then purge them in the same layer so they
# don't bloat the final image (only the ~95 MB bun binary stays)
ENV BUN_INSTALL=/usr/local
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip \
    && curl -fsSL https://bun.sh/install | bash \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*

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
