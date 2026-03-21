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
# Stage 2: runtime — language runtimes, heavily optimized for size
#
# Size budget after all optimizations (approximate):
#   g++ (--no-install-recommends):     ~130 MB
#   python3.11 (- pycache/test):       ~53 MB
#   jlink custom JRE + jdk.compiler:   ~62 MB  (was 285 MB full JDK)
#   bun binary:                        ~95 MB
#   qjs binary:                        ~5 MB
#   Rust binaries × 3 (stripped):      ~9 MB
#   Ubuntu base:                       ~88 MB
# ============================================================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Language runtimes — install JDK temporarily, use jlink to build a minimal
# custom JRE (62 MB) that includes javac, then delete the full JDK (285 MB).
# All in one RUN so only the final state (custom JRE) exists in the layer.
#
# Modules included:
#   java.base        — core CP classes: Scanner, ArrayList, HashMap, BigInteger, Math, …
#   java.logging     — java.util.logging (used by some CP frameworks)
#   java.management  — JVM instrumentation, sometimes needed at startup
#   java.naming      — JNDI, pulled in transitively by some stdlib paths
#   java.security.jgss — Kerberos/GSSAPI; pulled transitively by java.naming
#   java.xml         — javax.xml (XML parsing, used in some CP problems)
#   jdk.compiler     — javac tool itself
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    python3.11 \
    openjdk-21-jdk-headless \
    ca-certificates \
    && jlink --no-header-files --no-man-pages --compress=zip-6 \
        --add-modules java.base,java.logging,java.management,java.naming,java.security.jgss,java.xml,jdk.compiler \
        --output /tmp/java-minimal \
    && rm -rf /usr/lib/jvm \
    && mkdir -p /usr/lib/jvm \
    && mv /tmp/java-minimal /usr/lib/jvm/java-21-openjdk-amd64 \
    && ln -sf /usr/lib/jvm/java-21-openjdk-amd64 /usr/lib/jvm/default-java \
    && ln -sf /usr/lib/jvm/java-21-openjdk-amd64/bin/java   /usr/bin/java \
    && ln -sf /usr/lib/jvm/java-21-openjdk-amd64/bin/javac  /usr/bin/javac \
    && find /usr/lib/python3.11 -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true \
    && rm -rf /usr/lib/python3.11/test \
              /usr/lib/python3.11/unittest \
    && rm -rf /usr/share/doc \
              /usr/share/man \
              /usr/share/info \
              /usr/share/locale \
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

# Copy binaries from builder (strip = "symbols" in Cargo.toml removes ~700 KB each)
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
