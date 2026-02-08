# Base image with C++, Python, Java, and Rust
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies and languages
RUN apt-get update && apt-get install -y \
    # Basic system tools
    curl \
    wget \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    # C/C++ compiler and tools
    gcc \
    g++ \
    make \
    cmake \
    # Python 3.11
    python3.11 \
    python3.11-dev \
    python3.11-venv \
    python3-pip \
    # Java 17
    openjdk-17-jdk \
    openjdk-17-jre \
    # Additional tools
    jq \
    vim \
    nano \
    htop \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    --default-toolchain stable \
    --profile default \
    && rustup component add rustfmt clippy

# Create symbolic links for Python
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python

# Set up working directory
WORKDIR /workspace

# Create user for security (non-root)
RUN groupadd -r rustbox && useradd -r -g rustbox rustbox \
    && mkdir -p /home/rustbox \
    && chown -R rustbox:rustbox /home/rustbox \
    && chown -R rustbox:rustbox /workspace

# Switch to non-root user
USER rustbox

# Verify installations
RUN python3 --version \
    && gcc --version \
    && g++ --version \
    && java -version \
    && javac -version \
    && rustc --version \
    && cargo --version

# Default command
CMD ["/bin/bash"]