# Isolate image for building Rustbox with language dependencies
FROM rustbox-base:latest

# Switch back to root for installation
USER root

# Install additional build dependencies and security tools
RUN apt-get update && apt-get install -y \
    # Build tools
    autoconf \
    automake \
    libtool \
    pkg-config \
    # Security and isolation tools
    libseccomp-dev \
    libseccomp2 \
    # Additional development tools
    valgrind \
    gdb \
    strace \
    # Network tools
    netcat-openbsd \
    telnet \
    # File system tools
    rsync \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages for building
RUN pip3 install --no-cache-dir \
    setuptools \
    wheel \
    pytest \
    black \
    flake8 \
    mypy

# Create isolate directories
RUN mkdir -p /isolate/{bin,etc,lib,run,box} \
    && chown -R rustbox:rustbox /isolate

# Copy isolate configuration (JSON format)
COPY --chown=rustbox:rustbox isolate.json /isolate/etc/
COPY --chown=rustbox:rustbox limits.json /isolate/etc/

# Set up isolate environment
ENV ISOLATE_PATH=/isolate
ENV ISOLATE_BOX=/isolate/box
ENV ISOLATE_RUN=/isolate/run

# Create test directories with proper permissions
RUN mkdir -p /tmp/rustbox/{submissions,tests,output} \
    && chown -R rustbox:rustbox /tmp/rustbox \
    && chmod 755 /tmp/rustbox

# Switch back to rustbox user
USER rustbox

# Verify the environment
RUN echo "Isolate environment setup complete" \
    && ls -la /isolate/ \
    && python3 -c "import sys; print('Python path:', sys.path)" \
    && rustc --version

# Default command
CMD ["/bin/bash"]