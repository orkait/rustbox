# ============================================================================
# Judge runtime — extends rustbox-base
# Adds sandbox working directories only. No debug tools, no dev packages.
#
# Run with:
#   docker run --rm \
#     --privileged \
#     --cgroupns host \
#     rustbox-isolate \
#     judge execute-code --strict --box-id 1 --language python --code 'print(1)'
# ============================================================================
FROM rustbox-base:local

# Sandbox working directories
RUN mkdir -p \
    /var/run/rustbox \
    /tmp/rustbox/submissions \
    /tmp/rustbox/output

CMD ["/usr/local/bin/judge"]
