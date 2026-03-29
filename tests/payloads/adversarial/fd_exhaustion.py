fds = []
try:
    while True:
        fds.append(open("/dev/null"))
except OSError as e:
    print(f"blocked at {len(fds)} fds: {e}")
    raise
