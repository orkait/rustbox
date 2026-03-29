f = open("/tmp/bomb", "wb")
try:
    while True:
        f.write(b"A" * (1024 * 1024))
        f.flush()
except OSError as e:
    print(f"blocked: {e}")
    raise
