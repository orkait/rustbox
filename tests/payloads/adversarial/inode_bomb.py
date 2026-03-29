import os
try:
    for i in range(100000):
        open(f"/tmp/f{i}", "w").close()
except OSError as e:
    print(f"blocked at {i}: {e}")
    raise
