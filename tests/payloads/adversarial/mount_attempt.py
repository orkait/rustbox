import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
ret = libc.mount(b"/tmp", b"/mnt", b"tmpfs", 0, None)
if ret == 0:
    print("ESCAPED")
else:
    raise OSError("mount blocked")
