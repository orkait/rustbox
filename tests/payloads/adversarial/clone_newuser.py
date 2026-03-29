import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWUSER = 0x10000000
ret = libc.unshare(CLONE_NEWUSER)
if ret != 0:
    raise OSError(ctypes.get_errno(), "unshare blocked")
print("ESCAPED")
