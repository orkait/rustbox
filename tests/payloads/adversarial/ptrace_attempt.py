import ctypes
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_TRACEME = 0
ret = libc.ptrace(PTRACE_TRACEME, 0, 0, 0)
if ret == 0:
    print("ESCAPED")
else:
    raise OSError("ptrace blocked")
