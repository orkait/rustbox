import ctypes
size = 512 * 1024 * 1024
buf = ctypes.create_string_buffer(size)
for i in range(0, size, 4096):
    buf[i] = 65
