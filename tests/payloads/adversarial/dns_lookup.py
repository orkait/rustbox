import socket
addr = socket.getaddrinfo("google.com", 80)
print("ESCAPED:", addr)
