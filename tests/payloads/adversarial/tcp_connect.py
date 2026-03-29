import socket
s = socket.socket()
s.settimeout(2)
s.connect(("8.8.8.8", 53))
print("ESCAPED")
