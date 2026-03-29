import sys
n = int(sys.stdin.readline())
s = bytearray(b"\x01") * (n + 1)
s[0] = s[1] = 0
for i in range(2, int(n**0.5) + 1):
    if s[i]:
        s[i*i::i] = bytearray(len(s[i*i::i]))
print(sum(s))
