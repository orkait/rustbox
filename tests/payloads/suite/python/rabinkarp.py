import sys
parts = sys.stdin.readline().split()
length, pattern = int(parts[0]), parts[1]
text = pattern * length
base, mod = 31, 10**9 + 7
m, n = len(pattern), len(text)
ph = th = 0; power = 1
for i in range(m):
    ph = (ph * base + ord(pattern[i])) % mod
    th = (th * base + ord(text[i])) % mod
    if i > 0: power = (power * base) % mod
count = 0
for i in range(n - m + 1):
    if ph == th: count += 1
    if i + m < n:
        th = (th * base - ord(text[i]) * power * base + ord(text[i + m])) % mod
print(count)
