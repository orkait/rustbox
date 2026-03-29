import sys
a = sys.stdin.readline().strip()
b = sys.stdin.readline().strip()
n, m = len(a), len(b)
prev = [0] * (m + 1)
for i in range(1, n + 1):
    cur = [0] * (m + 1)
    for j in range(1, m + 1):
        if a[i-1] == b[j-1]: cur[j] = prev[j-1] + 1
        else: cur[j] = max(prev[j], cur[j-1])
    prev = cur
print(prev[m])
