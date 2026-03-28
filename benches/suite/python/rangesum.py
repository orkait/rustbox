import sys, random
input = sys.stdin.readline
n, q, seed = map(int, input().split())
random.seed(seed)
arr = [random.randint(1, 1000) for _ in range(n)]
prefix = [0] * (n + 1)
for i in range(n):
    prefix[i + 1] = prefix[i] + arr[i]
random.seed(seed + 1)
out = []
for _ in range(q):
    l = random.randint(0, n - 1)
    r = random.randint(l, min(l + 1000, n - 1))
    out.append(str(prefix[r + 1] - prefix[l]))
print('\n'.join(out))
