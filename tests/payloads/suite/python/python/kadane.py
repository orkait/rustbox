import sys, random
n, seed = map(int, sys.stdin.readline().split())
random.seed(seed)
arr = [random.randint(-1000, 1000) for _ in range(n)]
cur = mx = arr[0]
for x in arr[1:]:
    cur = max(x, cur + x)
    mx = max(mx, cur)
print(mx)
