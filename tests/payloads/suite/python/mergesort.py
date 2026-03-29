import sys, random
n, seed = map(int, sys.stdin.readline().split())
random.seed(seed)
arr = [random.randint(0, n) for _ in range(n)]
arr.sort()
print(' '.join(map(str, arr[:5])))
print(' '.join(map(str, arr[-5:])))
