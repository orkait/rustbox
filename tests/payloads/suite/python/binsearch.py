import sys, bisect
input = sys.stdin.readline
n = int(input())
arr = list(range(0, n * 2, 2))
q = int(input())
out = []
for _ in range(q):
    target = int(input())
    idx = bisect.bisect_left(arr, target)
    out.append(str(idx if idx < n and arr[idx] == target else -1))
print('\n'.join(out))
