import sys
from collections import deque
n = int(sys.stdin.readline())
adj = [[] for _ in range(n)]
for i in range(n - 1):
    adj[i].append(i + 1)
    adj[i + 1].append(i)
for i in range(0, n - 2, 2):
    adj[i].append(i + 2)
    adj[i + 2].append(i)
dist = [-1] * n
dist[0] = 0
q = deque([0])
while q:
    u = q.popleft()
    for v in adj[u]:
        if dist[v] == -1:
            dist[v] = dist[u] + 1
            q.append(v)
print(dist[n - 1])
