import sys, heapq, random
input = sys.stdin.readline
n, target_m, seed, num_q = map(int, input().split())
random.seed(seed)
adj = [[] for _ in range(n)]
for i in range(n - 1):
    w = random.randint(1, 100)
    adj[i].append((i + 1, w))
    adj[i + 1].append((i, w))
added = n - 1
while added < target_m:
    u = random.randint(0, n - 2)
    v = random.randint(u + 1, min(u + 50, n - 1))
    w = random.randint(1, 100)
    adj[u].append((v, w))
    adj[v].append((u, w))
    added += 1
dist = [float('inf')] * n
dist[0] = 0
pq = [(0, 0)]
while pq:
    d, u = heapq.heappop(pq)
    if d > dist[u]: continue
    for v, w in adj[u]:
        if dist[u] + w < dist[v]:
            dist[v] = dist[u] + w
            heapq.heappush(pq, (dist[v], v))
random.seed(seed + 1)
out = []
for _ in range(num_q):
    t = random.randint(1, n - 1)
    out.append(str(int(dist[t]) if dist[t] != float('inf') else -1))
print('\n'.join(out))
