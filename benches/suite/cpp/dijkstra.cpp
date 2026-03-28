#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n, target_m, seed, num_q;
    if (!(cin >> n >> target_m >> seed >> num_q)) return 0;

    mt19937 rng(seed);
    vector<vector<pair<int, int>>> adj(n);

    for (int i = 0; i < n - 1; ++i) {
        int w = uniform_int_distribution<int>(1, 100)(rng);
        adj[i].push_back({i + 1, w});
        adj[i + 1].push_back({i, w});
    }

    int added = n - 1;
    while (added < target_m) {
        int u = uniform_int_distribution<int>(0, n - 2)(rng);
        int v = uniform_int_distribution<int>(u + 1, min(u + 50, n - 1))(rng);
        int w = uniform_int_distribution<int>(1, 100)(rng);
        adj[u].push_back({v, w});
        adj[v].push_back({u, w});
        added++;
    }

    const long long INF = numeric_limits<long long>::max();
    vector<long long> dist(n, INF);
    dist[0] = 0;
    priority_queue<pair<long long, int>, vector<pair<long long, int>>, greater<pair<long long, int>>> pq;
    pq.push({0, 0});

    while (!pq.empty()) {
        long long d = pq.top().first;
        int u = pq.top().second;
        pq.pop();

        if (d > dist[u]) continue;
        for (auto& edge : adj[u]) {
            int v = edge.first;
            int w = edge.second;
            if (dist[u] + w < dist[v]) {
                dist[v] = dist[u] + w;
                pq.push({dist[v], v});
            }
        }
    }

    mt19937 rng2(seed + 1);
    for (int i = 0; i < num_q; ++i) {
        int t = uniform_int_distribution<int>(1, n - 1)(rng2);
        if (dist[t] == INF) {
            cout << -1 << "\n";
        } else {
            cout << dist[t] << "\n";
        }
    }

    return 0;
}
