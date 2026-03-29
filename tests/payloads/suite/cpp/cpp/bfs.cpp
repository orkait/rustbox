#include<bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n;
    if (!(cin >> n)) return 0;

    vector<vector<int>> adj(n);
    for (int i = 0; i < n - 1; ++i) {
        adj[i].push_back(i + 1);
        adj[i + 1].push_back(i);
    }
    for (int i = 0; i <= n - 3; i += 2) {
        adj[i].push_back(i + 2);
        adj[i + 2].push_back(i);
    }

    vector<int> dist(n, -1);
    dist[0] = 0;
    queue<int> q;
    q.push(0);

    while (!q.empty()) {
        int u = q.front();
        q.pop();
        for (int v : adj[u]) {
            if (dist[v] == -1) {
                dist[v] = dist[u] + 1;
                q.push(v);
            }
        }
    }

    cout << dist[n - 1] << endl;

    return 0;
}
