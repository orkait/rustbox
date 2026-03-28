#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n, q;
    long long seed;
    if (!(cin >> n >> q >> seed)) return 0;

    mt19937 rng(seed);
    uniform_int_distribution<int> dist(1, 1000);

    vector<int> arr(n);
    for (int i = 0; i < n; ++i) {
        arr[i] = dist(rng);
    }

    vector<long long> prefix(n + 1, 0);
    for (int i = 0; i < n; ++i) {
        prefix[i + 1] = prefix[i] + arr[i];
    }

    mt19937 rng2(seed + 1);
    uniform_int_distribution<int> dist_l(0, n - 1);

    for (int i = 0; i < q; ++i) {
        int l = dist_l(rng2);
        int max_r = min(l + 1000, n - 1);
        uniform_int_distribution<int> dist_r(l, max_r);
        int r = dist_r(rng2);
        cout << (prefix[r + 1] - prefix[l]) << "\n";
    }

    return 0;
}
