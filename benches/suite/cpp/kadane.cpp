#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n;
    long long seed;
    if (!(cin >> n >> seed)) return 0;

    mt19937 rng(seed);
    uniform_int_distribution<int> dist(-1000, 1000);

    vector<int> arr(n);
    for (int i = 0; i < n; ++i) {
        arr[i] = dist(rng);
    }

    long long cur = arr[0];
    long long mx = arr[0];

    for (int i = 1; i < n; ++i) {
        cur = max((long long)arr[i], cur + arr[i]);
        mx = max(mx, cur);
    }

    cout << mx << endl;

    return 0;
}
