#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n;
    unsigned int seed;
    if (!(cin >> n >> seed)) return 0;

    mt19937 rng(seed);
    vector<int> arr(n);
    for (int i = 0; i < n; ++i) {
        uniform_int_distribution<int> dist(0, n);
        arr[i] = dist(rng);
    }

    sort(arr.begin(), arr.end());

    for (int i = 0; i < 5; ++i) {
        cout << arr[i] << (i == 4 ? "" : " ");
    }
    cout << "\n";

    for (int i = 0; i < 5; ++i) {
        cout << arr[n - 5 + i] << (i == 4 ? "" : " ");
    }
    cout << endl;

    return 0;
}
