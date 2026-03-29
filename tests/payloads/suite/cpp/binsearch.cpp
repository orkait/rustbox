#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    int n;
    if (!(cin >> n)) return 0;

    vector<int> arr(n);
    for (int i = 0; i < n; ++i) {
        arr[i] = i * 2;
    }

    int q;
    if (!(cin >> q)) return 0;

    while (q--) {
        int target;
        cin >> target;
        auto it = lower_bound(arr.begin(), arr.end(), target);
        if (it != arr.end() && *it == target) {
            cout << distance(arr.begin(), it) << "\n";
        } else {
            cout << -1 << "\n";
        }
    }

    return 0;
}
