#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    int n;
    if (!(cin >> n)) return 0;
    if (n < 2) {
        cout << 0 << endl;
        return 0;
    }
    vector<char> s(n + 1, 1);
    s[0] = s[1] = 0;
    int limit = sqrt(n);
    for (int i = 2; i <= limit; ++i) {
        if (s[i]) {
            for (int j = i * i; j <= n; j += i) {
                s[j] = 0;
            }
        }
    }
    long long count = 0;
    for (int i = 0; i <= n; ++i) {
        if (s[i]) count++;
    }
    cout << count << endl;
    return 0;
}
