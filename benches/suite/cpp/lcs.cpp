#include<bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    string a, b;
    getline(cin, a);
    getline(cin, b);
    
    // Remove potential carriage return from Windows-style input
    if (!a.empty() && a.back() == '\r') a.pop_back();
    if (!b.empty() && b.back() == '\r') b.pop_back();
    
    int n = a.length();
    int m = b.length();
    
    vector<int> prev(m + 1, 0);
    for (int i = 1; i <= n; ++i) {
        vector<int> cur(m + 1, 0);
        for (int j = 1; j <= m; ++j) {
            if (a[i - 1] == b[j - 1]) {
                cur[j] = prev[j - 1] + 1;
            } else {
                cur[j] = max(prev[j], cur[j - 1]);
            }
        }
        prev = move(cur);
    }
    cout << prev[m] << endl;
    return 0;
}
