#include<bits/stdc++.h>
using namespace std;

int n;
int count_solutions = 0;
vector<bool> cols, d1, d2;

void bt(int row) {
    if (row == n) {
        count_solutions++;
        return;
    }
    for (int col = 0; col < n; ++col) {
        if (!cols[col] && !d1[row - col + n] && !d2[row + col]) {
            cols[col] = d1[row - col + n] = d2[row + col] = true;
            bt(row + 1);
            cols[col] = d1[row - col + n] = d2[row + col] = false;
        }
    }
}

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    if (!(cin >> n)) return 0;
    cols.assign(n, false);
    d1.assign(2 * n, false);
    d2.assign(2 * n, false);
    bt(0);
    cout << count_solutions << endl;
    return 0;
}
