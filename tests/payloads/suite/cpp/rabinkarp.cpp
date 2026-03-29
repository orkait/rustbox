#include <bits/stdc++.h>
using namespace std;

int main() {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);

    long long length;
    string pattern;
    if (!(cin >> length >> pattern)) return 0;

    string text = "";
    for (int i = 0; i < length; ++i) {
        text += pattern;
    }

    long long base = 31;
    long long mod = 1e9 + 7;
    long long m = pattern.length();
    long long n = text.length();

    long long ph = 0, th = 0, power = 1;
    for (int i = 0; i < m; ++i) {
        ph = (ph * base + (long long)pattern[i]) % mod;
        th = (th * base + (long long)text[i]) % mod;
        if (i > 0) power = (power * base) % mod;
    }

    long long count = 0;
    for (int i = 0; i <= n - m; ++i) {
        if (ph == th) count++;
        if (i + m < n) {
            th = (th * base - (long long)text[i] * power * base + (long long)text[i + m]) % mod;
            if (th < 0) th += mod;
        }
    }

    cout << count << endl;

    return 0;
}
