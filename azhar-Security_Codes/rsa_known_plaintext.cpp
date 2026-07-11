#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int64 mod_pow(int64 a, int64 e, int64 m) {
    int64 r = 1; a %= m;
    while (e) {
        if (e & 1) r = (__int128)r * a % m;
        a = (__int128)a * a % m;
        e >>= 1;
    }
    return r;
}
int64 egcd(int64 a, int64 b, int64 &x, int64 &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64 x1, y1; int64 g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}
int64 modinv(int64 a, int64 m) {
    int64 x, y; int64 g = egcd(a, m, x, y);
    if (g != 1) return -1;
    x %= m; if (x < 0) x += m;
    return x;
}

int main() {
    int64 p, q;
    cout << "Enter prime p and q: ";
    cin >> p >> q;

    int64 n = p * q;
    int64 phi = (p - 1) * (q - 1);
    cout << "n = " << n << ", phi = " << phi << "\n";

    int64 e;
    cout << "Enter public exponent e (0 for auto): ";
    cin >> e;
    if (e == 0) {
        e = 2;
        while (__gcd(e, phi) != 1) ++e;
        cout << "Auto-selected e = " << e << "\n";
    } else if (__gcd(e, phi) != 1) {
        cout << "e and phi(n) not coprime.\n";
        return 0;
    }

    int64 d = modinv(e, phi);
    if (d == -1) {
        cout << "No modular inverse for e mod phi.\n";
        return 0;
    }

    cout << "Private exponent d = " << d << "\n";

    vector<long long> dd;
    for (long long k = 1; k < phi; ++k) {
        if ((1 + k * phi) % e == 0) {
            long long d_cand = (1 + k * phi) / e;
            dd.push_back(d_cand);
            if ((int)dd.size() >= 8) break;
        }
    }

    cout << "Candidate d values: ";
    for (long long v : dd) cout << v << " ";
    cout << "\n";

    long long m;
    cout << "Enter plaintext m: ";
    cin >> m;
    long long c = mod_pow(m, e, n);
    cout << "Ciphertext c = " << c << "\n";

    for (long long i = 1; i <= phi; ++i) {
        if (mod_pow(c, i, n) == m) {
            cout << "Found exponent i = " << i << " (possible d)\n";
            break;
        }
    }

    cout << "Decrypted: " << mod_pow(c, d, n) << "\n";
}
