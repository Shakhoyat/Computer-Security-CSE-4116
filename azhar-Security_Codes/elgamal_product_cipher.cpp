#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int64 egcd(int64 a, int64 b, int64 &x, int64 &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64 x1, y1; int64 g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}

int64 mod_pow(int64 a, int64 e, int64 m) {
    int64 r = 1; a %= m;
    while (e) {
        if (e & 1) r = (__int128)r * a % m;
        a = (__int128)a * a % m;
        e >>= 1;
    }
    return r;
}

int64 modinv(int64 a, int64 m) {
    int64 x, y;
    int64 g = egcd(a, m, x, y);
    if (g != 1) return -1;
    x %= m;
    if (x < 0) x += m;
    return x;
}

int main() {
    int64 p = 467, alpha = 2, a = 123;
    int64 beta = mod_pow(alpha, a, p);
    cout << "Public (p, alpha, beta): (" << p << "," << alpha << "," << beta << ")\n";
    cout << "Private a = " << a << "\n";

    int64 m1 = 5, m2 = 9;
    int64 r1 = 7, r2 = 11;

    int64 C11 = mod_pow(alpha, r1, p);
    int64 C12 = (m1 * mod_pow(beta, r1, p)) % p;

    int64 C21 = mod_pow(alpha, r2, p);
    int64 C22 = (m2 * mod_pow(beta, r2, p)) % p;

    int64 C1p = (C11 * C21) % p;
    int64 C2p = (C12 * C22) % p;

    cout << "Combined Cipher (C1', C2') = (" << C1p << "," << C2p << ")\n";

    int64 s = mod_pow(C1p, a, p);
    int64 s_inv = modinv(s, p);
    int64 m_dec = (C2p * s_inv) % p;

    cout << "Decrypted m' = " << m_dec << "  Expected = " << (m1 * m2) % p << "\n";
}
