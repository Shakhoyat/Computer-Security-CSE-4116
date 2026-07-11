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

    int64 m = 20, r = 7;
    int64 C1 = mod_pow(alpha, r, p);
    int64 C2 = (m * mod_pow(beta, r, p)) % p;
    cout << "Original Cipher (C1, C2) = (" << C1 << "," << C2 << ")\n";

    int64 r2 = 9;
    int64 C1_new = (C1 * mod_pow(alpha, r2, p)) % p;
    int64 C2_new = (C2 * mod_pow(beta, r2, p)) % p;
    cout << "Re-randomized Cipher (C1', C2') = (" << C1_new << "," << C2_new << ")\n";

    int64 s = mod_pow(C1_new, a, p);
    int64 s_inv = modinv(s, p);
    int64 m_dec = (C2_new * s_inv) % p;

    cout << "Decrypted m' = " << m_dec << "  Expected = " << m << "\n";
}
