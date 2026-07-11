#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int64 mul_mod(int64 a, int64 b, int64 m) {
    return (int64)((__int128)a * b % m);
}
int64 mod_pow(int64 a, int64 e, int64 m) {
    int64 r = 1; a %= m;
    while (e) {
        if (e & 1) r = mul_mod(r, a, m);
        a = mul_mod(a, a, m);
        e >>= 1;
    }
    return r;
}
int64 egcd(int64 a, int64 b, int64 &x, int64 &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    int64 x1, y1;
    int64 g = egcd(b, a % b, x1, y1);
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
    int64 p = 61, q = 53;
    int64 n = p * q;
    int64 phi = (p - 1) * (q - 1);
    int64 e = 17;
    int64 d = modinv(e, phi);

    cout << "Public key (n, e): (" << n << ", " << e << ")\n";
    cout << "Private key (d): " << d << "\n";

    int64 m1 = 65, m2 = 77;
    int64 c1 = mod_pow(m1, e, n), c2 = mod_pow(m2, e, n);
    cout << "Enc(m1)=" << c1 << " Enc(m2)=" << c2 << "\n";

    int64 cprod = mul_mod(c1, c2, n);
    cout << "Combined ciphertext = " << cprod << "\n";

    int64 dec = mod_pow(cprod, d, n);
    cout << "Decrypted product: " << dec << " (expected " << (m1 * m2) % n << ")\n";
}
