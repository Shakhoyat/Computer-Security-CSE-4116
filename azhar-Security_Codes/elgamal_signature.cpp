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
    int64 x, y;
    int64 g = egcd(a, m, x, y);
    if (g != 1) return -1;
    x %= m;
    if (x < 0) x += m;
    return x;
}

int main() {
    int64 p = 467, alpha = 2, a = 127;
    int64 beta = mod_pow(alpha, a, p);
    cout << "Public key (p, alpha, beta): (" << p << ", " << alpha << ", " << beta << ")\n";
    cout << "Private key a = " << a << "\n";

    int64 M;
    cout << "Enter message (integer): ";
    cin >> M;

    int64 r = 5;
    if (__gcd(r, p - 1) != 1) {
        cout << "r not coprime to p-1\n";
        return 0;
    }

    int64 y1 = mod_pow(alpha, r, p);
    int64 r_inv = modinv(r, p - 1);
    int64 y2 = (r_inv * (M - a * y1)) % (p - 1);
    if (y2 < 0) y2 += (p - 1);

    cout << "Signature (y1, y2) = (" << y1 << ", " << y2 << ")\n";

    int64 left = mod_pow(alpha, M, p);
    int64 right = (__int128)mod_pow(beta, y1, p) * mod_pow(y1, y2, p) % p;

    cout << (left == right ? "Signature VALID\n" : " Signature INVALID\n");
}
