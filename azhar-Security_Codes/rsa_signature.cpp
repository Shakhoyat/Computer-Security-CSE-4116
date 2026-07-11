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
    x %= m; if (x < 0) x += m;
    return x;
}

int main() {
    int64 p = 61, q = 53;
    int64 n = p * q, phi = (p - 1) * (q - 1);
    int64 e = 17, d = modinv(e, phi);
    cout << "Public (n, e): (" << n << ", " << e << ")\nPrivate d: " << d << "\n";

    int64 message;
    cout << "Enter message (integer): ";
    cin >> message;

    int64 sign = mod_pow(message, d, n);
    cout << "Signature: " << sign << "\n";

    int64 verify = mod_pow(sign, e, n);
    cout << "Verification result: " << verify << (verify == message ? " Valid\n" : " Invalid\n");
}
