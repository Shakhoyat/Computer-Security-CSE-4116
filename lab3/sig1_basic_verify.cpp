// RSA signatures, file 1: sign/verify baseline.
//   1 sign with d, verify with e     4 tamper the signature
//   2 raw m vs hashed H(M)           5 wrong public key
//   3 tamper the message             6 sign/verify vs encrypt/decrypt
// 10-digit p,q -> n ~20 digits (~67 bits).
// Build: g++ -O2 -std=c++17 -o sig1 sig1_basic_verify.cpp   Run: ./sig1 [seed]
#include <bits/stdc++.h>
using namespace std;
typedef unsigned long long u64;
typedef unsigned __int128 u128;   // n, phi, e, d, m, sig all need more than 64 bits
typedef __int128 i128;            // egcd only: coefficients can go negative

string toStr(u128 x) {            // cout has no idea what __int128 is
    if (!x) return "0";
    string s;
    while (x) { s += char('0' + int(x % 10)); x /= 10; }
    reverse(s.begin(), s.end());
    return s;
}
ostream &operator<<(ostream &os, u128 x) { return os << toStr(x); }

// a*b can overflow __int128 once a,b are close to a 67-bit n, so multiply by
// repeated doubling instead of a straight a*b%m
u128 mulmod(u128 a, u128 b, u128 m) {
    a %= m; b %= m; u128 r = 0;
    while (b) { if (b & 1) { r += a; if (r >= m) r -= m; } a <<= 1; if (a >= m) a -= m; b >>= 1; }
    return r;
}
u128 gcdu(u128 a, u128 b) { while (b) { u128 t = a % b; a = b; b = t; } return a; }
i128 egcd(i128 a, i128 b, i128 &x, i128 &y) {
    if (!b) { x = 1; y = 0; return a; }
    i128 x1, y1, g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}
u128 inverse(u128 a, u128 m) {
    i128 x, y; egcd((i128)a, (i128)m, x, y);
    i128 r = x % (i128)m;
    return (u128)(r < 0 ? r + (i128)m : r);
}

// residue class mod n; '*' is mulmod, '^' is square-and-multiply.
// '^' binds looser than '==' in C++ so it always needs brackets: (a ^ e) == b
struct Mod {
    u128 v, n;
    Mod() : v(0), n(1) {}
    Mod(u128 val, u128 mod) : v(val % mod), n(mod) {}
    Mod operator*(const Mod &b) const { return Mod(mulmod(v, b.v, n), n); }
    Mod operator^(u128 e) const {
        Mod r(1, n), b = *this;
        while (e) { if (e & 1) r = r * b; b = b * b; e >>= 1; }
        return r;
    }
    bool operator==(const Mod &b) const { return v == b.v && n == b.n; }
    bool operator!=(const Mod &b) const { return !(*this == b); }
    Mod inv() const { return Mod(inverse(v, n), n); }
};
ostream &operator<<(ostream &os, const Mod &x) { return os << toStr(x.v); }

bool isPrime(u128 n) {             // deterministic Miller-Rabin, fine well past our sizes
    if (n < 2) return false;
    for (u64 p : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) if (n % p == 0) return n == p;
    u128 d = n - 1; int r = 0;
    while (!(d & 1)) { d >>= 1; r++; }
    for (u64 a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        Mod x = Mod(a, n) ^ d;
        if (x.v == 1 || x.v == n - 1) continue;
        bool composite = true;
        for (int i = 1; i < r; i++) { x = x * x; if (x.v == n - 1) { composite = false; break; } }
        if (composite) return false;
    }
    return true;
}
u64 rngState;
u64 nextRand() {                   // splitmix64
    u64 z = (rngState += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
u128 randPrime(int digits) {
    u64 lo = 1; for (int i = 1; i < digits; i++) lo *= 10;
    while (true) { u64 x = (lo + nextRand() % (9 * lo)) | 1; if (isPrime(x)) return x; }
}

struct Key { u128 p, q, n, phi, e, d; };
Key genKey(int digits = 10, u128 forceE = 0) {
    Key k;
    while (true) {
        do { k.p = randPrime(digits); k.q = randPrime(digits); } while (k.p == k.q);
        k.n = k.p * k.q; k.phi = (k.p - 1) * (k.q - 1);
        if (forceE) { if (gcdu(forceE, k.phi) == 1) { k.e = forceE; break; } continue; }
        k.e = 3; while (gcdu(k.e, k.phi) != 1) k.e += 2;   // walk up till it's coprime to phi
        break;
    }
    k.d = inverse(k.e, k.phi);
    return k;
}
u128 encrypt(u128 m, const Key &k) { return (Mod(m, k.n) ^ k.e).v; }
u128 decrypt(u128 c, const Key &k) { return (Mod(c, k.n) ^ k.d).v; }
u128 sign   (u128 m, const Key &k) { return (Mod(m, k.n) ^ k.d).v; }
bool verify (u128 m, u128 s, u128 n, u128 e) { return (Mod(s, n) ^ e) == Mod(m, n); }

// toy hash (FNV-1a folded into Z_n) standing in for SHA-256 -- the RSA algebra
// below is identical either way, only the quality of the hash changes
u128 H(const string &s, u128 n) {
    u64 h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    u128 r = h % n;
    return r ? r : 1;               // never let a message hash to 0
}
u128 pack(const string &s, u128 n) {
    u128 m = 0; for (unsigned char c : s) m = m * 256 + c;
    m %= n; return m ? m : 1;
}

int passed = 0, failed = 0;
void check(const string &what, bool ok, bool expect = true) {
    bool pass = (ok == expect);
    pass ? passed++ : failed++;
    cout << "    [" << (pass ? "OK  " : "FAIL") << "] " << what;
    if (!pass) cout << "  (expected " << (expect ? "valid" : "invalid") << ")";
    cout << "\n";
}
void summary() { cout << "\n==== " << passed << " passed, " << failed << " failed ====\n"; }

int main(int argc, char **argv) {
    rngState = (argc > 1) ? strtoull(argv[1], 0, 10) : 20260808ULL;
    u64 seed = rngState;
    Key A = genKey(), B = genKey();
    cout << "KEYS (seed " << seed << ")\n";
    cout << "  Alice p=" << A.p << "  q=" << A.q << "\n        n=" << A.n
         << "  (" << toStr(A.n).size() << " digits)\n        phi=" << A.phi
         << "\n        e=" << A.e << "  d=" << A.d << "\n";
    cout << "  Bob   n=" << B.n << "  e=" << B.e << "\n";
    check("e*d = 1 (mod phi)", mulmod(A.e, A.d, A.phi) == 1);

    string msg = "Ashik111: pay 100 to account 42";

    cout << "\n[1] RAW SIGNATURE   s = m^d mod n   verify: s^e == m\n";
    u128 raw = pack(msg, A.n), sRaw = sign(raw, A);
    cout << "    m = " << raw << "\n    s = " << sRaw << "\n";
    check("raw signature under Alice's public key", verify(raw, sRaw, A.n, A.e));

    // raw signing is unsafe for three reasons: (a) it only covers messages < n,
    // so two different messages equal mod n share a signature, (b) it's
    // multiplicative (see file 2), (c) forging a fresh (m,s) pair is free.
    // Hashing first kills (a) and (c), and (b) in practice.
    cout << "\n[2] HASH-THEN-SIGN\n";
    u128 h = H(msg, A.n), s = sign(h, A);
    cout << "    H(M) = " << h << "\n    s    = " << s << "\n";
    check("hashed signature verifies", verify(h, s, A.n, A.e));
    string longMsg = msg + string(200, 'x');
    check("a much longer message still fits the hashed scheme",
          verify(H(longMsg, A.n), sign(H(longMsg, A.n), A), A.n, A.e));

    cout << "\n[3] TAMPERED MESSAGE (signature untouched)\n";
    string t1 = msg; t1.back() = '3';                 // account 42 -> 43
    string t2 = msg.substr(0, msg.size() - 1);         // truncated
    check("one character changed", verify(H(t1, A.n), s, A.n, A.e), false);
    check("message truncated", verify(H(t2, A.n), s, A.n, A.e), false);

    cout << "\n[4] TAMPERED SIGNATURE (message untouched)\n";
    check("s+1", verify(h, s + 1, A.n, A.e), false);
    check("s replaced by another message's signature",
          verify(h, sign(H(t1, A.n), A), A.n, A.e), false);

    cout << "\n[5] WRONG PUBLIC KEY\n";
    check("Alice's sig checked with Bob's (n,e)", verify(H(msg, B.n), s, B.n, B.e), false);
    u128 sB = sign(H(msg, B.n), B);
    check("Bob signs, Bob verifies", verify(H(msg, B.n), sB, B.n, B.e));
    check("Bob signs, Alice verifies", verify(H(msg, A.n), sB, A.n, A.e), false);
    u128 eBad = A.e; do { eBad += 2; } while (gcdu(eBad, A.phi) != 1);
    check("correct n but a different valid e", verify(h, s, A.n, eBad), false);   // n alone isn't the key

    // (m^e)^d = (m^d)^e = m -- same identity, exponents swapped. What differs
    // is the security goal, not the maths: encrypt locks with e, sign locks with d.
    cout << "\n[6] SIGN vs ENCRYPT (same identity, opposite key order)\n";
    u128 m6 = 123456789;
    check("decrypt(encrypt(m)) == m", decrypt(encrypt(m6, A), A) == m6);
    check("verify-direction of sign(m) == m", (Mod(sign(m6, A), A.n) ^ A.e).v == m6);

    summary();
    return failed != 0;
}
