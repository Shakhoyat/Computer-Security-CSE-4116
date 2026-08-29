// Multiple messages, file 3: attacks that need more than one message.
//   1 determinism -- equal plaintexts are visible in the ciphertext list
//   2 homomorphic product of two ciphertexts, and a chosen-ciphertext attack
//   3 common modulus -- same n, two exponents, same message
//   4 Hastad broadcast -- same m to 3 recipients with e=3, CRT + cube root
//   5 fixes
// Build: g++ -O2 -std=c++17 -o m3 multi3_multi_message_attacks.cpp   Run: ./m3 [seed]
#include <bits/stdc++.h>
using namespace std;
typedef unsigned long long u64;
typedef unsigned __int128 u128;
typedef __int128 i128;

string toStr(u128 x) {
    if (!x) return "0";
    string s;
    while (x) { s += char('0' + int(x % 10)); x /= 10; }
    reverse(s.begin(), s.end());
    return s;
}
ostream &operator<<(ostream &os, u128 x) { return os << toStr(x); }

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

bool isPrime(u128 n) {
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
u64 nextRand() {
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
        k.e = 3; while (gcdu(k.e, k.phi) != 1) k.e += 2;
        break;
    }
    k.d = inverse(k.e, k.phi);
    return k;
}
u128 encrypt(u128 m, const Key &k) { return (Mod(m, k.n) ^ k.e).v; }
u128 decrypt(u128 c, const Key &k) { return (Mod(c, k.n) ^ k.d).v; }

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

// integer cube root by binary search; hi is capped so mid^3 can't overflow u128
u128 icbrt(u128 x) {
    u128 lo = 0, hi = (u128)1 << 42;
    while (lo < hi) {
        u128 mid = lo + (hi - lo + 1) / 2;
        if (mid * mid * mid <= x) lo = mid; else hi = mid - 1;
    }
    return lo;
}

int main(int argc, char **argv) {
    rngState = (argc > 1) ? strtoull(argv[1], 0, 10) : 20260808ULL;
    u64 seed = rngState;
    Key B = genKey();
    cout << "seed " << seed << "   Bob n=" << B.n << "  e=" << B.e << "\n";

    cout << "\n[1] DETERMINISM (Eve sees ciphertexts only)\n";
    const int N = 5;
    string msgs[N] = {"YES", "NO", "YES", "ABSTAIN", "YES"};
    u128 c[N]; for (int i = 0; i < N; i++) c[i] = encrypt(pack(msgs[i], B.n), B);
    for (int i = 0; i < N; i++) cout << "    vote " << i << " -> " << c[i] << "\n";
    int equalPairs = 0;
    for (int i = 0; i < N; i++) for (int j = i + 1; j < N; j++) if (c[i] == c[j]) equalPairs++;
    check("Eve learns which votes are equal without decrypting", equalPairs == 3);
    // the vote space is tiny, so she just encrypts every option herself with
    // the public key and matches -- a dictionary attack
    const char *opts[3] = {"YES", "NO", "ABSTAIN"}; int solved = 0;
    for (int i = 0; i < N; i++) for (int o = 0; o < 3; o++)
        if (encrypt(pack(opts[o], B.n), B) == c[i] && msgs[i] == opts[o]) solved++;
    check("small message space -> full dictionary recovery", solved == N);
    cout << "        fix: randomized padding (OAEP) -- two encryptions of the\n"
            "        same plaintext must produce unrelated ciphertexts.\n";

    // (m1*m2)^e = m1^e * m2^e, so ciphertexts multiply. Eve can't read m1, but
    // she can hand the decryption oracle a disguised version of it.
    cout << "\n[2] HOMOMORPHIC PRODUCT / CHOSEN-CIPHERTEXT\n";
    u128 m1 = 111111111, m2 = 222222222;
    Mod C1(encrypt(m1, B), B.n), C2(encrypt(m2, B), B.n);
    check("c1*c2 mod n decrypts to m1*m2 mod n", decrypt((C1 * C2).v, B) == mulmod(m1, m2, B.n));
    u128 secret = pack("Ashik111 secret", B.n), cSec = encrypt(secret, B);
    u128 r; do { r = 2 + (u128)(nextRand() % 1000000007ULL); } while (gcdu(r, B.n) != 1);
    Mod blinded = Mod(cSec, B.n) * (Mod(r, B.n) ^ B.e);   // looks like a fresh ciphertext
    check("the oracle sees no match with the target ciphertext", blinded.v == cSec, false);
    u128 oracleOut = decrypt(blinded.v, B);
    u128 recovered = mulmod(oracleOut, inverse(r, B.n), B.n);
    cout << "    oracle returned " << oracleOut << "  -> divide by r -> " << recovered << "\n";
    check("Eve recovers the target plaintext from the oracle", recovered == secret);

    // two users share n but have different e. Same m sent to both:
    // a*e1 + b*e2 = 1  =>  c1^a * c2^b = m^(a*e1+b*e2) = m. One of a,b comes
    // out negative, so that side needs a modular inverse.
    cout << "\n[3] COMMON MODULUS (same n, e1 != e2, same message)\n";
    Key U = genKey(); u128 n = U.n, e1 = 17, e2 = 65537;
    while (gcdu(e1, U.phi) != 1) e1 += 2;
    while (gcdu(e2, U.phi) != 1 || gcdu(e1, e2) != 1) e2 += 2;
    u128 m = pack("meet at 9pm", n);
    u128 cc1 = (Mod(m, n) ^ e1).v, cc2 = (Mod(m, n) ^ e2).v;
    i128 a, b; egcd((i128)e1, (i128)e2, a, b);
    cout << "    e1=" << e1 << " e2=" << e2 << "   a*e1+b*e2 = "
         << (long long)(a * (i128)e1 + b * (i128)e2) << "\n";
    Mod P1 = (a >= 0) ? (Mod(cc1, n) ^ (u128)a) : (Mod(cc1, n) ^ (u128)(-a)).inv();
    Mod P2 = (b >= 0) ? (Mod(cc2, n) ^ (u128)b) : (Mod(cc2, n) ^ (u128)(-b)).inv();
    check("common-modulus recovery of m with no private key", (P1 * P2).v == m);
    cout << "        recovered " << (P1 * P2) << "  (true m = " << m << ")\n";

    // c_i = m^3 mod n_i, coprime n_i. CRT gives m^3 mod n1*n2*n3, and since
    // m < min(n_i), m^3 < n1*n2*n3 -- the modulus never wraps, so an ordinary
    // integer cube root returns m. Three 10-digit-prime moduli would multiply
    // past what unsigned __int128 holds, so this demo uses 6-digit primes.
    cout << "\n[4] HASTAD BROADCAST (e=3, deliberately 6-digit primes -- see note)\n";
    // a pool of only ~68k 6-digit primes means two of the three keys really
    // can collide on a prime; CRT would then silently give a wrong answer, so
    // re-roll until the three moduli are actually coprime
    Key R[3];
    while (true) {
        for (int i = 0; i < 3; i++) R[i] = genKey(6, 3);
        if (gcdu(R[0].n, R[1].n) == 1 && gcdu(R[0].n, R[2].n) == 1 && gcdu(R[1].n, R[2].n) == 1) break;
    }
    u128 NN = R[0].n * R[1].n * R[2].n;
    u128 smallestN = min({R[0].n, R[1].n, R[2].n});
    u128 msg4 = pack("PASS", smallestN);
    cout << "    n1=" << R[0].n << " n2=" << R[1].n << " n3=" << R[2].n
         << "\n    product = " << NN << "   m = " << msg4 << "\n";
    check("m < every modulus, so m^3 < n1*n2*n3", msg4 * msg4 * msg4 < NN);
    u128 cs[3]; for (int i = 0; i < 3; i++) cs[i] = encrypt(msg4, R[i]);
    Mod X(0, NN);
    for (int i = 0; i < 3; i++) {
        u128 Ni = NN / R[i].n;
        u128 yi = inverse(Ni % R[i].n, R[i].n);
        X = Mod(X.v + mulmod(mulmod(cs[i], Ni, NN), yi, NN), NN);
    }
    cout << "    CRT gives m^3 = " << X << "\n";
    u128 root = icbrt(X.v);
    cout << "    integer cube root -> m = " << root << "\n";
    check("Hastad recovers m from 3 ciphertexts, no private key", root == msg4);

    cout << "\n[5] FIXES\n"
            "    [1] deterministic  -> OAEP random padding\n"
            "    [2] homomorphic    -> OAEP; never decrypt attacker-chosen ciphertexts\n"
            "    [3] common modulus -> every user gets their own n, never a shared one\n"
            "    [4] broadcast e=3  -> e=65537 and per-recipient random padding, so the\n"
            "                          'same m' the attack needs never actually exists\n";

    summary();
    return failed != 0;
}
