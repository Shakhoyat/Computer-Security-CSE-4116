// RSA signatures, file 2: forgery without the private key.
//   1 existential forgery (pick the signature first)
//   2 trivial fixed points (0 and 1 sign to themselves)
//   3 multiplicative forgery: sign(m1*m2) = sign(m1)*sign(m2)
//   4 chosen-message attack through a blinding oracle
//   5 the same attacks re-run against hash-then-sign
// Build: g++ -O2 -std=c++17 -o sig2 sig2_forgery.cpp   Run: ./sig2 [seed]
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
u128 sign   (u128 m, const Key &k) { return (Mod(m, k.n) ^ k.d).v; }
bool verify (u128 m, u128 s, u128 n, u128 e) { return (Mod(s, n) ^ e) == Mod(m, n); }

u128 H(const string &s, u128 n) {
    u64 h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    u128 r = h % n;
    return r ? r : 1;
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
    Key A = genKey();
    cout << "Alice (seed " << seed << ")  n=" << A.n << "  e=" << A.e
         << "\n  Eve knows ONLY (n,e); d=" << A.d << " is never touched below.\n";

    // Eve doesn't choose the message -- she picks the signature and derives a
    // message that fits it. Enough to fool a verifier that checks raw m, not H(M).
    cout << "\n[1] EXISTENTIAL FORGERY (raw signing)\n";
    u128 sPick = 987654321, mDerived = (Mod(sPick, A.n) ^ A.e).v;
    cout << "    Eve picks s = " << sPick << "  ->  m = s^e mod n = " << mDerived << "\n";
    check("raw verifier accepts the pair (m,s)", verify(mDerived, sPick, A.n, A.e));
    check("hashed verifier needs a message with H(M)=m", H("anything", A.n) == mDerived, false);

    // 0^d = 0 and 1^d = 1 under every key, so these two "signatures" are valid
    // everywhere. H() forced off 0 kills the first; padding kills the second.
    cout << "\n[2] TRIVIAL FIXED POINTS\n";
    check("(m=0, s=0) verifies under Alice's key", verify(0, 0, A.n, A.e));
    check("(m=1, s=1) verifies under Alice's key", verify(1, 1, A.n, A.e));
    check("H() never returns 0", H("", A.n) == 0, false);

    // (m1*m2)^d = m1^d * m2^d -- two signatures Eve has seen multiply into one
    // she was never given.
    cout << "\n[3] MULTIPLICATIVE FORGERY\n";
    u128 m1 = pack("invoice A", A.n), m2 = pack("invoice B", A.n);
    Mod S1(sign(m1, A), A.n), S2(sign(m2, A), A.n);
    Mod M12 = Mod(m1, A.n) * Mod(m2, A.n), S12 = S1 * S2;
    cout << "    m1*m2 mod n = " << M12 << "\n    forged sig  = " << S12
         << "   (no private key touched)\n";
    check("forged signature on m1*m2 verifies", verify(M12.v, S12.v, A.n, A.e));
    check("same trick fails against hash-then-sign",
          verify(H("invoice Ainvoice B", A.n), S12.v, A.n, A.e), false);

    // Alice runs a signing service but refuses one message T. Eve blinds T with
    // random r: T' = T * r^e mod n looks like noise, so the filter lets it
    // through. Alice returns s' = T'^d = T^d * r; Eve divides by r.
    cout << "\n[4] CHOSEN-MESSAGE ATTACK (blinding oracle)\n";
    u128 target = pack("pay Eve 1000000", A.n);
    u128 r; do { r = 2 + (u128)(nextRand() % 1000000007ULL); } while (gcdu(r, A.n) != 1);
    Mod blinded = Mod(target, A.n) * (Mod(r, A.n) ^ A.e);
    cout << "    target T  = " << target << "\n    blinded T'= " << blinded << "\n";
    Mod sBlind = blinded ^ A.d;                 // Alice's oracle signs the blinded value
    Mod forged = sBlind * Mod(r, A.n).inv();    // Eve unblinds
    check("unblinded forgery verifies on the REFUSED message", verify(target, forged.v, A.n, A.e));
    check("it equals what Alice would have produced directly", forged.v == sign(target, A));
    cout << "        fix: never sign attacker-supplied raw values -- hash first,\n"
            "        and use PSS so the signed block has verifiable structure.\n";

    cout << "\n[5] HASH-THEN-SIGN SCOREBOARD\n";
    string doc = "Ashik111 statement";
    u128 hd = H(doc, A.n), sd = sign(hd, A);
    check("honest hashed signature still verifies", verify(hd, sd, A.n, A.e));
    check("existential forgery needs a hash preimage", H(doc, A.n) == mDerived, false);
    check("product forgery needs H(M3)=H(M1)*H(M2)",
          H(doc, A.n) == mulmod(H("invoice A", A.n), H("invoice B", A.n), A.n), false);
    cout << "        note: blinding (attack 4) still works on a hashed value if the\n"
            "        signer accepts a pre-hashed number -- the signer must hash it\n"
            "        himself, never trust a hash handed in by the caller.\n";

    summary();
    return failed != 0;
}
