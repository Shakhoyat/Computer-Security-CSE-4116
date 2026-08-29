// ElGamal cryptosystem, file 1: key generation, encryption, decryption.
//   0 the theory-sheet example verbatim   p=11 D=3 E1=2 E2=8 PT=7 R=4 -> (5,6)
//   1 the same five steps on a 100-bit safe prime
//   2 decryption two ways: (C1^D)^-1  and  C1^(p-1-D)   [Fermat, no ext-Euclid]
//   3 fresh R every time -> same PT gives a different cipher on every run
//   4 the range rules: PT must be < p, R = 0 leaks the plaintext
// Naming follows the theory sheet exactly:
//   p large prime | D private/decryption key | E1 primitive root | E2 = E1^D mod p
//   public key = (E1, E2, p)   private key = D   cipher text = (C1, C2)
// Build: g++ -O2 -std=c++17 -o eg1 elgamal_v1_basic.cpp   Run: ./eg1 [seed]
#include <bits/stdc++.h>
using namespace std;

// ---------- 128-bit modular core (identical in every lab4 file) ----------
typedef unsigned long long u64;
typedef unsigned __int128  u128;   // p, E1, E2, D, R, C1, C2 all outgrow 64 bits
typedef __int128           i128;   // egcd only: its coefficients go negative

string toStr(u128 x) {             // cout has no idea what __int128 is
    if (!x) return "0";
    string s;
    while (x) { s += char('0' + int(x % 10)); x /= 10; }
    reverse(s.begin(), s.end());
    return s;
}
ostream &operator<<(ostream &os, u128 x) { return os << toStr(x); }
int digitCount(u128 x) { return (int)toStr(x).size(); }
int bitLen(u128 x) { int b = 0; while (x) { b++; x >>= 1; } return b; }

// a*b overflows u128 as soon as p passes 64 bits, so multiply by repeated
// doubling: O(log b) additions, never a value wider than the modulus.
u128 mulmod(u128 a, u128 b, u128 m) {
    a %= m; b %= m; u128 r = 0;
    while (b) { if (b & 1) { r += a; if (r >= m) r -= m; } a <<= 1; if (a >= m) a -= m; b >>= 1; }
    return r;
}
u128 powmod(u128 a, u128 e, u128 m) {          // square-and-multiply
    u128 r = 1; a %= m;
    while (e) { if (e & 1) r = mulmod(r, a, m); a = mulmod(a, a, m); e >>= 1; }
    return r;
}
u128 gcdu(u128 a, u128 b) { while (b) { u128 t = a % b; a = b; b = t; } return a; }
i128 egcd(i128 a, i128 b, i128 &x, i128 &y) {
    if (!b) { x = 1; y = 0; return a; }
    i128 x1, y1, g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}
u128 inverse(u128 a, u128 m) {                 // a^-1 mod m, assumes gcd(a,m)=1
    i128 x, y; egcd((i128)(a % m), (i128)m, x, y);
    i128 r = x % (i128)m;
    return (u128)(r < 0 ? r + (i128)m : r);
}

u64 rngState;
u64 nextRand() {                               // splitmix64
    u64 z = (rngState += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
u128 rand128() { return ((u128)nextRand() << 64) | nextRand(); }
u128 randRange(u128 lo, u128 hi) { return lo + rand128() % (hi - lo + 1); }   // inclusive

bool isPrime(u128 n) {                         // Miller-Rabin
    if (n < 2) return false;
    for (u64 d = 2; d < 1000; d += (d == 2 ? 1 : 2))
        if (n % d == 0) return n == d;         // cheap trial-division sieve first
    u128 d = n - 1; int r = 0;
    while (!(d & 1)) { d >>= 1; r++; }
    auto composite = [&](u128 a) {             // true if a witnesses n composite
        u128 x = powmod(a, d, n);
        if (x == 1 || x == n - 1) return false;
        for (int i = 1; i < r; i++) { x = mulmod(x, x, n); if (x == n - 1) return false; }
        return true;
    };
    for (u64 a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37})
        if (composite(a)) return false;        // this base set alone is exact below 3.3e24
    for (int i = 0; i < 8; i++)                // random bases past that: error < 4^-8
        if (composite(randRange(2, n - 2))) return false;
    return true;
}
u128 randBits(int bits) {                      // odd, exactly `bits` long
    u128 x = rand128() & ((((u128)1) << bits) - 1);
    return x | (((u128)1) << (bits - 1)) | 1;
}
// safe prime p = 2q+1: the only subgroup orders are 1, 2, q, 2q, so there is
// nowhere small for an attacker to push the discrete log into (Pohlig-Hellman)
u128 safePrime(int bits) {
    while (true) {
        u128 q = randBits(bits - 1);
        if (!isPrime(q)) continue;
        u128 p = 2 * q + 1;
        if (isPrime(p)) return p;
    }
}
// with p = 2q+1, g is a primitive root iff g^2 != 1 and g^q != 1
u128 primitiveRoot(u128 p, u128 q) {
    for (u128 g = 2;; g++)
        if (powmod(g, 2, p) != 1 && powmod(g, q, p) != 1) return g;
}

// ---------- ElGamal, named as on the theory sheet ----------
struct Key {
    u128 p;      // 1. large prime
    u128 D;      // 2. decryption / private key
    u128 E1;     // 3. 2nd part of the encryption / public key (primitive root of p)
    u128 E2;     // 4. 3rd part of the public key: E2 = E1^D mod p
    u128 q;      // (p-1)/2, kept around so R can be drawn safely
};
struct Cipher { u128 C1, C2; };

Key keyGen(int bits) {                         // Bob's five steps
    Key K;
    K.p  = safePrime(bits);
    K.q  = (K.p - 1) / 2;
    K.E1 = primitiveRoot(K.p, K.q);
    K.D  = randRange(2, K.p - 3);              // 1 <= D <= p-2
    K.E2 = powmod(K.E1, K.D, K.p);             // E2 = E1^D mod p
    return K;
}
u128 pickR(const Key &K) { return randRange(2, K.p - 3); }

Cipher encrypt(u128 PT, u128 R, const Key &K) {
    Cipher C;
    C.C1 = powmod(K.E1, R, K.p);                        // C1 = E1^R mod p
    C.C2 = mulmod(PT % K.p, powmod(K.E2, R, K.p), K.p); // C2 = PT * E2^R mod p
    return C;
}
u128 decrypt(const Cipher &C, const Key &K) {           // PT = [C2 * (C1^D)^-1] mod p
    u128 s = powmod(C.C1, K.D, K.p);
    return mulmod(C.C2, inverse(s, K.p), K.p);
}
u128 decryptFermat(const Cipher &C, const Key &K) {     // PT = C2 * C1^(p-1-D) mod p
    return mulmod(C.C2, powmod(C.C1, K.p - 1 - K.D, K.p), K.p);
}

// ---------- tiny test harness ----------
int passed = 0, failed = 0;
void check(const string &what, bool ok, bool expect = true) {
    bool pass = (ok == expect);
    pass ? passed++ : failed++;
    cout << "    [" << (pass ? "OK  " : "FAIL") << "] " << what;
    if (!pass) cout << "  (expected " << (expect ? "true" : "false") << ")";
    cout << "\n";
}
void summary() { cout << "\n==== " << passed << " passed, " << failed << " failed ====\n"; }

int main(int argc, char **argv) {
    rngState = (argc > 1) ? strtoull(argv[1], 0, 10) : 20260829ULL;
    u64 seed = rngState;

    cout << "[0] THE THEORY-SHEET EXAMPLE, STEP FOR STEP\n";
    {
        Key T; T.p = 11; T.D = 3; T.E1 = 2; T.q = 5;
        T.E2 = powmod(T.E1, T.D, T.p);
        cout << "    Bob: p=" << T.p << "  D=" << T.D << "  E1=" << T.E1
             << "  E2 = E1^D mod p = " << T.E2 << "\n";
        cout << "    public key (E1,E2,p) = (" << T.E1 << "," << T.E2 << "," << T.p
             << ")   private key D = " << T.D << "\n";
        u128 PT = 7, R = 4;
        Cipher C = encrypt(PT, R, T);
        cout << "    Alice: PT=" << PT << "  R=" << R
             << "  ->  C1 = E1^R = " << C.C1 << "   C2 = PT*E2^R = " << C.C2 << "\n";
        check("cipher is (5,6), matching the hand calculation", C.C1 == 5 && C.C2 == 6);
        u128 s = powmod(C.C1, T.D, T.p);
        cout << "    Bob:   C1^D = " << s << "   (C1^D)^-1 = " << inverse(s, T.p)
             << "   PT = C2*(C1^D)^-1 = " << decrypt(C, T) << "\n";
        check("decryption returns 7", decrypt(C, T) == PT);
    }

    cout << "\n[1] KEY GENERATION ON A 100-BIT SAFE PRIME (seed " << seed << ")\n";
    Key K = keyGen(100);
    cout << "    p  = " << K.p << "   (" << digitCount(K.p) << " digits, " << bitLen(K.p) << " bits)\n";
    cout << "    q  = (p-1)/2 = " << K.q << "\n";
    cout << "    E1 = " << K.E1 << "   (primitive root of p)\n";
    cout << "    D  = " << K.D << "\n";
    cout << "    E2 = " << K.E2 << "\n";
    check("p is prime", isPrime(K.p));
    check("q = (p-1)/2 is prime, so p is a safe prime", isPrime(K.q));
    check("E1^(p-1) = 1 mod p  (Fermat)", powmod(K.E1, K.p - 1, K.p) == 1);
    check("E1 has full order p-1, not q", powmod(K.E1, K.q, K.p) != 1);
    // this product is what kills 64-bit code: p ~ 2^100, so p*p ~ 2^200
    cout << "    note: p*p would need " << 2 * bitLen(K.p)
         << " bits -- that is why every multiply goes through mulmod()\n";

    cout << "\n[2] ENCRYPTION   C1 = E1^R mod p,  C2 = PT * E2^R mod p\n";
    u128 PT = 0;
    for (unsigned char c : string("Ashik-2k21")) PT = PT * 256 + c;   // pack text into one number
    PT %= K.p;
    u128 R = pickR(K);
    Cipher C = encrypt(PT, R, K);
    cout << "    PT = " << PT << "\n    R  = " << R << "\n";
    cout << "    C1 = " << C.C1 << "\n    C2 = " << C.C2 << "\n";
    check("PT < p, so nothing wraps", PT < K.p);

    cout << "\n[3] DECRYPTION   PT = [C2 * (C1^D)^-1] mod p\n";
    cout << "    recovered = " << decrypt(C, K) << "\n";
    check("Bob recovers PT", decrypt(C, K) == PT);
    // why it works: C1^D = (E1^R)^D = (E1^D)^R = E2^R, the exact mask C2 carries
    check("C1^D == E2^R   (same mask, reached from either side)",
          powmod(C.C1, K.D, K.p) == powmod(K.E2, R, K.p));
    Key wrong = K; wrong.D = K.D + 1;
    check("a wrong D gives garbage", decrypt(C, wrong) == PT, false);

    cout << "\n[4] SAME THING WITHOUT EXTENDED EUCLID   PT = C2 * C1^(p-1-D) mod p\n";
    // Fermat: C1^(p-1) = 1, so C1^(p-1-D) is already the inverse of C1^D
    cout << "    recovered = " << decryptFermat(C, K) << "\n";
    check("Fermat route agrees with the ext-Euclid route", decryptFermat(C, K) == decrypt(C, K));

    cout << "\n[5] FRESH R EVERY TIME (this is what textbook RSA does not give you)\n";
    Cipher a = encrypt(PT, pickR(K), K), b = encrypt(PT, pickR(K), K);
    cout << "    run 1: (" << a.C1 << ", " << a.C2 << ")\n";
    cout << "    run 2: (" << b.C1 << ", " << b.C2 << ")\n";
    check("same PT, two ciphers that do not match", a.C1 == b.C1 && a.C2 == b.C2, false);
    check("both still decrypt to PT", decrypt(a, K) == PT && decrypt(b, K) == PT);

    cout << "\n[6] THE RANGE RULES\n";
    Cipher over = encrypt(PT + K.p, pickR(K), K);        // PT+p is congruent to PT
    check("PT >= p comes back as sent", decrypt(over, K) == PT + K.p, false);
    check("...it comes back as PT mod p instead", decrypt(over, K) == PT);
    Cipher r0 = encrypt(PT, 0, K);                       // R=0 -> E1^0 = 1, E2^0 = 1
    cout << "    R = 0 gives (C1,C2) = (" << r0.C1 << ", " << r0.C2 << ")\n";
    check("R = 0 leaves the plaintext sitting in C2 in the clear", r0.C2 == PT);

    summary();
    return failed != 0;
}
