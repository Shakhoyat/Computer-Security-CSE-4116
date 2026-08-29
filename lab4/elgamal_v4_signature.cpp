// ElGamal cryptosystem, file 4: digital signature (sign with D, verify with E1,E2,p).
//   1 sign / verify, and the algebra that makes V1 == V2
//   2 raw M vs hashed H(M), and why M >= p-1 silently collides
//   3 tampered message, tampered signature, wrong public key
//   4 R reused on two messages -> the private key D falls out. No factoring needed.
//   5 existential forgery when nobody hashes: valid (M, S1, S2) with no key at all
//   6 the rules on R: fresh, secret, and coprime to p-1
// Naming follows the theory sheet:
//   p prime | D private key | E1 primitive root | E2 = E1^D mod p
//   signature = (S1, S2)   verification values = (V1, V2)
// Sign   : S1 = E1^R mod p,  S2 = (M - D*S1) * R^-1 mod (p-1)
// Verify : V1 = E1^M mod p,  V2 = E2^S1 * S1^S2 mod p,  accept iff V1 == V2
// Build: g++ -O2 -std=c++17 -o eg4 elgamal_v4_signature.cpp   Run: ./eg4 [seed]
#include <bits/stdc++.h>
using namespace std;

// ---------- 128-bit modular core (identical in every lab4 file) ----------
typedef unsigned long long u64;
typedef unsigned __int128  u128;
typedef __int128           i128;

string toStr(u128 x) {
    if (!x) return "0";
    string s;
    while (x) { s += char('0' + int(x % 10)); x /= 10; }
    reverse(s.begin(), s.end());
    return s;
}
ostream &operator<<(ostream &os, u128 x) { return os << toStr(x); }
int digitCount(u128 x) { return (int)toStr(x).size(); }

u128 mulmod(u128 a, u128 b, u128 m) {          // a*b would overflow u128 once p > 64 bits
    a %= m; b %= m; u128 r = 0;
    while (b) { if (b & 1) { r += a; if (r >= m) r -= m; } a <<= 1; if (a >= m) a -= m; b >>= 1; }
    return r;
}
u128 powmod(u128 a, u128 e, u128 m) {
    u128 r = 1; a %= m;
    while (e) { if (e & 1) r = mulmod(r, a, m); a = mulmod(a, a, m); e >>= 1; }
    return r;
}
u128 submod(u128 a, u128 b, u128 m) { a %= m; b %= m; return (a + m - b) % m; }   // a-b, no negatives
u128 gcdu(u128 a, u128 b) { while (b) { u128 t = a % b; a = b; b = t; } return a; }
i128 egcd(i128 a, i128 b, i128 &x, i128 &y) {
    if (!b) { x = 1; y = 0; return a; }
    i128 x1, y1, g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}
u128 inverse(u128 a, u128 m) {
    i128 x, y; egcd((i128)(a % m), (i128)m, x, y);
    i128 r = x % (i128)m;
    return (u128)(r < 0 ? r + (i128)m : r);
}
// a*x = b (mod n) when gcd(a,n) may be > 1: needed by the R-reuse attack, because
// p-1 is even so half the coefficients we hit are not invertible mod p-1.
vector<u128> solveLinear(u128 a, u128 b, u128 n, u128 cap = 64) {
    a %= n; b %= n;
    u128 g = gcdu(a, n);
    if (b % g || g > cap) return {};                    // no solution, or too many to enumerate
    u128 nn = n / g, x0 = mulmod(inverse(a / g, nn), (b / g) % nn, nn);
    vector<u128> out;
    for (u128 k = 0; k < g; k++) out.push_back(x0 + k * nn);
    return out;
}

u64 rngState;
u64 nextRand() {
    u64 z = (rngState += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
u128 rand128() { return ((u128)nextRand() << 64) | nextRand(); }
u128 randRange(u128 lo, u128 hi) { return lo + rand128() % (hi - lo + 1); }

bool isPrime(u128 n) {
    if (n < 2) return false;
    for (u64 d = 2; d < 1000; d += (d == 2 ? 1 : 2))
        if (n % d == 0) return n == d;
    u128 d = n - 1; int r = 0;
    while (!(d & 1)) { d >>= 1; r++; }
    auto composite = [&](u128 a) {
        u128 x = powmod(a, d, n);
        if (x == 1 || x == n - 1) return false;
        for (int i = 1; i < r; i++) { x = mulmod(x, x, n); if (x == n - 1) return false; }
        return true;
    };
    for (u64 a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) if (composite(a)) return false;
    for (int i = 0; i < 8; i++) if (composite(randRange(2, n - 2))) return false;
    return true;
}
u128 randBits(int bits) {
    u128 x = rand128() & ((((u128)1) << bits) - 1);
    return x | (((u128)1) << (bits - 1)) | 1;
}
u128 safePrime(int bits) {
    while (true) {
        u128 q = randBits(bits - 1);
        if (!isPrime(q)) continue;
        u128 p = 2 * q + 1;
        if (isPrime(p)) return p;
    }
}
u128 primitiveRoot(u128 p, u128 q) {
    for (u128 g = 2;; g++)
        if (powmod(g, 2, p) != 1 && powmod(g, q, p) != 1) return g;
}

// ---------- ElGamal signature, named as on the theory sheet ----------
struct Key { u128 p, D, E1, E2, q; };
struct Sig  { u128 S1, S2; };

Key keyGen(int bits) {
    Key K;
    K.p  = safePrime(bits);
    K.q  = (K.p - 1) / 2;
    K.E1 = primitiveRoot(K.p, K.q);
    K.D  = randRange(2, K.p - 3);
    K.E2 = powmod(K.E1, K.D, K.p);
    return K;
}
// R must be invertible mod p-1, so gcd(R, p-1) = 1. p-1 = 2q, so R must be odd
// and must not be a multiple of q.
u128 pickR(const Key &K) {
    while (true) { u128 R = randRange(2, K.p - 3); if (gcdu(R, K.p - 1) == 1) return R; }
}
Sig sign(u128 M, u128 R, const Key &K) {
    u128 n = K.p - 1;
    Sig S;
    S.S1 = powmod(K.E1, R, K.p);                                    // S1 = E1^R mod p
    S.S2 = mulmod(submod(M, mulmod(K.D, S.S1, n), n), inverse(R, n), n);  // S2 = (M - D*S1)/R
    return S;
}
bool verify(u128 M, const Sig &S, u128 E1, u128 E2, u128 p) {
    if (S.S1 == 0 || S.S1 >= p) return false;                       // range check, else forgeable
    u128 V1 = powmod(E1, M, p);                                     // V1 = E1^M mod p
    u128 V2 = mulmod(powmod(E2, S.S1, p), powmod(S.S1, S.S2, p), p);// V2 = E2^S1 * S1^S2 mod p
    return V1 == V2;
}
// toy hash (FNV-1a folded into Z_(p-1)) standing in for SHA-256. The algebra is
// the same either way; only the strength of the hash changes.
u128 H(const string &s, u128 p) {
    u64 h = 1469598103934665603ULL;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ULL; }
    u128 r = (u128)h % (p - 1);
    return r ? r : 1;
}

// ---------- tiny test harness ----------
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
    rngState = (argc > 1) ? strtoull(argv[1], 0, 10) : 20260829ULL;
    u64 seed = rngState;

    cout << "[1] KEYS (seed " << seed << ")\n";
    Key K = keyGen(100), Other = keyGen(100);
    cout << "    p  = " << K.p << "   (" << digitCount(K.p) << " digits)\n";
    cout << "    public (E1, E2, p) = (" << K.E1 << ", " << K.E2 << ", " << K.p << ")\n";
    cout << "    private D = " << K.D << "\n";
    check("E2 = E1^D mod p", powmod(K.E1, K.D, K.p) == K.E2);

    cout << "\n[2] SIGN AND VERIFY\n";
    string msg = "Ashik111: pay 100 to account 42";
    u128 M = H(msg, K.p), R = pickR(K);
    Sig S = sign(M, R, K);
    cout << "    H(M) = " << M << "\n    R    = " << R << "\n";
    cout << "    S1 = E1^R mod p            = " << S.S1 << "\n";
    cout << "    S2 = (M - D*S1)*R^-1 mod p-1 = " << S.S2 << "\n";
    cout << "    V1 = " << powmod(K.E1, M, K.p) << "\n";
    cout << "    V2 = " << mulmod(powmod(K.E2, S.S1, K.p), powmod(S.S1, S.S2, K.p), K.p) << "\n";
    check("signature verifies", verify(M, S, K.E1, K.E2, K.p));
    // why: R*S2 + D*S1 = M (mod p-1), so E1^(R*S2) * E1^(D*S1) = E1^M,
    // i.e. S1^S2 * E2^S1 = E1^M. That is exactly V2 == V1.
    check("R*S2 + D*S1 = M  (mod p-1)",
          (mulmod(R, S.S2, K.p - 1) + mulmod(K.D, S.S1, K.p - 1)) % (K.p - 1) == M % (K.p - 1));
    check("gcd(R, p-1) = 1, so R^-1 exists mod p-1", gcdu(R, K.p - 1) == 1);

    cout << "\n[3] RAW M vs HASHED H(M)\n";
    u128 raw = 0;
    for (unsigned char c : msg) raw = raw * 256 + c;
    raw %= (K.p - 1);
    check("a raw packed message signs and verifies too", verify(raw, sign(raw, pickR(K), K), K.E1, K.E2, K.p));
    // but the exponent E1^M only ever sees M mod (p-1), so M and M+(p-1) are the
    // same message as far as the maths is concerned
    check("M + (p-1) is accepted by the signature on M",
          verify(raw + (K.p - 1), sign(raw, pickR(K), K), K.E1, K.E2, K.p));
    string longMsg = msg + string(500, 'x');
    check("hashing lets a 500-byte message fit the scheme",
          verify(H(longMsg, K.p), sign(H(longMsg, K.p), pickR(K), K), K.E1, K.E2, K.p));

    cout << "\n[4] TAMPERING\n";
    string t1 = msg; t1.back() = '3';                   // account 42 -> 43
    check("one character changed in the message", verify(H(t1, K.p), S, K.E1, K.E2, K.p), false);
    check("S1 bumped by 1", verify(M, {S.S1 + 1, S.S2}, K.E1, K.E2, K.p), false);
    check("S2 bumped by 1", verify(M, {S.S1, S.S2 + 1}, K.E1, K.E2, K.p), false);
    check("S1 and S2 swapped", verify(M, {S.S2, S.S1}, K.E1, K.E2, K.p), false);
    check("checked against somebody else's public key",
          verify(M, S, Other.E1, Other.E2, Other.p), false);
    check("S1 = 0 rejected by the range check", verify(M, {0, S.S2}, K.E1, K.E2, K.p), false);

    cout << "\n[5] R REUSED ON TWO MESSAGES -> PRIVATE KEY RECOVERED\n";
    // Alice signs two different messages but forgets to draw a fresh R.
    u128 Rbad = pickR(K);
    u128 Ma = H("transfer 100 to Bob", K.p), Mb = H("transfer 999 to Eve", K.p);
    Sig Sa = sign(Ma, Rbad, K), Sb = sign(Mb, Rbad, K);
    cout << "    same R used twice, so S1 is identical in both: " << (Sa.S1 == Sb.S1 ? "yes" : "no") << "\n";
    check("Eve spots the repeat straight from the two signatures", Sa.S1 == Sb.S1);
    // S2a - S2b = (Ma - Mb) * R^-1  (mod p-1)   ->  R = (Ma - Mb) * (S2a - S2b)^-1
    u128 n = K.p - 1;
    u128 foundR = 0, foundD = 0;
    for (u128 cand : solveLinear(submod(Sa.S2, Sb.S2, n), submod(Ma, Mb, n), n))
        if (powmod(K.E1, cand, K.p) == Sa.S1) foundR = cand;        // confirm against S1
    cout << "    recovered R = " << foundR << "\n";
    check("Eve recovers the nonce R", foundR == Rbad);
    // then D*S1 = Ma - R*S2a  (mod p-1)  ->  D
    for (u128 cand : solveLinear(Sa.S1, submod(Ma, mulmod(foundR, Sa.S2, n), n), n))
        if (powmod(K.E1, cand, K.p) == K.E2) foundD = cand;         // confirm against E2
    cout << "    recovered D = " << foundD << "\n    actual    D = " << K.D << "\n";
    check("Eve recovers the private key D", foundD == K.D);
    Sig forged = sign(H("transfer 1000000 to Eve", K.p), pickR(K), { K.p, foundD, K.E1, K.E2, K.q });
    check("Eve now signs anything she likes",
          verify(H("transfer 1000000 to Eve", K.p), forged, K.E1, K.E2, K.p));
    // exactly the bug that broke the PS3 (ECDSA, same nonce every time)

    cout << "\n[6] EXISTENTIAL FORGERY WHEN NOBODY HASHES\n";
    // Eve has only (E1, E2, p). She cannot pick the message, but she can produce
    // SOME message plus a signature that verifies:
    //   S1 = E1^a * E2^b,  S2 = -S1*b^-1 mod p-1,  M = a*S2 mod p-1
    u128 a = randRange(2, n - 1), b;
    do { b = randRange(2, n - 1); } while (gcdu(b, n) != 1);
    u128 fS1 = mulmod(powmod(K.E1, a, K.p), powmod(K.E2, b, K.p), K.p);
    u128 fS2 = mulmod(submod(0, fS1, n), inverse(b, n), n);
    u128 fM  = mulmod(a, fS2, n);
    cout << "    forged M  = " << fM << "\n    forged S1 = " << fS1 << "\n    forged S2 = " << fS2 << "\n";
    check("a forged triple verifies against Alice's public key",
          verify(fM, {fS1, fS2}, K.E1, K.E2, K.p));
    check("but Eve did not choose fM -- it fell out of a and b", fM == mulmod(a, fS2, n));
    // the fix: verifiers must check a signature on H(M), and Eve would have to
    // find a message hashing to fM -- a preimage, which SHA-256 does not give her
    check("no readable message is known to hash to fM", H(msg, K.p) == fM, false);

    cout << "\n[7] THE RULES ON R\n";
    u128 Reven = 2 * randRange(2, K.q - 1);          // p-1 = 2q, so every even R shares the 2
    check("an even R is illegal: gcd(R, p-1) = 2, so R^-1 mod p-1 does not exist",
          gcdu(Reven, K.p - 1) == 1, false);
    check("pickR() only ever hands back a coprime R", gcdu(pickR(K), K.p - 1) == 1);
    u128 Rgood = pickR(K);
    check("a fresh R gives a different S1 each time", sign(M, Rgood, K).S1 == S.S1, false);
    check("...and both signatures verify", verify(M, sign(M, Rgood, K), K.E1, K.E2, K.p));
    // and R must stay secret: given R, D = (M - R*S2) * S1^-1 mod (p-1), one line
    u128 leaked = 0;
    for (u128 cand : solveLinear(S.S1, submod(M, mulmod(R, S.S2, n), n), n))
        if (powmod(K.E1, cand, K.p) == K.E2) leaked = cand;
    check("leaking R for a single signature already gives away D", leaked == K.D);

    summary();
    return failed != 0;
}
