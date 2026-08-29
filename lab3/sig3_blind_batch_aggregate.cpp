// RSA signatures, file 3: blind, batch, aggregate, ordering.
//   1 blind signature protocol (blind / sign / unblind / verify)
//   2 unlinkability -- the signer's transcript matches no released pair
//   3 batch verification -- the naive product test is unsound
//   4 small-exponents batch test (the standard fix)
//   5 aggregate: one signature covering many documents
//   6 sign-then-encrypt vs encrypt-then-sign (surreptitious forwarding)
// Build: g++ -O2 -std=c++17 -o sig3 sig3_blind_batch_aggregate.cpp   Run: ./sig3 [seed]
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
    Key A = genKey(), B = genKey(), C = genKey();
    cout << "seed " << seed << "   Alice n=" << A.n << " e=" << A.e
         << "\n                Bob   n=" << B.n << " e=" << B.e
         << "\n                Carol n=" << C.n << " e=" << C.e << "\n";

    // blind:   M' = H(M) * r^e mod n
    // sign:    S' = M'^d  = H(M)^d * r^(e*d) = H(M)^d * r
    // unblind: S  = S' * r^-1 = H(M)^d
    // Used for e-cash / e-voting: the authority signs a ballot it never reads.
    cout << "\n[1] BLIND SIGNATURE (Bob signs a ballot he cannot read)\n";
    string ballot = "ballot#7741: candidate C";
    u128 hb = H(ballot, B.n), r;
    do { r = 2 + (u128)(nextRand() % 1000000007ULL); } while (gcdu(r, B.n) != 1);
    Mod blinded = Mod(hb, B.n) * (Mod(r, B.n) ^ B.e);
    Mod sBlind  = blinded ^ B.d;                 // Bob's entire view of the protocol
    Mod S       = sBlind * Mod(r, B.n).inv();    // voter unblinds
    cout << "    r = " << r << "\n    Bob sees M' = " << blinded
         << "\n    Bob returns S'= " << sBlind << "\n    voter holds S = " << S << "\n";
    check("unblinded signature verifies under Bob's key", verify(hb, S.v, B.n, B.e));
    check("S equals a direct signature on H(M)", S.v == sign(hb, B));

    cout << "\n[2] UNLINKABILITY\n";
    check("what Bob signed != the published message", blinded.v == hb, false);
    check("what Bob returned != the published signature", sBlind.v == S.v, false);
    u128 r2; do { r2 = 2 + (u128)(nextRand() % 1000000007ULL); } while (gcdu(r2, B.n) != 1);
    Mod blinded2 = Mod(hb, B.n) * (Mod(r2, B.n) ^ B.e);
    check("same ballot, new r -> a completely different transcript", blinded2.v == blinded.v, false);
    cout << "        note: a blind signer must never reuse that key for ordinary\n"
            "        documents, or a caller can smuggle in the attack from file 2 [4].\n";

    // naive batch: (prod s_i)^e == prod h_i -- one exponentiation instead of k
    cout << "\n[3] BATCH VERIFICATION (naive product test)\n";
    const int K = 5;
    string docs[K] = {"invoice #1", "invoice #2", "invoice #3", "invoice #4", "invoice #5"};
    u128 hs[K], ss[K];
    for (int i = 0; i < K; i++) { hs[i] = H(docs[i], A.n); ss[i] = sign(hs[i], A); }
    Mod pS(1, A.n), pH(1, A.n);
    for (int i = 0; i < K; i++) { pS = pS * Mod(ss[i], A.n); pH = pH * Mod(hs[i], A.n); }
    check("naive batch, 5 honest signatures", (pS ^ A.e) == pH);
    // swapping two signatures leaves the PRODUCT unchanged -- the batch still
    // passes even though neither swapped pair is individually valid
    swap(ss[0], ss[1]);
    Mod pS2(1, A.n); for (int i = 0; i < K; i++) pS2 = pS2 * Mod(ss[i], A.n);
    check("naive batch still passes after swapping s0 and s1", (pS2 ^ A.e) == pH);
    check("but pair 0 individually is invalid", verify(hs[0], ss[0], A.n, A.e), false);
    check("and pair 1 individually is invalid", verify(hs[1], ss[1], A.n, A.e), false);

    // prod (s_i^v_i)^e == prod (h_i^v_i), fresh random v_i each run
    cout << "\n[4] RANDOMIZED BATCH (small-exponents test)\n";
    u64 v[K]; for (int i = 0; i < K; i++) v[i] = 1 + nextRand() % 65536;
    Mod wS(1, A.n), wH(1, A.n);
    for (int i = 0; i < K; i++) { wS = wS * (Mod(ss[i], A.n) ^ v[i]); wH = wH * (Mod(hs[i], A.n) ^ v[i]); }
    check("randomized batch catches the swap", (wS ^ A.e) == wH, false);
    swap(ss[0], ss[1]);                          // restore the honest set
    Mod wS2(1, A.n), wH2(1, A.n);
    for (int i = 0; i < K; i++) { wS2 = wS2 * (Mod(ss[i], A.n) ^ v[i]); wH2 = wH2 * (Mod(hs[i], A.n) ^ v[i]); }
    check("randomized batch on the honest set", (wS2 ^ A.e) == wH2);
    cout << "        cost: 1 big exponentiation + k tiny ones, instead of k big ones.\n";

    // chain the per-document hashes, sign the chain head once -- order and
    // membership are both bound into that one signature
    cout << "\n[5] AGGREGATE SIGNATURE (5 documents, 1 signature)\n";
    string chain; for (int i = 0; i < K; i++) chain += toStr(H(docs[i], A.n)) + "|";
    u128 hAgg = H(chain, A.n), sAgg = sign(hAgg, A);
    cout << "    chain head = " << hAgg << "   signature = " << sAgg << "\n";
    check("aggregate verifies over the full ordered set", verify(hAgg, sAgg, A.n, A.e));
    string reorder; for (int i = K - 1; i >= 0; i--) reorder += toStr(H(docs[i], A.n)) + "|";
    check("same 5 docs, reordered", verify(H(reorder, A.n), sAgg, A.n, A.e), false);
    string dropped; for (int i = 0; i < K - 1; i++) dropped += toStr(H(docs[i], A.n)) + "|";
    check("one document dropped", verify(H(dropped, A.n), sAgg, A.n, A.e), false);

    // sign-then-encrypt: Alice sends sign_A(M) encrypted to Bob. Bob decrypts,
    // re-encrypts the SAME signed message to Carol -- Carol wrongly concludes
    // Alice wrote to her. The signature is genuine; the recipient isn't bound to it.
    cout << "\n[6] MESSAGE ORDERING (surreptitious forwarding)\n";
    string conf = "Ashik111: confidential offer";
    u128 hConf = H(conf, A.n), sConf = sign(hConf, A);
    u128 toBob = encrypt(pack(conf, B.n), B);
    check("Bob decrypts and the signature checks out",
          decrypt(toBob, B) == pack(conf, B.n) && verify(hConf, sConf, A.n, A.e));
    u128 toCarol = encrypt(pack(conf, C.n), C);   // Bob forwards, signature untouched
    check("Carol decrypts Bob's forward", decrypt(toCarol, C) == pack(conf, C.n));
    check("Carol still sees a VALID Alice signature", verify(hConf, sConf, A.n, A.e));
    cout << "        -> Carol wrongly believes the offer was addressed to her.\n";
    u128 hBound = H(conf + "|to:" + toStr(B.n), A.n), sBound = sign(hBound, A);   // fix: bind the recipient
    check("recipient-bound signature checks out for Bob", verify(hBound, sBound, A.n, A.e));
    check("same signature checked as if addressed to Carol",
          verify(H(conf + "|to:" + toStr(C.n), A.n), sBound, A.n, A.e), false);

    summary();
    return failed != 0;
}
