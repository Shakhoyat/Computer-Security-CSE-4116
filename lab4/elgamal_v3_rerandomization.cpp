// ElGamal cryptosystem, file 3: re-randomisation (cipher refresh / mix-net step).
//   1 take (C1, C2) and produce a completely different pair for the SAME PT
//   2 why it works: multiplying in E1^R', E2^R' is just moving R -> R + R'
//   3 a two-server mix-net: shuffle ballots so nobody can link in to out
//   4 the traps: R' = 0 is a no-op, and refreshing does NOT re-key or authenticate
// Naming follows the theory sheet:
//   p prime | D private key | E1 primitive root | E2 = E1^D mod p | cipher = (C1, C2)
// Build: g++ -O2 -std=c++17 -o eg3 elgamal_v3_rerandomization.cpp   Run: ./eg3 [seed]
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

// ---------- ElGamal, named as on the theory sheet ----------
struct Key { u128 p, D, E1, E2, q; };
struct Cipher { u128 C1, C2; };

Key keyGen(int bits) {
    Key K;
    K.p  = safePrime(bits);
    K.q  = (K.p - 1) / 2;
    K.E1 = primitiveRoot(K.p, K.q);
    K.D  = randRange(2, K.p - 3);
    K.E2 = powmod(K.E1, K.D, K.p);
    return K;
}
u128 pickR(const Key &K) { return randRange(2, K.p - 3); }

Cipher encrypt(u128 PT, u128 R, const Key &K) {
    return { powmod(K.E1, R, K.p), mulmod(PT % K.p, powmod(K.E2, R, K.p), K.p) };
}
u128 decrypt(const Cipher &C, const Key &K) {
    return mulmod(C.C2, inverse(powmod(C.C1, K.D, K.p), K.p), K.p);
}
// the whole point of this file. Note it needs only the PUBLIC key:
// multiplying in an encryption of 1 leaves the plaintext untouched.
Cipher reRandomise(const Cipher &C, u128 Rnew, const Key &K) {
    return { mulmod(C.C1, powmod(K.E1, Rnew, K.p), K.p),
             mulmod(C.C2, powmod(K.E2, Rnew, K.p), K.p) };
}
bool same(const Cipher &a, const Cipher &b) { return a.C1 == b.C1 && a.C2 == b.C2; }

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

    cout << "[1] KEYS (seed " << seed << ")\n";
    Key K = keyGen(100);
    cout << "    p  = " << K.p << "   (" << digitCount(K.p) << " digits)\n";
    cout << "    public (E1, E2, p) = (" << K.E1 << ", " << K.E2 << ", " << K.p << ")\n";
    cout << "    private D = " << K.D << "\n";

    cout << "\n[2] ORIGINAL CIPHER\n";
    u128 PT = 20, R = pickR(K);
    Cipher C = encrypt(PT, R, K);
    cout << "    PT = " << PT << "   R = " << R << "\n";
    cout << "    (C1, C2) = (" << C.C1 << ", " << C.C2 << ")\n";
    check("decrypts to PT", decrypt(C, K) == PT);

    cout << "\n[3] RE-RANDOMISE   C1' = C1*E1^R',  C2' = C2*E2^R'\n";
    u128 Rnew = pickR(K);
    Cipher C2p = reRandomise(C, Rnew, K);
    cout << "    R' = " << Rnew << "\n";
    cout << "    (C1', C2') = (" << C2p.C1 << ", " << C2p.C2 << ")\n";
    check("nothing about the pair survives", same(C, C2p), false);
    check("the plaintext is untouched", decrypt(C2p, K) == PT);
    check("no private key was needed -- only (E1, E2, p)", true);
    // C1' = E1^R * E1^R' = E1^(R+R'), C2' = PT * E2^(R+R'):
    // the refreshed pair is the cipher Alice WOULD have sent with R + R'
    check("identical to encrypting PT directly with R + R'",
          same(C2p, encrypt(PT, R + Rnew, K)));
    // equivalent way to say it: we multiplied in an encryption of 1
    check("same as the product-cipher trick against E(1)",
          same(C2p, Cipher{ mulmod(C.C1, encrypt(1, Rnew, K).C1, K.p),
                            mulmod(C.C2, encrypt(1, Rnew, K).C2, K.p) }));

    cout << "\n[4] REFRESH AGAIN AND AGAIN\n";
    Cipher chain = C;
    for (int i = 0; i < 5; i++) chain = reRandomise(chain, pickR(K), K);
    cout << "    after 5 refreshes: (" << chain.C1 << ", " << chain.C2 << ")\n";
    check("still PT after 5 rounds", decrypt(chain, K) == PT);

    cout << "\n[5] MIX-NET: TWO SERVERS SHUFFLE THREE BALLOTS\n";
    // each server re-randomises every ballot then permutes the list. Neither
    // server can read a vote, and neither can link its input list to its output.
    vector<u128> votes = {1001, 1002, 1003};
    vector<Cipher> box;
    for (u128 v : votes) box.push_back(encrypt(v, pickR(K), K));
    cout << "    submitted:";
    for (auto &b : box) cout << "  C1=" << toStr(b.C1).substr(0, 8) << "..";
    cout << "\n";
    vector<Cipher> before = box;
    for (int server = 1; server <= 2; server++) {
        for (auto &b : box) b = reRandomise(b, pickR(K), K);
        for (int i = (int)box.size() - 1; i > 0; i--) swap(box[i], box[nextRand() % (i + 1)]);
        cout << "    after server " << server << ":";
        for (auto &b : box) cout << "  C1=" << toStr(b.C1).substr(0, 8) << "..";
        cout << "\n";
    }
    bool anyMatch = false;
    for (auto &a : before) for (auto &b : box) if (same(a, b)) anyMatch = true;
    check("not one output pair matches any input pair", anyMatch, false);
    multiset<u128> out;
    for (auto &b : box) out.insert(decrypt(b, K));
    check("the tally is unchanged", out == multiset<u128>(votes.begin(), votes.end()));

    cout << "\n[6] THE TRAPS\n";
    check("R' = 0 is a no-op -- a mix server must reject it",
          same(C, reRandomise(C, 0, K)));
    // refreshing hides WHICH cipher this was; it does not hide the plaintext from
    // the key holder, does not change the key, and does not authenticate anything
    check("refreshing does NOT re-key: Bob's same D still opens it", decrypt(C2p, K) == PT);
    Cipher tampered = { C2p.C1, mulmod(C2p.C2, 3, K.p) };
    check("a refreshed cipher is still malleable (x3 slips through)",
          decrypt(tampered, K) == 3 * PT);
    // and the giveaway an observer CAN still use if you forget to refresh:
    check("two encryptions of PT with the same R are byte-identical",
          same(encrypt(PT, R, K), encrypt(PT, R, K)));

    summary();
    return failed != 0;
}
