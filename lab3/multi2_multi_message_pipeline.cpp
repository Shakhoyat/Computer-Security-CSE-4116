// Multiple messages, file 2: full pipeline over a message list.
//   1 represent -> encrypt -> decrypt a list of messages
//   2 sign -> verify the same list
//   3 sign AND encrypt (Alice -> Bob) per message
//   4 one message to many recipients (each with its own key)
//   5 many senders to one recipient (which public key verifies?)
//   6 hybrid: one RSA op for a session key, N cheap ops for the messages
// Build: g++ -O2 -std=c++17 -o m2 multi2_multi_message_pipeline.cpp   Run: ./m2 [seed]
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

int bitLen(u128 x) { int b = 0; while (x) { b++; x >>= 1; } return b; }
int blockBytes(u128 n) { return (bitLen(n) - 1) / 8; }
vector<u128> toBlocks(const string &s, int k) {
    vector<u128> v;
    for (size_t i = 0; i < s.size(); i += k) {
        u128 m = 0;
        for (int j = 0; j < k; j++) m = m * 256 + (i + j < s.size() ? (unsigned char)s[i + j] : 0);
        v.push_back(m);
    }
    return v;
}
string fromBlocks(const vector<u128> &v, int k, size_t origLen) {
    string s;
    for (u128 m : v) {
        string t(k, '\0');
        for (int j = k - 1; j >= 0; j--) { t[j] = char(int(m % 256)); m /= 256; }
        s += t;
    }
    s.resize(origLen);
    return s;
}

int main(int argc, char **argv) {
    rngState = (argc > 1) ? strtoull(argv[1], 0, 10) : 20260808ULL;
    u64 seed = rngState;
    Key A = genKey(), B = genKey(), C = genKey();
    cout << "seed " << seed << "\n  Alice n=" << A.n << " e=" << A.e
         << "\n  Bob   n=" << B.n << " e=" << B.e
         << "\n  Carol n=" << C.n << " e=" << C.e << "\n";

    const int N = 4;
    string msgs[N] = { "Ashik111: order 500 units",
                        "delivery on 2026-09-01",
                        "invoice total = 12750.00 BDT",
                        "Ashik111: order 500 units" };   // deliberately equal to msgs[0]

    cout << "\n[1] ENCRYPT ALL " << N << " MESSAGES TO BOB\n";
    int k = blockBytes(B.n);
    vector<vector<u128>> ct(N); size_t lens[N];
    for (int i = 0; i < N; i++) {
        lens[i] = msgs[i].size();
        for (u128 m : toBlocks(msgs[i], k)) ct[i].push_back(encrypt(m, B));
        cout << "    msg " << i << ": " << lens[i] << " bytes -> " << ct[i].size()
             << " blocks, c0 = " << ct[i][0] << "\n";
    }
    bool allBack = true;
    for (int i = 0; i < N; i++) {
        vector<u128> pt; for (u128 c : ct[i]) pt.push_back(decrypt(c, B));
        if (fromBlocks(pt, k, lens[i]) != msgs[i]) allBack = false;
    }
    check("all " + to_string(N) + " messages decrypt back exactly", allBack);
    // raw RSA is deterministic, so msg 3 == msg 0 is visible straight from the
    // ciphertext -- Eve reads the relation without breaking anything
    check("identical plaintexts produce identical ciphertexts (a leak)", ct[0] == ct[3]);
    check("different plaintexts do not collide", ct[0] == ct[1], false);

    cout << "\n[2] ALICE SIGNS ALL " << N << " MESSAGES\n";
    u128 hs[N], ss[N];
    for (int i = 0; i < N; i++) { hs[i] = H(msgs[i], A.n); ss[i] = sign(hs[i], A); }
    bool allSig = true;
    for (int i = 0; i < N; i++) if (!verify(hs[i], ss[i], A.n, A.e)) allSig = false;
    check("every signature verifies under Alice's public key", allSig);
    check("msg 0 and msg 3 are equal, so their signatures are equal", ss[0] == ss[3]);
    check("signature of msg 0 does not verify msg 1", verify(hs[1], ss[0], A.n, A.e), false);
    string tampered = msgs[2]; tampered.back() = '1';
    int badIndex = -1;
    for (int i = 0; i < N; i++) {
        string m = (i == 2) ? tampered : msgs[i];
        if (!verify(H(m, A.n), ss[i], A.n, A.e)) badIndex = i;
    }
    check("the one tampered message is located (index 2)", badIndex == 2);

    // Alice signs with HER private key, encrypts with BOB's public key -- the
    // two moduli differ, so the hash has to be reduced under the right one.
    cout << "\n[3] SIGN + ENCRYPT (Alice -> Bob), per message\n";
    bool allOK = true;
    for (int i = 0; i < N; i++) {
        u128 sig = sign(H(msgs[i], A.n), A);
        vector<u128> enc; for (u128 m : toBlocks(msgs[i], k)) enc.push_back(encrypt(m, B));
        vector<u128> dec; for (u128 c : enc) dec.push_back(decrypt(c, B));
        string got = fromBlocks(dec, k, msgs[i].size());
        bool ok = (got == msgs[i]) && verify(H(got, A.n), sig, A.n, A.e);
        cout << "    msg " << i << "  sig=" << sig << "  " << (ok ? "AUTHENTIC" : "REJECT") << "\n";
        if (!ok) allOK = false;
    }
    check("confidentiality + integrity + non-repudiation on all messages", allOK);
    Key E = genKey();
    u128 fake = sign(H(msgs[0], E.n), E);
    check("Eve signs with her own key and claims to be Alice",
          verify(H(msgs[0], A.n), fake, A.n, A.e), false);

    // each recipient has a different n, so the same plaintext becomes a
    // different ciphertext for each -- the broadcast setting Hastad breaks
    // when e is small (see multi3 [4])
    cout << "\n[4] BROADCAST: one message, three recipients\n";
    string bc = "board meeting 09:00";
    Key rcpt[3] = {A, B, C}; const char *who[3] = {"Alice", "Bob", "Carol"};
    bool bcOK = true; vector<u128> bcC;
    for (int i = 0; i < 3; i++) {
        int ki = blockBytes(rcpt[i].n);
        vector<u128> e2; for (u128 m : toBlocks(bc, ki)) e2.push_back(encrypt(m, rcpt[i]));
        vector<u128> d2; for (u128 c : e2) d2.push_back(decrypt(c, rcpt[i]));
        if (fromBlocks(d2, ki, bc.size()) != bc) bcOK = false;
        bcC.push_back(e2[0]);
        cout << "    to " << who[i] << ": c0 = " << e2[0] << "\n";
    }
    check("all three recipients recover the same plaintext", bcOK);
    check("the three ciphertexts differ", bcC[0] != bcC[1] && bcC[1] != bcC[2]);

    cout << "\n[5] THREE SENDERS -> BOB: which public key verifies?\n";
    string note = "shipment received";
    Key sender[3] = {A, C, E}; const char *sname[3] = {"Alice", "Carol", "Eve"};
    u128 sigs[3]; for (int i = 0; i < 3; i++) sigs[i] = sign(H(note, sender[i].n), sender[i]);
    int self = 0, cross = 0;
    for (int i = 0; i < 3; i++) for (int j = 0; j < 3; j++)
        if (verify(H(note, sender[j].n), sigs[i], sender[j].n, sender[j].e)) (i == j) ? self++ : cross++;
    for (int i = 0; i < 3; i++) cout << "    " << sname[i] << "'s signature = " << sigs[i] << "\n";
    check("all 3 signatures verify under their own key", self == 3);
    check("no signature verifies under a foreign key", cross > 0, false);

    // RSA is slow and capped at n. Encrypt one session key with RSA, then XOR
    // every message with a keystream expanded from it.
    cout << "\n[6] HYBRID over the message list\n";
    u64 sessionKey = 1 + nextRand() % 1000000007ULL;
    u128 wrapped = encrypt((u128)sessionKey % B.n, B);
    cout << "    session key K = " << sessionKey << "   RSA-wrapped = " << wrapped << "\n";
    u64 rec = (u64)decrypt(wrapped, B);
    check("Bob unwraps the session key", rec == sessionKey);
    bool hyb = true; int rsaOps = 2, symOps = 0;
    for (int i = 0; i < N; i++) {
        u64 st = sessionKey + i; string enc = msgs[i], dec;
        for (char &c : enc) { st = st * 6364136223846793005ULL + 1442695040888963407ULL; c ^= char(st >> 33); symOps++; }
        st = rec + i; dec = enc;
        for (char &c : dec) { st = st * 6364136223846793005ULL + 1442695040888963407ULL; c ^= char(st >> 33); }
        if (dec != msgs[i]) hyb = false;
    }
    check("all messages recovered through the hybrid path", hyb);
    int pureRSA = 0; for (int i = 0; i < N; i++) pureRSA += 2 * (int)toBlocks(msgs[i], k).size();
    cout << "    RSA ops used: " << rsaOps << " (hybrid) vs " << pureRSA
         << " (pure RSA), plus " << symOps << " byte XORs\n";

    summary();
    return failed != 0;
}
