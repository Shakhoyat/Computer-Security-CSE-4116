// Multiple messages, file 1: message representation.
//   1 char-by-char representation and why it leaks
//   2 block representation: k = (bitlen(n)-1)/8 bytes packed base-256
//   3 full round trip encrypt/decrypt over blocks
//   4 corner cases: leading zero bytes, tail padding, empty message, m >= n
//   5 cost comparison
// Build: g++ -O2 -std=c++17 -o m1 multi1_representation.cpp   Run: ./m1 [seed]
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
int blockBytes(u128 n) { return (bitLen(n) - 1) / 8; }   // widest block that always packs < n

vector<u128> toBlocks(const string &s, int k) {
    vector<u128> v;
    for (size_t i = 0; i < s.size(); i += k) {
        u128 m = 0;
        for (int j = 0; j < k; j++) m = m * 256 + (i + j < s.size() ? (unsigned char)s[i + j] : 0);
        v.push_back(m);
    }
    return v;
}
// a block whose first byte is 0 would unpack shorter if you just peel digits
// off, so always emit k bytes per block and trim using the real length
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
    Key B = genKey();
    int k = blockBytes(B.n);
    cout << "seed " << seed << "   Bob n=" << B.n << "  (" << bitLen(B.n)
         << " bits, " << toStr(B.n).size() << " digits)  e=" << B.e << "\n";
    cout << "  block size k = (bitlen-1)/8 = " << k << " bytes"
         << "   max block value = 256^" << k << "-1 < n\n";
    { u128 mx = 1; for (int i = 0; i < k; i++) mx *= 256; check("max block value < n", mx - 1 < B.n); }

    string msg = "Ashik111 sees the seeds in the sea";

    // one RSA op per character, and raw RSA is deterministic -- equal characters
    // give equal ciphertexts. A substitution cipher wearing an RSA costume.
    cout << "\n[1] CHAR-BY-CHAR REPRESENTATION\n";
    vector<u128> cc;
    for (unsigned char ch : msg) cc.push_back(encrypt(ch, B));
    map<u128, int> freq; for (u128 c : cc) freq[c]++;
    int dup = 0; for (auto &pr : freq) if (pr.second > 1) dup++;
    cout << "    " << cc.size() << " ciphertext numbers, " << freq.size()
         << " distinct, " << dup << " values repeat\n";
    check("repeated ciphertexts leak repeated letters", dup > 0);
    // Eve doesn't even need frequencies -- she can rebuild the whole lookup
    // table herself with the PUBLIC key alone.
    int tableHits = 0;
    for (int ch = 32; ch < 127; ch++) if (encrypt((u128)ch, B) == cc[0]) tableHits++;
    check("Eve rebuilds a full alphabet lookup table with the public key", tableHits == 1);

    cout << "\n[2] BLOCK REPRESENTATION (" << k << " bytes -> one integer)\n";
    vector<u128> blk = toBlocks(msg, k);
    cout << "    \"" << msg << "\"  (" << msg.size() << " bytes) -> " << blk.size() << " blocks\n";
    for (size_t i = 0; i < blk.size(); i++)
        cout << "      block " << i << " = " << blk[i] << "   \"" << msg.substr(i * k, k) << "\"\n";
    bool allFit = true; for (u128 m : blk) if (m >= B.n) allFit = false;
    check("every block value is < n", allFit);
    check("representation round trip (no RSA yet)", fromBlocks(blk, k, msg.size()) == msg);

    cout << "\n[3] ENCRYPT AND DECRYPT THE BLOCKS\n";
    vector<u128> ct, pt;
    for (u128 m : blk) ct.push_back(encrypt(m, B));
    for (u128 c : ct)  pt.push_back(decrypt(c, B));
    for (size_t i = 0; i < ct.size(); i++)
        cout << "      c" << i << " = " << ct[i] << "  ->  m" << i << " = " << pt[i] << "\n";
    string back = fromBlocks(pt, k, msg.size());
    cout << "    recovered = \"" << back << "\"\n";
    check("full round trip through RSA", back == msg);

    cout << "\n[4] CORNER CASES\n";
    string zeros = "AB"; zeros += '\0'; zeros += '\0'; zeros += "CD";
    check("interior zero bytes survive", fromBlocks(toBlocks(zeros, k), k, zeros.size()) == zeros);
    string lead; lead += '\0'; lead += '\0'; lead += "hi";
    check("leading zero bytes survive (fixed-width unpack)",
          fromBlocks(toBlocks(lead, k), k, lead.size()) == lead);
    string one = "Z";
    check("message shorter than one block", fromBlocks(toBlocks(one, k), k, one.size()) == one);
    string exact(k * 3, 'q');
    check("length an exact multiple of k", fromBlocks(toBlocks(exact, k), k, exact.size()) == exact);
    check("empty message -> 0 blocks", toBlocks("", k).empty());
    // pushing k+1 bytes into one block would exceed n, so it wraps mod n during
    // encryption and comes back as tooBig mod n, not tooBig itself
    u128 tooBig = 0;
    for (int j = 0; j <= k; j++) tooBig = tooBig * 256 + 255;
    check("a (k+1)-byte block would exceed n", tooBig < B.n, false);
    check("...so it decrypts to tooBig mod n, not tooBig", decrypt(encrypt(tooBig, B), B) == tooBig % B.n);

    cout << "\n[5] COST FOR THIS MESSAGE\n";
    cout << "    char-wise : " << msg.size() << " encrypts + " << msg.size() << " decrypts\n";
    cout << "    block-wise: " << blk.size() << " encrypts + " << blk.size() << " decrypts  ("
         << k << "x fewer, and no per-character frequency leak)\n";
    cout << "    still deterministic though -- identical blocks repeat. Only random\n"
            "    padding (OAEP) removes that; see multi3 [1].\n";

    summary();
    return failed != 0;
}
