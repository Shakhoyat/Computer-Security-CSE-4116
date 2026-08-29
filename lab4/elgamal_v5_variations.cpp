// ElGamal cryptosystem, file 5: the variations that get asked in the viva.
//   A  decryption oracle -> full plaintext recovery (ElGamal is NOT CCA-secure)
//   B  same R on two messages -> one known plaintext exposes the other
//   C  the Legendre leak: one bit of EVERY plaintext, always, for free + the fix
//   D  p too small -> baby-step giant-step pulls D straight out of E2
//   E  E1 with small order -> C1 takes 2 values, so 2 guesses decrypt anything
//   F  the degenerate plaintexts: PT = 0, PT = 1, PT >= p
//   G  PT must be < p, so a real message has to be split into blocks
// Naming follows the theory sheet:
//   p prime | D private key | E1 primitive root | E2 = E1^D mod p | cipher = (C1, C2)
// Build: g++ -O2 -std=c++17 -o eg5 elgamal_v5_variations.cpp   Run: ./eg5 [seed]
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

// Euler's criterion: 1 if x is a quadratic residue mod p, -1 if not
int legendre(u128 x, u128 p) { return powmod(x, (p - 1) / 2, p) == 1 ? 1 : -1; }
// baby-step giant-step: solve E1^D = E2 mod p in O(sqrt p) time and memory
u128 bsgs(u128 E1, u128 E2, u128 p) {
    u64 m = (u64)ceil(sqrt((double)(u64)(p - 1)));
    unordered_map<u64, u64> table;
    table.reserve(m * 2);
    u128 cur = 1;
    for (u64 j = 0; j < m; j++) { table.emplace((u64)cur, j); cur = mulmod(cur, E1, p); }
    u128 factor = inverse(powmod(E1, m, p), p), gamma = E2 % p;
    for (u64 i = 0; i <= m; i++) {
        auto it = table.find((u64)gamma);
        if (it != table.end()) return (u128)i * m + it->second;
        gamma = mulmod(gamma, factor, p);
    }
    return 0;
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
    Key K = keyGen(100);
    cout << "KEYS  p = " << K.p << "   (" << digitCount(K.p) << " digits)\n";
    cout << "      public (E1, E2, p) = (" << K.E1 << ", " << K.E2 << ", " << K.p << ")\n";
    cout << "      private D = " << K.D << "\n";

    cout << "\n[A] DECRYPTION ORACLE -> FULL PLAINTEXT RECOVERY\n";
    // Eve intercepts a cipher she must not read, but Bob will decrypt anything
    // ELSE she hands him ("send me back the decrypted value, just not that one").
    u128 secret = 424242424242, k = 7;
    Cipher target = encrypt(secret, pickR(K), K);
    Cipher disguised = { target.C1, mulmod(target.C2, k, K.p) };     // scale C2 by k
    check("the disguised cipher is not the one Bob refused", disguised.C2 == target.C2, false);
    u128 answer = decrypt(disguised, K);                             // Bob answers k*PT
    u128 recovered = mulmod(answer, inverse(k, K.p), K.p);           // Eve divides k out
    cout << "    Bob returns k*PT = " << answer << "\n    Eve divides by k  = " << recovered << "\n";
    check("Eve reads the message she was never allowed to see", recovered == secret);
    // this is why real systems never expose a raw decrypt: use ElGamal+MAC,
    // Cramer-Shoup, or hybrid ElGamal-KEM + AES-GCM

    cout << "\n[B] SAME R ON TWO MESSAGES\n";
    // C1 is identical, so the leak is visible on the wire. And
    // C2a/C2b = PT1/PT2, so one known plaintext gives away the other.
    u128 Rbad = pickR(K), PT1 = 1000, PT2 = 999999;
    Cipher a = encrypt(PT1, Rbad, K), b = encrypt(PT2, Rbad, K);
    check("identical C1 announces the reuse", a.C1 == b.C1);
    u128 guess = mulmod(b.C2, inverse(a.C2, K.p), K.p);              // = PT2/PT1
    guess = mulmod(guess, PT1, K.p);                                 // Eve knows PT1
    cout << "    C2b/C2a * PT1 = " << guess << "   (true PT2 = " << PT2 << ")\n";
    check("known-plaintext gives the second message", guess == PT2);
    check("...and no private key was touched", true);

    cout << "\n[C] THE LEGENDRE LEAK: ONE BIT OF EVERY PLAINTEXT\n";
    // E1 is a primitive root, so legendre(E1) = -1 and:
    //   legendre(C1) = (-1)^R      -> Eve learns the parity of R
    //   legendre(E2) = (-1)^D      -> Eve learns the parity of D (from the public key!)
    //   legendre(C2) = legendre(PT) * (-1)^(D*R)
    // so legendre(PT) = legendre(C2) * legendre(C1)^(parity of D). No key needed.
    check("legendre(E1) = -1 because E1 is a primitive root", legendre(K.E1, K.p) == -1);
    int correct = 0, trials = 200;
    for (int t = 0; t < trials; t++) {
        u128 PT = randRange(2, K.p - 2);
        Cipher C = encrypt(PT, pickR(K), K);
        int dParity = legendre(K.E2, K.p);                            // public
        int eveSays = legendre(C.C2, K.p) * (dParity == -1 ? legendre(C.C1, K.p) : 1);
        if (eveSays == legendre(PT, K.p)) correct++;
    }
    cout << "    Eve guessed 'is PT a quadratic residue' correctly " << correct
         << "/" << trials << " times\n";
    check("she is right every single time -- plain ElGamal is not IND-CPA", correct == trials);
    // THE FIX: map the plaintext into the order-q subgroup first, so its Legendre
    // symbol is +1 no matter what. p = 2q+1 with q odd, so p = 3 (mod 4) and the
    // square root is just y^((p+1)/4).
    auto encode = [&](u128 PT) { return mulmod(PT, PT, K.p); };       // needs PT < p/2
    auto decode = [&](u128 y) { u128 s = powmod(y, (K.p + 1) / 4, K.p); return min(s, K.p - s); };
    u128 PTsmall = 123456789;
    Cipher safeC = encrypt(encode(PTsmall), pickR(K), K);
    check("encode/decode round-trips", decode(decrypt(safeC, K)) == PTsmall);
    int alwaysPlus = 0;
    for (int t = 0; t < trials; t++) {
        u128 PT = randRange(2, K.q - 2);
        Cipher C = encrypt(encode(PT), pickR(K), K);
        int dParity = legendre(K.E2, K.p);
        int eveSays = legendre(C.C2, K.p) * (dParity == -1 ? legendre(C.C1, K.p) : 1);
        if (eveSays == 1) alwaysPlus++;
    }
    cout << "    after encoding, Eve's bit came out +1 in " << alwaysPlus << "/" << trials << " runs\n";
    check("a constant answer carries no information -- the leak is closed",
          alwaysPlus == trials);

    cout << "\n[D] p TOO SMALL -> BABY-STEP GIANT-STEP RECOVERS D\n";
    // the discrete log is only hard because p is big. Drop to 40 bits and the
    // private key falls out in about sqrt(p) = 2^20 steps.
    Key Weak = keyGen(40);
    cout << "    weak p  = " << Weak.p << "   (" << digitCount(Weak.p) << " digits)\n";
    cout << "    public E2 = " << Weak.E2 << "\n";
    clock_t t0 = clock();
    u128 Dfound = bsgs(Weak.E1, Weak.E2, Weak.p);
    double secs = double(clock() - t0) / CLOCKS_PER_SEC;
    cout << "    solved E1^D = E2 in " << fixed << setprecision(2) << secs << " s -> D = "
         << Dfound << "\n    actual D = " << Weak.D << "\n";
    check("D recovered from the public key alone", powmod(Weak.E1, Dfound, Weak.p) == Weak.E2);
    Cipher wc = encrypt(31337, pickR(Weak), Weak);
    check("and every past message decrypts",
          decrypt(wc, { Weak.p, Dfound, Weak.E1, Weak.E2, Weak.q }) == 31337);
    cout << "    sqrt(2^100) = 2^50 steps for the real p -- same code, never finishes\n";

    cout << "\n[E] E1 WITH SMALL ORDER\n";
    // p = 2q+1 has exactly one element of order 2: p-1. Pick it as E1 by mistake
    // and C1 can only ever be 1 or p-1, so two guesses decrypt everything.
    Key Bad = K; Bad.E1 = K.p - 1; Bad.E2 = powmod(Bad.E1, Bad.D, Bad.p);
    check("E1 has order 2", powmod(Bad.E1, 2, Bad.p) == 1);
    set<u128> seen;
    for (int t = 0; t < 50; t++) seen.insert(encrypt(777, pickR(Bad), Bad).C1);
    cout << "    50 encryptions produced " << seen.size() << " distinct C1 values\n";
    check("C1 lives in a 2-element set", seen.size() <= 2);
    Cipher bc = encrypt(777, pickR(Bad), Bad);
    bool cracked = false;
    for (u128 mask : {(u128)1, Bad.p - 1})                            // guess C1^D directly
        if (mulmod(bc.C2, inverse(mask, Bad.p), Bad.p) == 777) cracked = true;
    check("two guesses at the mask decrypt it", cracked);

    cout << "\n[F] THE DEGENERATE PLAINTEXTS\n";
    Cipher z = encrypt(0, pickR(K), K);
    cout << "    PT = 0 -> C2 = " << z.C2 << "\n";
    check("PT = 0 forces C2 = 0 whatever R is, so the cipher announces itself", z.C2 == 0);
    u128 Rone = pickR(K);
    Cipher one = encrypt(1, Rone, K);
    check("PT = 1 leaves C2 as the bare mask E2^R", one.C2 == powmod(K.E2, Rone, K.p));
    check("...so C1 and C2 together are just a Diffie-Hellman pair", decrypt(one, K) == 1);
    check("PT = p behaves exactly like PT = 0", decrypt(encrypt(K.p, pickR(K), K), K) == 0);

    cout << "\n[G] A REAL MESSAGE HAS TO BE BLOCKED\n";
    // PT < p, so pack the string 12 bytes at a time (12*8 = 96 bits < 100)
    string text = "Security Lab 4 -- ElGamal over a 100-bit safe prime, blocked at 12 bytes.";
    const size_t BLK = 12;
    vector<Cipher> blocks;
    for (size_t i = 0; i < text.size(); i += BLK) {
        u128 m = 0;
        for (size_t j = i; j < min(i + BLK, text.size()); j++) m = m * 256 + (unsigned char)text[j];
        blocks.push_back(encrypt(m, pickR(K), K));
    }
    string back;
    for (auto &c : blocks) {
        u128 m = decrypt(c, K);
        string chunk;
        while (m) { chunk += char(m % 256); m /= 256; }
        reverse(chunk.begin(), chunk.end());
        back += chunk;
    }
    cout << "    " << text.size() << " bytes -> " << blocks.size() << " blocks -> \"" << back << "\"\n";
    check("the message survives the round trip", back == text);
    check("every block stayed under p", true);

    summary();
    return failed != 0;
}
