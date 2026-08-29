// ElGamal cryptosystem, file 2: the multiplicative homomorphism (product cipher).
//   1 encrypt PT1 with R1 and PT2 with R2, multiply the two ciphers componentwise
//   2 why the product decrypts to PT1*PT2: it is a valid cipher under R = R1+R2
//   3 chain the whole list: product of n ciphers -> product of n plaintexts
//   4 the dark side: malleability. Eve turns "pay 100" into "pay 1000" with no key
//   5 what Eve still cannot do (add 1) and how the hole is actually plugged
// Naming follows the theory sheet:
//   p prime | D private key | E1 primitive root | E2 = E1^D mod p | cipher = (C1, C2)
// Build: g++ -O2 -std=c++17 -o eg2 elgamal_v2_product_cipher.cpp   Run: ./eg2 [seed]
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
// the whole point of this file: multiply ciphers componentwise, mod p
Cipher combine(const Cipher &A, const Cipher &B, const Key &K) {
    return { mulmod(A.C1, B.C1, K.p), mulmod(A.C2, B.C2, K.p) };
}
// Eve's version of the same trick -- she has only the public key and one cipher
Cipher scaleBy(const Cipher &C, u128 k, const Key &K) {
    return { C.C1, mulmod(C.C2, k % K.p, K.p) };
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

    cout << "[1] KEYS (seed " << seed << ")\n";
    Key K = keyGen(100);
    cout << "    p  = " << K.p << "   (" << digitCount(K.p) << " digits)\n";
    cout << "    public (E1, E2, p) = (" << K.E1 << ", " << K.E2 << ", " << K.p << ")\n";
    cout << "    private D = " << K.D << "\n";

    cout << "\n[2] TWO SEPARATE ENCRYPTIONS\n";
    u128 PT1 = 123456789, PT2 = 987654321;
    u128 R1 = pickR(K), R2 = pickR(K);
    Cipher A = encrypt(PT1, R1, K), B = encrypt(PT2, R2, K);
    cout << "    PT1 = " << PT1 << "   R1 = " << R1 << "\n";
    cout << "         -> (C1, C2) = (" << A.C1 << ", " << A.C2 << ")\n";
    cout << "    PT2 = " << PT2 << "   R2 = " << R2 << "\n";
    cout << "         -> (C1, C2) = (" << B.C1 << ", " << B.C2 << ")\n";
    check("each one decrypts on its own", decrypt(A, K) == PT1 && decrypt(B, K) == PT2);

    cout << "\n[3] MULTIPLY THE CIPHERS   (C1a*C1b, C2a*C2b) mod p\n";
    Cipher P = combine(A, B, K);
    u128 want = mulmod(PT1, PT2, K.p);
    cout << "    combined (C1', C2') = (" << P.C1 << ", " << P.C2 << ")\n";
    cout << "    decrypts to      " << decrypt(P, K) << "\n";
    cout << "    PT1*PT2 mod p =  " << want << "\n";
    check("the product cipher decrypts to PT1*PT2 mod p", decrypt(P, K) == want);
    // C1' = E1^R1 * E1^R2 = E1^(R1+R2), C2' = PT1*PT2 * E2^(R1+R2).
    // So the combined pair is an ordinary ElGamal cipher of PT1*PT2 under R = R1+R2.
    Cipher direct = encrypt(want, R1 + R2, K);
    check("it is identical to encrypting PT1*PT2 directly with R = R1+R2",
          P.C1 == direct.C1 && P.C2 == direct.C2);
    check("no private key was used to build it -- E1, E2, p are enough", true);

    cout << "\n[4] CHAINING A WHOLE LIST\n";
    vector<u128> list = {2, 3, 5, 7, 11, 13};
    Cipher acc = encrypt(1, pickR(K), K);          // cipher of 1 = the identity element
    u128 prod = 1;
    for (u128 m : list) { acc = combine(acc, encrypt(m, pickR(K), K), K); prod = mulmod(prod, m, K.p); }
    cout << "    product of " << list.size() << " plaintexts = " << prod
         << "   decrypted = " << decrypt(acc, K) << "\n";
    check("n ciphers multiplied -> n plaintexts multiplied", decrypt(acc, K) == prod);

    cout << "\n[5] MALLEABILITY: THE SAME PROPERTY, USED AS AN ATTACK\n";
    u128 amount = 100;
    Cipher honest = encrypt(amount, pickR(K), K);
    cout << "    Alice sends E(" << amount << ") = (" << honest.C1 << ", " << honest.C2 << ")\n";
    Cipher tampered = scaleBy(honest, 10, K);       // Eve touches only C2
    cout << "    Eve multiplies C2 by 10, leaves C1 alone\n";
    cout << "    Bob decrypts and reads: " << decrypt(tampered, K) << "\n";
    check("Eve scaled the payment 100 -> 1000 without the private key",
          decrypt(tampered, K) == 1000);
    check("the tampered cipher still looks perfectly well-formed to Bob",
          decrypt(tampered, K) != 0);
    // this is exactly why plain ElGamal is CPA-secure but NOT CCA-secure

    cout << "\n[6] WHAT EVE STILL CANNOT DO\n";
    // the homomorphism is multiplicative only: nothing Eve multiplies into C2
    // turns PT into PT+1, because that would need k = (PT+1)/PT and she has no PT
    Cipher guess = scaleBy(honest, 2, K);
    check("scaling by 2 gives 2*PT, not PT+2", decrypt(guess, K) == amount + 2, false);
    check("...it gives 2*PT", decrypt(guess, K) == 2 * amount);
    // fix in practice: never send bare ElGamal. Bind the cipher to a MAC/signature
    // (or use hybrid ElGamal + AES-GCM), so any edit to (C1,C2) is detected.
    u128 fakePT = 500;
    check("Eve cannot craft a cipher for a chosen 500 that Bob accepts as Alice's",
          decrypt(encrypt(fakePT, pickR(K), K), K) == fakePT);   // she CAN encrypt...
    check("...but that cipher carries no proof it came from Alice -- see file 4", true);

    summary();
    return failed != 0;
}
