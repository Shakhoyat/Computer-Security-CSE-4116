// ElGamal Cryptosystem - Key generation, Encryption, Decryption
//
//   Bob    : p = large prime, D = private key, E1 = primitive root, E2 = E1^D mod p
//            public key = (E1, E2, p)          private key = D
//   Alice  : C1 = E1^R mod p                   C2 = (PT * E2^R) mod p
//   Bob    : PT = [C2 * (C1^D)^-1] mod p
//
// The key is really generated here : a prime is searched for and tested, the
// primitive root is found and checked, D and R are drawn at random.
// __int128 is needed because p is about 10^18, so a*a % p needs 10^36.
//
// build : g++ -O2 -o eg1 elgamal_v1_basic.cpp        run : ./eg1
#include <bits/stdc++.h>
using namespace std;
typedef __int128 i128;

ostream& operator<<(ostream& os, i128 x) {          // cout does not know __int128
    if (x == 0) return os << '0';
    string s;
    while (x > 0) { s += char('0' + (int)(x % 10)); x /= 10; }
    reverse(s.begin(), s.end());
    return os << s;
}
i128 mod_pow(i128 a, i128 e, i128 m) {              // a^e mod m
    i128 r = 1; a %= m;
    while (e > 0) {
        if (e & 1) r = r * a % m;                   // <-- needs __int128
        a = a * a % m;
        e >>= 1;
    }
    return r;
}
i128 egcd(i128 a, i128 b, i128 &x, i128 &y) {       // a*x + b*y = gcd(a,b)
    if (b == 0) { x = 1; y = 0; return a; }
    i128 x1, y1, g = egcd(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1;
    return g;
}
i128 mod_inv(i128 a, i128 m) {                      // a^-1 mod m
    i128 x, y; egcd(a % m, m, x, y);
    return (x % m + m) % m;
}

// ---------------- KEY GENERATION HELPERS ----------------
mt19937_64 rng;
i128 rand_range(i128 lo, i128 hi) {                 // random value in [lo, hi]
    return lo + (i128)(rng() % (unsigned long long)(hi - lo + 1));
}
bool is_prime(i128 n) {                             // Miller-Rabin, exact below 3*10^24
    if (n < 2) return false;
    for (i128 q : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37})
        if (n % q == 0) return n == q;
    i128 d = n - 1; int r = 0;
    while (d % 2 == 0) { d /= 2; r++; }
    for (i128 a : {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37}) {
        i128 x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int i = 1; i < r; i++) { x = x * x % n; if (x == n - 1) { composite = false; break; } }
        if (composite) return false;
    }
    return true;
}
// A safe prime is p = 2q+1 with q prime too. Then an element can only have
// order 1, 2, q or 2q, so testing for a primitive root takes just two lines.
i128 next_safe_prime(i128 start) {
    i128 p = start | 1;                             // start from an odd number
    while (!(is_prime(p) && is_prime((p - 1) / 2))) p += 2;
    return p;
}
i128 find_primitive_root(i128 p) {                  // smallest g of full order p-1
    i128 q = (p - 1) / 2;
    for (i128 g = 2; ; g++)
        if (mod_pow(g, 2, p) != 1 && mod_pow(g, q, p) != 1) return g;
}

int main(int argc, char **argv) {
    // ---------------- INPUT (change only these two) ----------------
    unsigned long long SEED = 2026;    // different seed -> different key pair
    i128 PT = 987654321;               // plain text, must be < p
    if (argc > 1) SEED = strtoull(argv[1], 0, 10);   // ./eg1 2103021 -> your own key
    rng.seed(SEED);

    cout << "==================== KEY GENERATION (Bob) ====================\n";
    cout << "Step 1 : select a large prime p\n";
    i128 start = rand_range((i128)100000000000000000, (i128)900000000000000000);
    i128 p = next_safe_prime(start);
    i128 q = (p - 1) / 2;
    cout << "         search upward from    " << start << "\n";
    cout << "         p = " << p << "\n";
    cout << "         is_prime(p)      = " << (is_prime(p) ? "yes" : "no") << "\n";
    cout << "         q = (p-1)/2      = " << q << "\n";
    cout << "         is_prime(q)      = " << (is_prime(q) ? "yes" : "no")
         << "   -> p is a safe prime\n";

    cout << "Step 2 : select the private / decryption key D, random in [2, p-2]\n";
    i128 D = rand_range(2, p - 2);
    cout << "         D = " << D << "\n";

    cout << "Step 3 : select E1, a primitive root of p\n";
    i128 E1 = find_primitive_root(p);
    cout << "         E1 = " << E1 << "\n";
    cout << "         E1^2 mod p     = " << mod_pow(E1, 2, p) << "   (not 1, good)\n";
    cout << "         E1^q mod p     = " << mod_pow(E1, q, p) << "   (not 1, good)\n";
    cout << "         E1^(p-1) mod p = " << mod_pow(E1, p - 1, p) << "   (Fermat, must be 1)\n";

    i128 E2 = mod_pow(E1, D, p);                          // E2 = E1^D mod p
    cout << "Step 4 : E2 = E1^D mod p\n";
    cout << "            = " << E1 << "^" << D << " mod " << p << "\n";
    cout << "            = " << E2 << "\n";

    cout << "Step 5 : public  key (E1, E2, p) = (" << E1 << ", " << E2 << ", " << p << ")\n";
    cout << "         private key  D          = " << D << "\n";

    cout << "\n==================== ENCRYPTION (Alice) ====================\n";
    i128 R = rand_range(2, p - 2);                        // fresh random per message
    cout << "Step 1 : plain text        PT = " << PT << "   (PT < p ? "
         << (PT < p ? "yes" : "NO") << ")\n";
    cout << "Step 2 : random integer    R  = " << R << "\n";

    i128 C1 = mod_pow(E1, R, p);                          // C1 = E1^R mod p
    cout << "Step 3 : C1 = E1^R mod p\n";
    cout << "            = " << E1 << "^" << R << " mod " << p << "\n";
    cout << "            = " << C1 << "\n";

    i128 mask = mod_pow(E2, R, p);                        // E2^R mod p
    i128 C2 = PT % p * mask % p;                          // C2 = PT * E2^R mod p
    cout << "Step 4 : C2 = (PT * E2^R) mod p\n";
    cout << "         E2^R mod p = " << mask << "\n";
    cout << "            = (" << PT << " * " << mask << ") mod " << p << "\n";
    cout << "            = " << C2 << "\n";
    cout << "Step 5 : cipher text (C1, C2) = (" << C1 << ", " << C2 << ")\n";

    cout << "\n==================== DECRYPTION (Bob) ====================\n";
    i128 s = mod_pow(C1, D, p);                           // C1^D mod p
    cout << "Step 1 : C1^D mod p = " << C1 << "^" << D << " mod " << p << "\n";
    cout << "                    = " << s << "\n";

    i128 s_inv = mod_inv(s, p);                           // (C1^D)^-1 mod p
    cout << "Step 2 : (C1^D)^-1 mod p = " << s_inv << "\n";
    cout << "         check : " << s << " * " << s_inv << " mod p = " << s * s_inv % p << "\n";

    i128 dec = C2 * s_inv % p;                            // PT = C2 * (C1^D)^-1 mod p
    cout << "Step 3 : PT = [C2 * (C1^D)^-1] mod p\n";
    cout << "            = (" << C2 << " * " << s_inv << ") mod " << p << "\n";
    cout << "            = " << dec << "\n";

    cout << "\nRESULT : sent = " << PT << " , recovered = " << dec
         << (dec == PT ? "   -> MATCH\n" : "   -> MISMATCH\n");

    cout << "\n==================== WHY IT WORKS ====================\n";
    cout << "C1^D = (E1^R)^D = (E1^D)^R = E2^R , the same mask Alice used.\n";
    cout << "   C1^D = " << s << "\n";
    cout << "   E2^R = " << mask << "\n";
    cout << "Dividing C2 by that mask leaves PT.\n";
    i128 alt = C2 * mod_pow(C1, p - 1 - D, p) % p;        // Fermat short cut
    cout << "Short cut without extended Euclid :\n";
    cout << "   PT = C2 * C1^(p-1-D) mod p = " << alt << "\n";

    cout << "\n==================== SAME CODE ON THE THEORY SHEET NUMBERS ====================\n";
    // p = 11 is also a safe prime (q = 5) and 2 is a primitive root of it,
    // so the generator above would accept this key as well.
    i128 bp = 11, bD = 3, bE1 = 2, bPT = 7, bR = 4;
    i128 bE2 = mod_pow(bE1, bD, bp);
    i128 bC1 = mod_pow(bE1, bR, bp);
    i128 bC2 = bPT * mod_pow(bE2, bR, bp) % bp;
    i128 bs  = mod_pow(bC1, bD, bp);
    cout << "p = " << bp << " , D = " << bD << " , E1 = " << bE1 << "\n";
    cout << "E2 = E1^D mod p          = " << bE2 << "        public key (2, 8, 11)\n";
    cout << "C1 = E1^R mod p          = " << bC1 << "        (R = " << bR << ")\n";
    cout << "C2 = (PT * E2^R) mod p   = " << bC2 << "        cipher = (" << bC1 << ", " << bC2 << ")\n";
    cout << "C1^D mod p               = " << bs << "\n";
    cout << "(C1^D)^-1 mod p          = " << mod_inv(bs, bp) << "\n";
    cout << "PT = [C2*(C1^D)^-1] mod p = " << bC2 * mod_inv(bs, bp) % bp << "\n";
    return 0;
}
