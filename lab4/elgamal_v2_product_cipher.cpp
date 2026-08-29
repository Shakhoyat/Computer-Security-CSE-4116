// ElGamal Product Cipher - multiply two cipher texts, get the product of the
// two plain texts (the homomorphic property of ElGamal).
//
//   E(PT1) = (E1^R1 , PT1*E2^R1)      E(PT2) = (E1^R2 , PT2*E2^R2)
//   multiply piece by piece :
//   C1' = C1a*C1b = E1^(R1+R2)        C2' = C2a*C2b = (PT1*PT2)*E2^(R1+R2)
//   so (C1', C2') is a normal cipher text of PT1*PT2 with R = R1+R2.
//   The private key D is never needed - the public key is enough.
//
// build : g++ -O2 -o eg2 elgamal_v2_product_cipher.cpp        run : ./eg2
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
    while (e > 0) { if (e & 1) r = r * a % m; a = a * a % m; e >>= 1; }
    return r;
}
i128 egcd(i128 a, i128 b, i128 &x, i128 &y) {
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
i128 rand_range(i128 lo, i128 hi) { return lo + (i128)(rng() % (unsigned long long)(hi - lo + 1)); }
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
i128 next_safe_prime(i128 start) {                  // p = 2q+1 with q prime too
    i128 p = start | 1;
    while (!(is_prime(p) && is_prime((p - 1) / 2))) p += 2;
    return p;
}
i128 find_primitive_root(i128 p) {                  // smallest g of full order p-1
    i128 q = (p - 1) / 2;
    for (i128 g = 2; ; g++)
        if (mod_pow(g, 2, p) != 1 && mod_pow(g, q, p) != 1) return g;
}

int main(int argc, char **argv) {
    // ---------------- INPUT ----------------
    unsigned long long SEED = 2026;    // different seed -> different key pair
    i128 PT1 = 5, PT2 = 9;             // the two messages, PT1*PT2 must stay < p
    if (argc > 1) SEED = strtoull(argv[1], 0, 10);   // ./eg1 2103021 -> your own key
    rng.seed(SEED);

    cout << "==================== KEY GENERATION (Bob) ====================\n";
    i128 p  = next_safe_prime(rand_range((i128)100000000000000000, (i128)900000000000000000));
    i128 q  = (p - 1) / 2;
    i128 D  = rand_range(2, p - 2);
    i128 E1 = find_primitive_root(p);
    i128 E2 = mod_pow(E1, D, p);
    cout << "Step 1 : p  = " << p << "   prime? " << (is_prime(p) ? "yes" : "no") << "\n";
    cout << "         q  = (p-1)/2 = " << q << "   prime? " << (is_prime(q) ? "yes" : "no")
         << "   -> safe prime\n";
    cout << "Step 2 : D  = " << D << "   (private key)\n";
    cout << "Step 3 : E1 = " << E1 << "   primitive root, since E1^q mod p = "
         << mod_pow(E1, q, p) << " != 1\n";
    cout << "Step 4 : E2 = E1^D mod p = " << E2 << "\n";
    cout << "Step 5 : public (E1, E2, p) = (" << E1 << ", " << E2 << ", " << p << ")\n";

    cout << "\n==================== ENCRYPT MESSAGE 1 ====================\n";
    i128 R1 = rand_range(2, p - 2);
    i128 C1a = mod_pow(E1, R1, p);                          // C1 = E1^R mod p
    i128 C2a = PT1 % p * mod_pow(E2, R1, p) % p;            // C2 = PT * E2^R mod p
    cout << "PT1 = " << PT1 << " , R1 = " << R1 << "\n";
    cout << "C1a = E1^R1 mod p         = " << C1a << "\n";
    cout << "C2a = (PT1 * E2^R1) mod p = " << C2a << "\n";

    cout << "\n==================== ENCRYPT MESSAGE 2 ====================\n";
    i128 R2 = rand_range(2, p - 2);
    i128 C1b = mod_pow(E1, R2, p);
    i128 C2b = PT2 % p * mod_pow(E2, R2, p) % p;
    cout << "PT2 = " << PT2 << " , R2 = " << R2 << "\n";
    cout << "C1b = E1^R2 mod p         = " << C1b << "\n";
    cout << "C2b = (PT2 * E2^R2) mod p = " << C2b << "\n";

    cout << "\n==================== MULTIPLY THE TWO CIPHERS ====================\n";
    i128 C1p = C1a * C1b % p;                               // C1' = C1a * C1b mod p
    i128 C2p = C2a * C2b % p;                               // C2' = C2a * C2b mod p
    cout << "C1' = (C1a * C1b) mod p = " << C1p << "\n";
    cout << "C2' = (C2a * C2b) mod p = " << C2p << "\n";

    cout << "\n==================== DECRYPT THE PRODUCT ====================\n";
    i128 s = mod_pow(C1p, D, p);
    cout << "C1'^D mod p      = " << s << "\n";
    cout << "(C1'^D)^-1 mod p = " << mod_inv(s, p) << "\n";
    i128 dec = C2p * mod_inv(s, p) % p;                     // PT' = C2'*(C1'^D)^-1
    cout << "PT' = [C2' * (C1'^D)^-1] mod p = " << dec << "\n";
    cout << "expected PT1*PT2 mod p         = " << PT1 * PT2 % p << "\n";
    cout << (dec == PT1 * PT2 % p ? "-> MATCH\n" : "-> MISMATCH\n");

    cout << "\n==================== PROOF : SAME AS ONE DIRECT ENCRYPTION ====================\n";
    i128 dC1 = mod_pow(E1, R1 + R2, p);
    i128 dC2 = PT1 * PT2 % p * mod_pow(E2, R1 + R2, p) % p;
    cout << "encrypt(PT1*PT2, R1+R2) = (" << dC1 << ", " << dC2 << ")\n";
    cout << "our combined cipher     = (" << C1p << ", " << C2p << ")\n";
    cout << (dC1 == C1p && dC2 == C2p ? "-> identical\n" : "-> different\n");

    cout << "\n==================== SIDE EFFECT : MALLEABILITY ====================\n";
    // Eve has only (E1, E2, p). She multiplies C2 by k and leaves C1 alone,
    // so Bob decrypts k*PT instead of PT.
    i128 amount = 100, R3 = rand_range(2, p - 2), k = 10;
    i128 hC1 = mod_pow(E1, R3, p);
    i128 hC2 = amount % p * mod_pow(E2, R3, p) % p;
    cout << "Alice sends E(" << amount << ") = (" << hC1 << ", " << hC2 << ")\n";
    i128 tC2 = hC2 * k % p;
    cout << "Eve multiplies C2 by k = " << k << " , keeps C1 -> (" << hC1 << ", " << tC2 << ")\n";
    cout << "Bob decrypts and reads : " << tC2 * mod_inv(mod_pow(hC1, D, p), p) % p
         << "   (he was meant to read " << amount << ")\n";
    cout << "So plain ElGamal gives secrecy, NOT integrity. Add a signature or a MAC.\n";
    return 0;
}
