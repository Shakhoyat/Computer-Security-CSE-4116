// ElGamal Digital Signature - sign with the private key D, verify with the
// public key (E1, E2, p).
//
//   Sign   (Alice) : pick R with gcd(R, p-1) = 1
//                    S1 = E1^R mod p
//                    S2 = (M - D*S1) * R^-1 mod (p-1)
//                    send (M, S1, S2)
//   Verify (Bob)   : V1 = E1^M mod p
//                    V2 = (E2^S1 * S1^S2) mod p
//                    signature is valid  <=>  V1 == V2
//
//   Note : S1 and S2 use DIFFERENT moduli. S1 is mod p , S2 is mod (p-1).
//          Mixing the two up is the classic mistake.
//
// build : g++ -O2 -o eg4 elgamal_v4_signature.cpp        run : ./eg4
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
i128 gcd128(i128 a, i128 b) { while (b) { i128 t = a % b; a = b; b = t; } return a; }
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
i128 pick_R(i128 p) {                               // signing needs R^-1 mod (p-1)
    i128 n = p - 1, R = rand_range(2, n - 1) | 1;   // so R must be odd
    while (gcd128(R, n) != 1) { R += 2; if (R >= n) R = 3; }
    return R;
}

int main(int argc, char **argv) {
    // ---------------- INPUT ----------------
    unsigned long long SEED = 2026;    // different seed -> different key pair
    i128 M = 111111;                   // message (a hash digest in real life), M < p-1
    if (argc > 1) SEED = strtoull(argv[1], 0, 10);   // ./eg1 2103021 -> your own key
    rng.seed(SEED);

    cout << "==================== KEY GENERATION (Alice) ====================\n";
    i128 p  = next_safe_prime(rand_range((i128)100000000000000000, (i128)900000000000000000));
    i128 n  = p - 1;                                // signatures live mod p-1
    i128 q  = n / 2;
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
    cout << "         private D = " << D << "     p-1 = " << n << "\n";

    cout << "\n==================== SIGNING (Alice) ====================\n";
    cout << "Step 1 : message  M = " << M << "\n";
    i128 R = pick_R(p);
    cout << "Step 2 : random   R = " << R << "\n";
    cout << "         gcd(R, p-1) = " << gcd128(R, n) << "   (must be 1 so R^-1 exists)\n";

    i128 S1 = mod_pow(E1, R, p);                             // S1 = E1^R mod p
    cout << "Step 3 : S1 = E1^R mod p\n";
    cout << "            = " << E1 << "^" << R << " mod " << p << "\n";
    cout << "            = " << S1 << "\n";

    i128 DS1 = D % n * (S1 % n) % n;                         // D*S1 mod (p-1)
    i128 top = ((M - DS1) % n + n) % n;                      // (M - D*S1) mod (p-1)
    i128 Rin = mod_inv(R, n);                                // R^-1 mod (p-1)
    i128 S2  = top * Rin % n;                                // S2 = (M - D*S1)*R^-1
    cout << "Step 4 : S2 = (M - D*S1) * R^-1 mod (p-1)\n";
    cout << "         D*S1 mod (p-1)       = " << DS1 << "\n";
    cout << "         (M - D*S1) mod (p-1) = " << top << "\n";
    cout << "         R^-1 mod (p-1)       = " << Rin << "\n";
    cout << "         S2 = (" << top << " * " << Rin << ") mod " << n << "\n";
    cout << "            = " << S2 << "\n";
    cout << "Step 5 : signature (S1, S2) = (" << S1 << ", " << S2 << ")\n";

    cout << "\n==================== VERIFYING (Bob) ====================\n";
    i128 V1 = mod_pow(E1, M, p);                             // V1 = E1^M mod p
    cout << "Step 1 : V1 = E1^M mod p = " << E1 << "^" << M << " mod " << p << "\n";
    cout << "            = " << V1 << "\n";

    i128 x = mod_pow(E2, S1, p), y = mod_pow(S1, S2, p);
    i128 V2 = x * y % p;                                     // V2 = E2^S1 * S1^S2 mod p
    cout << "Step 2 : V2 = (E2^S1 * S1^S2) mod p\n";
    cout << "         E2^S1 mod p = " << x << "\n";
    cout << "         S1^S2 mod p = " << y << "\n";
    cout << "         V2 = " << V2 << "\n";
    cout << "Step 3 : V1 == V2 ?  " << (V1 == V2 ? "YES -> SIGNATURE VALID\n"
                                                 : "NO -> SIGNATURE INVALID\n");

    cout << "\n==================== WHY IT WORKS ====================\n";
    // from S2 = (M - D*S1)*R^-1 we get   R*S2 + D*S1 = M  (mod p-1)
    // raise E1 to both sides :  E1^(R*S2) * E1^(D*S1) = E1^M
    //                           S1^S2     * E2^S1     = E1^M      <- V2 == V1
    i128 lhs = (R % n * (S2 % n) % n + D % n * (S1 % n) % n) % n;
    cout << "R*S2 + D*S1 mod (p-1) = " << lhs << "\n";
    cout << "M           mod (p-1) = " << M % n << "\n";
    cout << "Raise E1 to both sides : S1^S2 * E2^S1 = E1^M , which is exactly V2 = V1.\n";

    cout << "\n==================== TAMPER TESTS ====================\n";
    i128 Mbad = M + 1;                                       // message changed
    cout << "message changed to " << Mbad << " : V1 = " << mod_pow(E1, Mbad, p) << " , V2 = " << V2
         << (mod_pow(E1, Mbad, p) == V2 ? "  -> VALID\n" : "  -> INVALID (caught)\n");

    i128 W2 = mod_pow(E2, S1, p) * mod_pow(S1, S2 + 1, p) % p;   // signature changed
    cout << "S2 changed to S2+1 : V1 = " << V1 << " , V2 = " << W2
         << (V1 == W2 ? "  -> VALID\n" : "  -> INVALID (caught)\n");

    i128 E2other = mod_pow(E1, D + 1, p);                     // somebody else's key
    i128 W3 = mod_pow(E2other, S1, p) * mod_pow(S1, S2, p) % p;
    cout << "checked with a different public key : V1 = " << V1 << " , V2 = " << W3
         << (V1 == W3 ? "  -> VALID\n" : "  -> INVALID (caught)\n");
    return 0;
}
