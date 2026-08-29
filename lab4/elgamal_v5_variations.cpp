// ElGamal - the variations / attacks that usually get asked in the viva.
//
//   A  same R used for two messages      -> one known plain text gives the other
//   B  same R used for two signatures    -> the private key D falls out
//   C  decryption oracle                 -> Eve reads a message she may not read
//   D  p too small                       -> brute force the discrete log, get D
//   E  Legendre symbol                   -> one bit of EVERY plain text leaks
//   F  R = 0 and PT = 0                  -> the two degenerate cases
//
// The key used below is generated the proper way, exactly like in file 1.
//
// build : g++ -O2 -o eg5 elgamal_v5_variations.cpp        run : ./eg5
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

int main(int argc, char **argv) {
    // ---------------- INPUT ----------------
    unsigned long long SEED = 2026;    // different seed -> different key pair
    if (argc > 1) SEED = strtoull(argv[1], 0, 10);   // ./eg1 2103021 -> your own key
    rng.seed(SEED);

    cout << "==================== KEY GENERATION ====================\n";
    i128 p  = next_safe_prime(rand_range((i128)100000000000000000, (i128)900000000000000000));
    i128 n  = p - 1;
    i128 q  = n / 2;
    i128 D  = rand_range(2, p - 2);
    i128 E1 = find_primitive_root(p);
    i128 E2 = mod_pow(E1, D, p);
    cout << "Step 1 : p  = " << p << "   prime? " << (is_prime(p) ? "yes" : "no") << "\n";
    cout << "         q  = (p-1)/2 = " << q << "   prime? " << (is_prime(q) ? "yes" : "no")
         << "   -> safe prime\n";
    cout << "Step 2 : D  = " << D << "   <- the secret Eve is hunting\n";
    cout << "Step 3 : E1 = " << E1 << "   primitive root\n";
    cout << "Step 4 : E2 = E1^D mod p = " << E2 << "\n";
    cout << "Step 5 : public (E1, E2, p) = (" << E1 << ", " << E2 << ", " << p << ")\n";

    cout << "\n========== [A] SAME R USED FOR TWO MESSAGES ==========\n";
    // C1 comes out the same in both, which already announces the mistake.
    // C2b / C2a = PT2 / PT1 , so if Eve knows PT1 she gets PT2.
    i128 PT1 = 1000, PT2 = 999999, Rsame = rand_range(2, p - 2);
    i128 aC1 = mod_pow(E1, Rsame, p), aC2 = PT1 * mod_pow(E2, Rsame, p) % p;
    i128 bC1 = mod_pow(E1, Rsame, p), bC2 = PT2 * mod_pow(E2, Rsame, p) % p;
    cout << "R reused  = " << Rsame << "\n";
    cout << "cipher 1  : (" << aC1 << ", " << aC2 << ")\n";
    cout << "cipher 2  : (" << bC1 << ", " << bC2 << ")\n";
    cout << "C1 equal ? " << (aC1 == bC1 ? "YES -> R was reused\n" : "no\n");
    cout << "Eve knows PT1 = " << PT1 << "\n";
    cout << "PT2 = (C2b * C2a^-1 * PT1) mod p = " << bC2 * mod_inv(aC2, p) % p * PT1 % p
         << "   (real PT2 = " << PT2 << ")\n";

    cout << "\n========== [B] SAME R USED FOR TWO SIGNATURES ==========\n";
    // S2a = (M1 - D*S1)*R^-1 , S2b = (M2 - D*S1)*R^-1   (mod p-1)
    // subtract : S2a - S2b = (M1 - M2)*R^-1
    //   ->  R = (M1 - M2) * (S2a - S2b)^-1   mod (p-1)
    //   ->  D = (M1 - R*S2a) * S1^-1         mod (p-1)
    i128 M1 = 111111, M2 = 222222;
    i128 R = rand_range(2, n - 1) | 1;                       // R and S1 must both be
    while (gcd128(R, n) != 1 || gcd128(mod_pow(E1, R, p), n) != 1) {   // invertible mod p-1
        R += 2; if (R >= n) R = 3;
    }
    i128 S1  = mod_pow(E1, R, p);
    i128 S2a = ((M1 - D % n * (S1 % n) % n) % n + n) % n * mod_inv(R, n) % n;
    i128 S2b = ((M2 - D % n * (S1 % n) % n) % n + n) % n * mod_inv(R, n) % n;
    cout << "signature on M1 = " << M1 << " : (S1, S2a) = (" << S1 << ", " << S2a << ")\n";
    cout << "signature on M2 = " << M2 << " : (S1, S2b) = (" << S1 << ", " << S2b << ")\n";
    cout << "same S1 -> R was reused\n";
    i128 dS2 = ((S2a - S2b) % n + n) % n, dM = ((M1 - M2) % n + n) % n;
    cout << "gcd(S2a-S2b, p-1) = " << gcd128(dS2, n) << "   (needs to be 1 to invert)\n";
    i128 Rrec = dM * mod_inv(dS2, n) % n;                    // R = (M1-M2)/(S2a-S2b)
    cout << "R = (M1-M2) * (S2a-S2b)^-1 mod (p-1) = " << Rrec << "   (real R = " << R << ")\n";
    i128 top  = ((M1 - Rrec % n * (S2a % n) % n) % n + n) % n;
    i128 Drec = top * mod_inv(S1 % n, n) % n;                // D = (M1 - R*S2a)/S1
    cout << "D = (M1 - R*S2a) * S1^-1 mod (p-1)   = " << Drec << "   (real D = " << D << ")\n";
    cout << (Drec == D ? "-> PRIVATE KEY RECOVERED. Eve can now sign anything.\n"
                       : "-> failed for this R\n");

    cout << "\n========== [C] DECRYPTION ORACLE ==========\n";
    // Bob refuses to decrypt one particular cipher, but decrypts anything else.
    // Eve multiplies C2 by k, gets k*PT back, then divides by k.
    i128 secret = 424242424242, Rc = rand_range(2, p - 2), k = 7;
    i128 tC1 = mod_pow(E1, Rc, p), tC2 = secret * mod_pow(E2, Rc, p) % p;
    cout << "target cipher : (" << tC1 << ", " << tC2 << ")   Bob refuses this one\n";
    i128 fake = tC2 * k % p;
    cout << "Eve sends     : (" << tC1 << ", " << fake << ")   (C2 multiplied by k = " << k << ")\n";
    i128 reply = fake * mod_inv(mod_pow(tC1, D, p), p) % p;  // Bob decrypts, returns k*PT
    cout << "Bob replies   : " << reply << "   = k * PT\n";
    cout << "Eve divides by k : " << reply * mod_inv(k, p) % p << "   (secret was " << secret << ")\n";

    cout << "\n========== [D] p TOO SMALL -> DISCRETE LOG BY BRUTE FORCE ==========\n";
    // security rests on "given E1 and E2 = E1^D, find D". Generate a small key
    // the same proper way and a plain loop finds D at once.
    i128 ps  = next_safe_prime(400);                         // small prime, same generator
    i128 E1s = find_primitive_root(ps);
    i128 Ds  = rand_range(2, ps - 2);
    i128 E2s = mod_pow(E1s, Ds, ps);
    cout << "small key : p = " << ps << " , E1 = " << E1s << " , E2 = " << E2s
         << "   (real D = " << Ds << ")\n";
    i128 found = 0;
    for (i128 d = 1; d < ps; d++)
        if (mod_pow(E1s, d, ps) == E2s) { found = d; break; }
    cout << "loop d = 1..p-1 until E1^d == E2  ->  D = " << found
         << (found == Ds ? "   -> RECOVERED\n" : "   -> not found\n");
    cout << "With p = " << p << " that loop needs about 10^17 tries, so it never ends.\n";

    cout << "\n========== [E] LEGENDRE SYMBOL : ONE BIT ALWAYS LEAKS ==========\n";
    // Euler : x^((p-1)/2) mod p is 1 if x is a square (QR), p-1 if it is not.
    // E1 is a primitive root, so it is NOT a square. Then
    //     legendre(C2) = legendre(PT) * legendre(C1)^(D mod 2)
    // and (D mod 2) is readable from the public E2. So Eve learns whether the
    // plain text is a square, with no key at all.
    i128 PT = 987654321, Re = rand_range(2, p - 2);
    i128 eC1 = mod_pow(E1, Re, p), eC2 = PT * mod_pow(E2, Re, p) % p;
    i128 lE2 = mod_pow(E2,  q, p);                           // q = (p-1)/2
    i128 lC1 = mod_pow(eC1, q, p);
    i128 lC2 = mod_pow(eC2, q, p);
    i128 guess = (lE2 == p - 1) ? lC1 * lC2 % p : lC2;       // undo the mask
    i128 truth = mod_pow(PT, q, p);
    cout << "legendre(E2) = " << (lE2 == 1 ? "+1 (D is even)" : "-1 (D is odd)") << "\n";
    cout << "legendre(C1) = " << (lC1 == 1 ? "+1" : "-1")
         << "   legendre(C2) = " << (lC2 == 1 ? "+1" : "-1") << "\n";
    cout << "Eve says PT is " << (guess == 1 ? "a square" : "NOT a square") << "\n";
    cout << "truth    PT is " << (truth == 1 ? "a square" : "NOT a square") << "\n";
    cout << (guess == truth ? "-> correct, so ElGamal over the full group is not perfectly hiding\n"
                            : "-> wrong\n");

    cout << "\n========== [F] DEGENERATE CASES ==========\n";
    cout << "R = 0  -> C1 = " << mod_pow(E1, 0, p) << " , C2 = " << PT * mod_pow(E2, 0, p) % p
         << "   (that is PT itself, in the clear)\n";
    cout << "PT = 0 -> C2 = " << (i128)0 * mod_pow(E2, Re, p) % p
         << "   (always 0, so the cipher announces its own plain text)\n";
    cout << "PT >= p -> comes back as PT mod p, never as sent. Always keep PT < p.\n";
    return 0;
}
