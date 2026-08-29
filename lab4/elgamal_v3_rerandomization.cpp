// ElGamal Re-randomization - turn a cipher text into a completely different
// looking cipher text of the SAME plain text, using only the public key.
//
//   old : C1  = E1^R mod p             C2  = (PT * E2^R) mod p
//   new : C1' = C1 * E1^R' mod p       C2' = C2 * E2^R' mod p
//
//   C1' = E1^(R+R') and C2' = PT * E2^(R+R') , so the plain text never moved,
//   only the random part did. Used in mix-nets and e-voting so nobody can match
//   an incoming ballot to an outgoing ballot.
//
// build : g++ -O2 -o eg3 elgamal_v3_rerandomization.cpp        run : ./eg3
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
    i128 PT = 20;                      // plain text, must be < p
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

    cout << "\n==================== ORIGINAL CIPHER (Alice) ====================\n";
    i128 R  = rand_range(2, p - 2);
    i128 C1 = mod_pow(E1, R, p);                    // C1 = E1^R mod p
    i128 C2 = PT % p * mod_pow(E2, R, p) % p;       // C2 = PT * E2^R mod p
    cout << "PT = " << PT << " , R = " << R << "\n";
    cout << "C1 = E1^R mod p        = " << C1 << "\n";
    cout << "C2 = (PT * E2^R) mod p = " << C2 << "\n";

    cout << "\n==================== RE-RANDOMIZE (mix server) ====================\n";
    i128 Rn = rand_range(2, p - 2);                 // must never be 0
    cout << "fresh random R' = " << Rn << "   (only the public key is used below)\n";
    i128 C1n = C1 * mod_pow(E1, Rn, p) % p;         // C1' = C1 * E1^R' mod p
    i128 C2n = C2 * mod_pow(E2, Rn, p) % p;         // C2' = C2 * E2^R' mod p
    cout << "E1^R' mod p = " << mod_pow(E1, Rn, p) << "\n";
    cout << "E2^R' mod p = " << mod_pow(E2, Rn, p) << "\n";
    cout << "C1' = (C1 * E1^R') mod p = " << C1n << "\n";
    cout << "C2' = (C2 * E2^R') mod p = " << C2n << "\n";
    cout << "old pair = (" << C1  << ", " << C2  << ")\n";
    cout << "new pair = (" << C1n << ", " << C2n << ")\n";
    cout << (C1 != C1n && C2 != C2n ? "-> nothing in common, yet PT is untouched\n" : "-> no change\n");

    cout << "\n==================== DECRYPT THE NEW PAIR (Bob) ====================\n";
    i128 s = mod_pow(C1n, D, p);
    cout << "C1'^D mod p      = " << s << "\n";
    cout << "(C1'^D)^-1 mod p = " << mod_inv(s, p) << "\n";
    i128 dec = C2n * mod_inv(s, p) % p;             // PT = C2' * (C1'^D)^-1 mod p
    cout << "PT = [C2' * (C1'^D)^-1] mod p = " << dec << "\n";
    cout << (dec == PT ? "-> MATCH, same plain text\n" : "-> MISMATCH\n");

    cout << "\n==================== PROOF : R SIMPLY BECAME R+R' ====================\n";
    i128 dC1 = mod_pow(E1, R + Rn, p);
    i128 dC2 = PT % p * mod_pow(E2, R + Rn, p) % p;
    cout << "encrypt(PT, R+R') = (" << dC1 << ", " << dC2 << ")\n";
    cout << "re-randomized     = (" << C1n << ", " << C2n << ")\n";
    cout << (dC1 == C1n && dC2 == C2n ? "-> identical\n" : "-> different\n");

    cout << "\n==================== SMALL MIX-NET (3 BALLOTS) ====================\n";
    i128 vote[3] = {1001, 1002, 1003};
    i128 a[3], b[3];
    for (int i = 0; i < 3; i++) {                   // voters encrypt
        i128 r = rand_range(2, p - 2);
        a[i] = mod_pow(E1, r, p);
        b[i] = vote[i] % p * mod_pow(E2, r, p) % p;
        cout << "ballot " << i + 1 << " in  : C1 = " << a[i] << "\n";
    }
    for (int i = 0; i < 3; i++) {                   // server refreshes each one
        i128 r = rand_range(2, p - 2);
        a[i] = a[i] * mod_pow(E1, r, p) % p;
        b[i] = b[i] * mod_pow(E2, r, p) % p;
    }
    swap(a[0], a[2]); swap(b[0], b[2]);             // and shuffles them
    for (int i = 0; i < 3; i++) {
        i128 v = b[i] * mod_inv(mod_pow(a[i], D, p), p) % p;
        cout << "ballot " << i + 1 << " out : C1 = " << a[i] << "  -> vote " << v << "\n";
    }
    cout << "Same three votes counted, but no output pair matches any input pair.\n";

    cout << "\nNOTE : R' = 0 changes nothing (E1^0 = E2^0 = 1), so a mix server\n";
    cout << "       must never pick R' = 0.\n";
    return 0;
}
