// ===========================================================================
//  RSA -- VERSION 5 : Why "Textbook RSA" Is Not Safe  (3 attacks)
//
//  Versions 1-4 all use RAW RSA: c = m^e mod n with no padding. That is fine
//  for a lab but broken in practice. This file breaks it three different ways.
//  (n here is deliberately kept SMALL on purpose -- that smallness IS the
//   vulnerability being demonstrated. See rsa_v7_attacks2.cpp for attacks
//   that work even on more realistic key sizes.)
//  Core toolkit derivations are explained in full in rsa_v1_string.cpp.
//  Build : g++ -O2 -o v5 rsa_v5_attacks.cpp
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;
typedef __int128 big;

ostream& operator<<(ostream& os, big x) {
    if (x < 0) { os << '-'; x = -x; }
    if (x > 9) os << (big)(x / 10);
    return os << (int)(x % 10);
}
big gcd(big a, big b) { while (b) { big t = a % b; a = b; b = t; } return a; }
big extGCD(big a, big b, big &x, big &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    big x1, y1, g = extGCD(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1; return g;
}
big modInverse(big e, big phi) { big x, y; extGCD(e, phi, x, y); return ((x % phi) + phi) % phi; }
big modPow(big base, big exp, big m) {
    big r = 1; base %= m; if (base < 0) base += m;
    while (exp > 0) { if (exp & 1) r = (r * base) % m; base = (base * base) % m; exp >>= 1; }
    return r;
}
int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }

int main() {
    big p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    big e = 17, d = modInverse(e, phi);

    // =========================================================================
    //  ATTACK 1 : RSA WITHOUT PADDING IS DETERMINISTIC
    //  Same plaintext char always gives the same ciphertext number, so
    //  char-by-char RSA is really just a monoalphabetic substitution cipher
    //  and dies to frequency analysis -- exactly like the Caesar cipher.
    // =========================================================================
    const char* msg = "SEE THE SEEDS";
    int len = myLength(msg);
    big c[100];
    for (int i = 0; i < len; i++) c[i] = modPow((big)(unsigned char)msg[i], e, n);

    cout << "ATTACK 1 : DETERMINISM  (public key alone is enough)\n";
    cout << "  plaintext  : \"" << msg << "\"\n  ciphertext : ";
    for (int i = 0; i < len; i++) cout << c[i] << " ";
    cout << "\n  Eve counts how often each ciphertext number repeats:\n";
    big top = 0; int topCount = 0;
    for (int i = 0; i < len; i++) {
        int first = 1, count = 0;
        for (int j = 0; j < len; j++) {
            if (c[j] == c[i]) count++;
            if (j < i && c[j] == c[i]) first = 0;
        }
        if (first && count > 1) cout << "    " << c[i] << " appears " << count << " times\n";
        if (count > topCount) { topCount = count; top = c[i]; }
    }
    cout << "  most frequent = " << top << " (" << topCount
         << " times) -> in English that is almost certainly 'E'\n";
    cout << "  Eve can also just encrypt every letter herself with the PUBLIC key\n";
    cout << "  and build a full lookup table -- no private key needed.\n";
    cout << "  FIX: random padding (OAEP) so the same char never repeats.\n\n";

    // =========================================================================
    //  ATTACK 2 : SMALL MODULUS -> FACTOR n AND REBUILD THE PRIVATE KEY
    //  RSA's whole security is "factoring n is hard". For a small n it is not.
    //  (trial division is used here ON PURPOSE, not Miller-Rabin -- Eve does
    //   not know p or q, only n, so she must search for a factor.)
    // =========================================================================
    cout << "ATTACK 2 : FACTORING  (Eve knows only the public key " << n
         << ", " << e << ")\n";
    big fp = 0, fq = 0, tries = 0;
    for (big i = 2; i * i <= n; i++) { tries++; if (n % i == 0) { fp = i; fq = n / i; break; } }
    big fphi = (fp - 1) * (fq - 1);
    big fd = modInverse(e, fphi);
    cout << "  after " << tries << " trial divisions:  n = " << fp << " x " << fq << "\n";
    cout << "  phi = " << fphi << "   ->   recovered d = " << fd
         << "   (true d = " << d << ")\n";
    cout << "  Eve now decrypts: first char = '"
         << (char)(ll)modPow(c[0], fd, n) << "'\n";
    cout << "  FIX: use n of 2048 bits or more, so factoring takes longer than\n";
    cout << "       the age of the universe.\n\n";

    // =========================================================================
    //  ATTACK 3 : SMALL EXPONENT e = 3 WITH NO PADDING
    //  If m^e is still smaller than n, the "mod n" never actually reduces
    //  anything, so c = m^e as plain integers and Eve just takes the e-th root.
    // =========================================================================
    big bp = 1013, bq = 1019, bn = bp * bq;        // n = 1032247
    big be = 3;
    big m = 65;                                     // the letter 'A'
    big bc = modPow(m, be, bn);
    cout << "ATTACK 3 : SMALL EXPONENT  (n = " << bn << ", e = 3)\n";
    cout << "  m = " << m << ", c = m^3 mod n = " << bc << "\n";
    cout << "  m^3 = " << (m * m * m) << " which is SMALLER than n, so 'mod n' did nothing.\n";
    big root = 0;
    while ((root + 1) * (root + 1) * (root + 1) <= bc) root++;   // integer cube root
    cout << "  Eve takes the plain cube root of " << bc << "  ->  m = " << root
         << " = '" << (char)(ll)root << "'   NO private key used.\n";
    cout << "  FIX: padding makes m huge, so m^e always wraps around n.\n";
    return 0;
}
