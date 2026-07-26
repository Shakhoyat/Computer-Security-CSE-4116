// ===========================================================================
//  RSA -- VERSION 1 : KEY GENERATION + STRING ENCRYPTION/DECRYPTION
//  ***** THIS IS THE REFERENCE FILE -- read the CORE block once here. *****
//  Every other file (v2..v7) reuses the exact same 6 functions with only a
//  1-line comment, so if you can explain THIS file you can explain all of
//  them. No external maths library is used -- gcd, modular inverse, modular
//  exponentiation and primality testing are all written from scratch.
//  Build : g++ -O2 -o v1 rsa_v1_string.cpp     Run : ./v1
// ===========================================================================
#include <iostream>
#include <string>
using namespace std;
typedef long long ll;      // loop counters, string indices -- always small
typedef __int128 big;      // p, q, n, phi, e, d, message, cipher -- can be HUGE

// cin/cout don't know what __int128 is, so we teach cout to print one.
// (we never need to READ a big literal in THIS file -- every huge number
//  here is built at RUNTIME from ordinary "long long" seeds, e.g.
//  big p = 3000000019LL; -- but readBig() below is the fallback for the
//  rare case a lab hands you a number typed as text that is too large even
//  for a long long LITERAL, e.g. reading it from cin as a string first.)
ostream& operator<<(ostream& os, big x) {
    if (x < 0) { os << '-'; x = -x; }
    if (x > 9) os << (big)(x / 10);
    return os << (int)(x % 10);
}
big readBig(const string &s) {
    big r = 0; bool neg = false; size_t i = 0;
    if (!s.empty() && s[0] == '-') { neg = true; i = 1; }
    for (; i < s.size(); i++) r = r * 10 + (s[i] - '0');
    return neg ? -r : r;
}

// ============================================================ THE CORE ====

// ---- GCD : Euclid's algorithm, ~2300 years old -----------------------------
// gcd(a,b) = gcd(b, a mod b), repeat until b hits 0.
// example  gcd(1071, 462):  (1071,462) -> (462,147) -> (147,21) -> (21,0)
//          answer = 21
big gcd(big a, big b) { while (b) { big t = a % b; a = b; b = t; } return a; }

// ---- EXTENDED Euclid : also solves  a*x + b*y = gcd(a,b)  (Bezout) --------
// WHY we need this: to decrypt we need d = e^-1 mod phi, i.e. some d with
//     e*d = 1 (mod phi)   <=>   e*d + phi*k = 1   for some integer k
// So d is exactly the "x" that extended Euclid finds when it solves
//     e*x + phi*y = gcd(e, phi) = 1
// A solution EXISTS if and only if gcd(e,phi) = 1 -- that is precisely why
// step 4 below insists on gcd(e,phi) = 1 before accepting e as public key.
//
// Brute force ("try d = 1,2,3,... until e*d % phi == 1") is O(phi). Once
// phi passes about 10^8 that loop will not finish before the exam ends.
// Extended Euclid finds the same d in O(log phi) steps -- for phi ~ 10^19
// that is about 63 steps, instantly.
//
// worked example : e=17, phi=780  (from p=31, q=41, classic textbook pair)
//   780 = 45*17 + 15        17 = 1*15 + 2        15 = 7*2 + 1       2=2*1+0
// unwind from the bottom (back-substitution):
//   1 = 15 - 7*2
//   1 = 15 - 7*(17 - 1*15) = 8*15 - 7*17
//   1 = 8*(780-45*17) - 7*17 = 8*780 - 367*17
//   => 17*(-367) + 780*8 = 1   => x = -367 -> d = (-367 mod 780) = 413
//   check: (17*413) mod 780 = 7021 mod 780 = 1   CORRECT
big extGCD(big a, big b, big &x, big &y) {
    if (b == 0) { x = 1; y = 0; return a; }
    big x1, y1;
    big g = extGCD(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return g;
}
big modInverse(big e, big phi) {
    big x, y;
    extGCD(e, phi, x, y);
    return ((x % phi) + phi) % phi;      // C++ '%' can return negative, fix it
}

// ---- modular exponentiation : base^exp mod m, O(log exp) squarings -------
// square-and-multiply: read exp in binary, square every step, multiply in
// only on the 1-bits.        example  3^13 mod 7      13 = 1101(2)
//   start r=1, base=3
//   bit 1 (LSB) -> r = 1*3 %7 = 3        base = 3*3%7 = 2
//   bit 0       -> r stays 3             base = 2*2%7 = 4
//   bit 1       -> r = 3*4 %7 = 5        base = 4*4%7 = 2
//   bit 1 (MSB) -> r = 5*2 %7 = 3        base = 2*2%7 = 4
//   answer = 3   (check: 3^13 = 1594323 = 7*227760 + 3 -- correct)
// only ceil(log2(exp)) multiplications instead of exp-1 -- for exp ~ 10^18
// that is ~60 multiplications instead of a quintillion.
big modPow(big base, big exp, big m) {
    big r = 1; base %= m; if (base < 0) base += m;
    while (exp > 0) {
        if (exp & 1) r = (r * base) % m;
        base = (base * base) % m;
        exp >>= 1;
    }
    return r;
}
// SAFETY NOTE -- why __int128 and not long long:
// the dangerous line above is "base * base". It only stays correct while
// that product fits in the type, i.e. while base*base < TYPE_MAX.
//     long long max ~ 9.2 * 10^18   -> safe only while modulus n <  ~3   *10^9
//     __int128  max ~ 1.7 * 10^38   -> safe while modulus n stays < ~1.3 *10^19
// __int128 does not just "let you print bigger numbers" -- it moves the
// point where multiplication silently breaks from a 10-digit modulus to a
// 19-digit modulus. STEP 9 below shows this bug happening live, in both
// directions (a value too big to even STORE in long long, and a value that
// fits fine but still breaks long long's multiplication).

// ---- Miller-Rabin primality test ------------------------------------------
// Trial division ("try every i up to sqrt(n)") is O(sqrt n): fine for
// n ~ 10^6, needs ~10^9 divisions for n ~ 10^18 (minutes -- unusable live).
// Miller-Rabin runs in O(k * log^3 n) and is what real crypto libraries use.
//   Fermat's little theorem: if n is prime, a^(n-1) = 1 (mod n) for any
//   0 < a < n. Write n-1 = 2^r * d with d odd. Then the chain
//       a^d, a^(2d), a^(4d), ... , a^((2^r)*d) = a^(n-1)
//   must end at 1 (mod n) if n is prime. The entry right BEFORE the first 1
//   can only legally be n-1 (i.e. -1) -- because working modulo a PRIME,
//   x^2 = 1 has only the two solutions x = 1 or x = -1. If we ever see some
//   OTHER square root of 1, n cannot be prime. Testing several random bases
//   "a" catches essentially all composites; the 12 witnesses below make the
//   test fully DETERMINISTIC (no error probability) for every n < 3.3*10^24.
bool isPrime(big n) {
    if (n < 2) return false;
    for (big p : {2,3,5,7,11,13,17,19,23,29,31,37})
        if (n % p == 0) return n == p;
    big d = n - 1; int r = 0;
    while (d % 2 == 0) { d /= 2; r++; }
    for (big a : {2,3,5,7,11,13,17,19,23,29,31,37}) {
        if (a >= n) continue;
        big x = modPow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool compositeWitness = true;
        for (int i = 0; i < r - 1; i++) {
            x = (x * x) % n;
            if (x == n - 1) { compositeWitness = false; break; }
        }
        if (compositeWitness) return false;     // found a non-trivial root of 1
    }
    return true;
}

// keep searching odd numbers upward until isPrime says yes -- this is
// literally how real RSA key generation picks p and q.
big nextPrime(big start) {
    big x = (start % 2 == 0) ? start + 1 : start;
    while (!isPrime(x)) x += 2;
    return x;
}

int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }
// ======================================================== END OF CORE =====

int main() {
    // ---- STEP 1 : choose two distinct primes ------------------------------
    big p = 61, q = 53;
    cout << "STEP 1  p = " << p << " (prime? " << isPrime(p) << "), "
         << "q = " << q << " (prime? " << isPrime(q) << ")\n";

    // ---- STEP 2 : modulus n = p*q  -----------------------------------------
    big n = p * q;
    cout << "STEP 2  n = p*q = " << n
         << "   (n must be > 255 so every ASCII char fits as one block)\n";

    // ---- STEP 3 : Euler totient phi = (p-1)(q-1) ---------------------------
    // phi(n) counts integers in [1,n] coprime to n. For a PRIME p, every one
    // of 1..p-1 is coprime to p, so phi(p) = p-1. Because phi is
    // multiplicative and gcd(p,q)=1: phi(n) = phi(p)*phi(q) = (p-1)(q-1).
    big phi = (p - 1) * (q - 1);
    cout << "STEP 3  phi = (p-1)(q-1) = " << phi << "\n";

    // ---- STEP 4 : public exponent e, with 1 < e < phi and gcd(e,phi) = 1 --
    big e = 2;
    while (e < phi && gcd(e, phi) != 1) e++;
    if (gcd(17, phi) == 1) e = 17;                 // prefer the classic e = 17
    cout << "STEP 4  e = " << e << "   (gcd(e,phi) = " << gcd(e, phi) << ")\n";

    // ---- STEP 5 : private exponent d = e^-1 mod phi via EXTENDED EUCLID ---
    big bx, by;
    big g = extGCD(e, phi, bx, by);
    big d = modInverse(e, phi);
    cout << "STEP 5  extGCD(e,phi): " << e << "*(" << bx << ") + " << phi
         << "*(" << by << ") = " << g << "\n";
    cout << "        d = " << d << "   check: (e*d) mod phi = "
         << (e * d) % phi << "  (must be 1)\n";

    cout << "\n  PUBLIC  KEY (n, e) = (" << n << ", " << e << ")\n";
    cout << "  PRIVATE KEY (n, d) = (" << n << ", " << d << ")\n";

    // =========================================================================
    //  WHY DOES  (m^e)^d mod n  GIVE BACK  m ?   -- the one proof that matters
    // =========================================================================
    //  Euler's theorem: if gcd(m,n) = 1, then  m^phi(n) = 1 (mod n).
    //  We picked d so that e*d = 1 (mod phi), i.e. e*d = 1 + k*phi for some
    //  integer k. So:
    //      (m^e)^d = m^(e*d) = m^(1 + k*phi) = m * (m^phi)^k = m * 1^k = m
    //                                                  ^^^^^^^^^^ Euler's thm
    //  That single substitution is the entire correctness proof of RSA.
    //  (the rare case gcd(m,n) != 1 needs a slightly longer CRT-based proof
    //   on p and q separately -- not needed here since every message byte
    //   m < n and n = p*q with p,q prime, so gcd(m,n)=1 for any m that is
    //   not itself a multiple of p or q.)
    big sample = 42;
    cout << "\n  Euler-theorem check with m=" << sample << " :  m^phi mod n = "
         << modPow(sample, phi, n) << "  (must be 1)\n\n";

    // ---- STEP 6 : encrypt the message, one character at a time -------------
    const char* msg = "Ashik111";
    int len = myLength(msg);
    big cipher[100];

    cout << "STEP 6  ENCRYPTION   c = m^e mod n\n";
    cout << "  i  char   m     c\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        big m = (big)(unsigned char)msg[i];        // char -> ASCII number
        cipher[i] = modPow(m, e, n);
        cout << "  " << i << "   '" << msg[i] << "'   " << m
             << "   " << cipher[i] << "\n";
    }

    // ---- STEP 7 : decrypt ---------------------------------------------------
    char plain[101];
    cout << "\nSTEP 7  DECRYPTION   m = c^d mod n\n";
    cout << "  i    c     m   char\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        big m = modPow(cipher[i], d, n);
        plain[i] = (char)(ll)m;
        cout << "  " << i << "  " << cipher[i] << "   " << m
             << "   '" << plain[i] << "'\n";
    }
    plain[len] = '\0';

    // ---- STEP 8 : verify ------------------------------------------------------
    bool same = true;
    for (int i = 0; i < len; i++) if (msg[i] != plain[i]) same = false;
    cout << "\nSTEP 8  original  = \"" << msg << "\"\n";
    cout << "        recovered = \"" << plain << "\"\n";
    cout << "        result    = " << (same ? "MATCH" : "MISMATCH") << "\n";

    // =========================================================================
    //  STEP 9 : WHY __int128?  -- overflow demonstrated LIVE, both ways
    // =========================================================================
    cout << "\n========== STEP 9 : WHY __int128 (overflow demo) ==========\n";

    // ---- 9A : n fits comfortably in long long, but base*base still doesn't -
    big p3 = nextPrime((big)1000000), q3 = nextPrime((big)2000000);
    big n3 = p3 * q3, phi3 = (p3 - 1) * (q3 - 1);
    big e3 = 17, d3 = modInverse(e3, phi3);
    cout << "9A  p3=" << p3 << " q3=" << q3 << " -> n3=" << n3
         << "  (fits fine in a long long, whose max is 9223372036854775807)\n";

    ll base = 65 % (ll)n3, exp3 = (ll)e3, mUnsafe = (ll)n3;   // plain long long copy
    ll rUnsafe = 1;
    while (exp3 > 0) {                        // SAME algorithm, but in "ll" not "big"
        if (exp3 & 1) rUnsafe = (rUnsafe * base) % mUnsafe;    // <-- overflows here
        base = (base * base) % mUnsafe;                        // <-- and here
        exp3 >>= 1;
    }
    big rSafe = modPow(65, e3, n3);
    cout << "    long long modPow(65,17,n3) = " << rUnsafe
         << "   (WRONG -- silently overflowed, no crash, no warning)\n";
    cout << "    __int128  modPow(65,17,n3) = " << rSafe << "   (correct)\n";
    cout << "    decrypt the correct value back: " << modPow(rSafe, d3, n3)
         << "  (must be 65)\n\n";

    // ---- 9B : a value that does not even FIT in a long long variable -------
    big p2 = nextPrime((big)3000000000LL), q2 = nextPrime((big)3500000000LL);
    big n2 = p2 * q2, phi2 = (p2 - 1) * (q2 - 1);
    cout << "9B  p2=" << p2 << " q2=" << q2 << "\n";
    cout << "    n2   = " << n2   << "\n";
    cout << "    phi2 = " << phi2 << "\n";
    cout << "    long long max is only 9223372036854775807 -- both numbers above\n";
    cout << "    are BIGGER than that. Forcing n2 into a 'long long' variable gives:\n";
    ll broken = (ll)n2;
    cout << "    (long long)n2 = " << broken << "   <-- garbage, wrapped around\n\n";

    big e2 = 65537;                                  // classic real-world exponent
    cout << "    gcd(e2, phi2) = " << gcd(e2, phi2) << " (must be 1)\n";
    big d2 = modInverse(e2, phi2);
    cout << "    brute force (try every d) would need up to phi2 = " << phi2
         << " tries -- at 10^9 tries/sec that is over 300 YEARS.\n";
    cout << "    extended Euclid needs only about log2(phi2) =~ 63 steps -- instant.\n";
    cout << "    d2 = " << d2 << "   check (e2*d2) mod phi2 = " << (e2 * d2) % phi2 << "\n";

    big m2 = 123456789;
    big c2 = modPow(m2, e2, n2);
    big back2 = modPow(c2, d2, n2);
    cout << "    m2=" << m2 << "  ->  c2=" << c2 << "  ->  decrypted=" << back2
         << "  ->  " << (back2 == m2 ? "MATCH" : "MISMATCH") << "\n";
    cout << "    every one of n2, phi2, e2, d2, c2 lives safely inside __int128,\n";
    cout << "    a range no lab-sized RSA key you will be given can escape.\n";
    return 0;
}
