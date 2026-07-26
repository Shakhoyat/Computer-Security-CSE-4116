// ===========================================================================
//  RSA -- VERSION 7 : Three More Classic Attacks
//    A. COMMON MODULUS ATTACK      -- same n reused for two different e's
//    B. FERMAT FACTORIZATION       -- p and q chosen too close together
//    C. WIENER'S ATTACK            -- private exponent d chosen too small
//  Core toolkit derivations are explained in full in rsa_v1_string.cpp.
//  Build : g++ -O2 -o v7 rsa_v7_attacks2.cpp
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
bool isPrime(big n) {
    if (n < 2) return false;
    for (big p : {2,3,5,7,11,13,17,19,23,29,31,37}) if (n % p == 0) return n == p;
    big d = n - 1; int r = 0; while (d % 2 == 0) { d /= 2; r++; }
    for (big a : {2,3,5,7,11,13,17,19,23,29,31,37}) {
        if (a >= n) continue;
        big x = modPow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool bad = true;
        for (int i = 0; i < r - 1; i++) { x = (x * x) % n; if (x == n - 1) { bad = false; break; } }
        if (bad) return false;
    }
    return true;
}
big nextPrime(big start) { big x = (start % 2 == 0) ? start + 1 : start; while (!isPrime(x)) x += 2; return x; }

// integer square root (largest r with r*r <= x), needed by attacks B and C
// since __int128 has no built-in sqrt(). Binary search bit-by-bit -- 64
// iterations, always exact (no floating point rounding errors involved).
big isqrt(big x) {
    big r = 0;
    for (big bit = (big)1 << 63; bit > 0; bit >>= 1) {
        big next = r + bit;
        if (next * next <= x) r = next;
    }
    return r;
}

int main() {
    // =========================================================================
    //  ATTACK A : COMMON MODULUS ATTACK
    //  Two "users" are (badly) set up to share the SAME modulus n but
    //  different public exponents e1, e2 with gcd(e1,e2) = 1. The SAME
    //  message m is encrypted once for each: c1 = m^e1 mod n, c2 = m^e2 mod n.
    //  Since gcd(e1,e2)=1, extended Euclid gives integers a,b with
    //        a*e1 + b*e2 = 1
    //  so     c1^a * c2^b = m^(a*e1) * m^(b*e2) = m^(a*e1 + b*e2) = m^1 = m
    //  Eve recovers m using ONLY the two public exponents and two
    //  ciphertexts -- no private key, no factoring, needed at all.
    // =========================================================================
    cout << "===== ATTACK A : COMMON MODULUS =====\n";
    big p = 61, q = 53, n = p * q;
    big e1 = 17, e2 = 257;                                  // gcd(e1,e2) must be 1
    cout << "  shared n=" << n << "   e1=" << e1 << "  e2=" << e2
         << "   gcd(e1,e2)=" << gcd(e1, e2) << "\n";

    big m = 65;                                              // secret message 'A'
    big c1 = modPow(m, e1, n), c2 = modPow(m, e2, n);
    cout << "  Alice encrypts the SAME m=" << m << " for both users:\n";
    cout << "  c1 = m^e1 mod n = " << c1 << "\n  c2 = m^e2 mod n = " << c2 << "\n";

    big a, b;
    extGCD(e1, e2, a, b);                                   // a*e1 + b*e2 = 1
    cout << "  extGCD(e1,e2): " << e1 << "*(" << a << ") + " << e2 << "*(" << b << ") = 1\n";

    big part1 = (a >= 0) ? modPow(c1, a, n) : modInverse(modPow(c1, -a, n), n);
    big part2 = (b >= 0) ? modPow(c2, b, n) : modInverse(modPow(c2, -b, n), n);
    big recovered = (part1 * part2) % n;
    cout << "  Eve computes c1^a * c2^b mod n = " << recovered
         << "   (real message was " << m << ")\n";
    cout << "  " << (recovered == m ? "RECOVERED with NO private key" : "failed") << "\n";
    cout << "  FIX: never reuse the same n for two different key pairs.\n\n";

    // =========================================================================
    //  ATTACK B : FERMAT FACTORIZATION  (p and q picked too close together)
    //  If n = p*q with p,q close, write n = a^2 - b^2 = (a-b)(a+b), a "sum of
    //  squares" trick that works because a = (p+q)/2, b = (q-p)/2 are close
    //  to sqrt(n) whenever p and q are close to each other.
    //  Algorithm: start a = ceil(sqrt(n)); increase a by 1 each round until
    //  a^2 - n is a PERFECT SQUARE b^2. Then p = a-b, q = a+b.
    // =========================================================================
    cout << "===== ATTACK B : FERMAT FACTORIZATION =====\n";
    big fp = nextPrime((big)100000), fq = nextPrime(fp + 2);  // deliberately close!
    big fn = fp * fq;
    cout << "  vulnerable primes chosen too close: p=" << fp << "  q=" << fq
         << "   n=" << fn << "\n";

    big fa = isqrt(fn); if (fa * fa < fn) fa++;
    big fb, steps = 0;
    while (true) {
        steps++;
        big b2 = fa * fa - fn;
        fb = isqrt(b2);
        if (fb * fb == b2) break;
        fa++;
    }
    cout << "  Fermat's method needed only " << steps << " tries to find a perfect square\n";
    cout << "  recovered p=" << (fa - fb) << "  q=" << (fa + fb)
         << "   (check p*q=" << (fa - fb) * (fa + fb) << ")\n";
    cout << "  compare: trial division would need up to sqrt(n) =~ " << isqrt(fn)
         << " tries\n";
    cout << "  FIX: p and q must differ in length by several digits, chosen\n";
    cout << "       independently at random -- never as 'a prime near another prime'.\n\n";

    // =========================================================================
    //  ATTACK C : WIENER'S ATTACK  (private exponent d chosen too small)
    //  From e*d = 1 + k*phi (the same equation modInverse solves), dividing
    //  both sides by n*d gives  e/n =~ k/d  (since phi is always close to n).
    //  So the REAL d shows up as a DENOMINATOR in the continued-fraction
    //  expansion of e/n. Wiener (1990) proved this recovers d whenever
    //  d < (1/3) * n^(1/4) -- i.e. "small d" is fatal, no matter how big e is.
    // =========================================================================
    cout << "===== ATTACK C : WIENER (small private exponent) =====\n";
    big wp = nextPrime((big)3000000), wq = nextPrime((big)4000000);
    big wn = wp * wq, wphi = (wp - 1) * (wq - 1);

    big d_secret = 101;                                  // deliberately TINY
    while (gcd(d_secret, wphi) != 1) d_secret += 2;
    big e_pub = modInverse(d_secret, wphi);               // looks like a normal e

    big bound = isqrt(isqrt(wn)) / 3;                      // ~ (1/3) n^(1/4)
    cout << "  n=" << wn << "   secret d=" << d_secret
         << "   Wiener bound (1/3)n^1/4 =~ " << bound
         << "   (" << (d_secret < bound ? "d IS inside the danger zone" : "safe") << ")\n";
    cout << "  public exponent e = " << e_pub << "  (looks perfectly random to Eve)\n";

    // expand e_pub / wn as a continued fraction, test every convergent
    // denominator as a candidate d
    big ca = e_pub, cb = wn;
    big numer2 = 0, numer1 = 1, denom2 = 1, denom1 = 0;   // p_{-2}=0,p_{-1}=1,q_{-2}=1,q_{-1}=0
    bool found = false; big foundD = 0, foundP = 0, foundQ = 0;
    while (cb != 0 && !found) {
        big cq = ca / cb;
        big numer = cq * numer1 + numer2;
        big denom = cq * denom1 + denom2;
        if (numer != 0 && (e_pub * denom - 1) % numer == 0) {
            big phiCand = (e_pub * denom - 1) / numer;
            big sum = wn - phiCand + 1;                    // candidate p+q
            big disc = sum * sum - 4 * wn;                 // candidate (p-q)^2
            if (disc >= 0) {
                big root = isqrt(disc);
                if (root * root == disc && (sum - root) % 2 == 0) {
                    big cp = (sum - root) / 2, cqq = (sum + root) / 2;
                    if (cp > 1 && cqq > 1 && cp * cqq == wn) {
                        found = true; foundD = denom; foundP = cp; foundQ = cqq;
                    }
                }
            }
        }
        big t = ca % cb; ca = cb; cb = t;
        numer2 = numer1; numer1 = numer;
        denom2 = denom1; denom1 = denom;
    }
    cout << "  Eve, using ONLY (e_pub, n): recovered d = " << foundD
         << "   (matches secret d? " << (foundD == d_secret ? "YES" : "no") << ")\n";
    cout << "  and factored n as p=" << foundP << " q=" << foundQ << "\n";
    cout << "  FIX: always require d > n^0.25 (in practice d is chosen the same\n";
    cout << "       size as phi, never picked small 'for speed').\n";
    return 0;
}
