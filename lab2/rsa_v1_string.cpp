// ===========================================================================
//  RSA -- VERSION 1 : String Encryption / Decryption
//  No built-in maths library is used. gcd, modular exponentiation, modular
//  inverse, primality test and string length are all written from scratch.
//  Build : g++ -o v1 rsa_v1_string.cpp     Run : ./v1
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;

// --------------------------------------------------------------- THE CORE
// (these 5 functions are reused by EVERY version -- memorise this block)

// length of a C-string : count until the '\0' terminator
int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }

// gcd by Euclid : keep replacing (a,b) with (b, a mod b) until b becomes 0
ll gcd(ll a, ll b) { while (b != 0) { ll t = a % b; a = b; b = t; } return a; }

// (base^exp) mod m by square-and-multiply : O(log exp) instead of O(exp)
ll modPow(ll base, ll exp, ll m) {
    ll result = 1;
    base = base % m;                       // shrink the base first
    while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % m;   // bit is 1 -> multiply
        base = (base * base) % m;                         // square for next bit
        exp = exp / 2;                                    // drop the used bit
    }
    return result;
}

// modular inverse : the d that satisfies (e * d) mod phi == 1
ll modInverse(ll e, ll phi) {
    for (ll d = 2; d < phi; d++) if ((e * d) % phi == 1) return d;
    return -1;                             // -1 means no inverse exists
}

// trial division up to sqrt(n) -- note i*i<=n avoids needing sqrt()
bool isPrime(ll n) {
    if (n < 2) return false;
    for (ll i = 2; i * i <= n; i++) if (n % i == 0) return false;
    return true;
}
// ------------------------------------------------------------ END OF CORE

int main() {
    // ---- STEP 1 : choose two distinct primes ----------------------------
    ll p = 61, q = 53;
    cout << "STEP 1  p = " << p << " (prime? " << isPrime(p) << "), "
         << "q = " << q << " (prime? " << isPrime(q) << ")\n";

    // ---- STEP 2 : modulus n = p*q  --------------------------------------
    ll n = p * q;
    cout << "STEP 2  n = p*q = " << n
         << "   (MUST be > 255 so every ASCII char fits)\n";

    // ---- STEP 3 : Euler totient phi = (p-1)(q-1) ------------------------
    ll phi = (p - 1) * (q - 1);
    cout << "STEP 3  phi = (p-1)(q-1) = " << phi << "\n";

    // ---- STEP 4 : public exponent e, with 1 < e < phi and gcd(e,phi)=1 --
    ll e = 2;
    while (e < phi && gcd(e, phi) != 1) e++;
    if (e < 17 && gcd(17, phi) == 1) e = 17;      // prefer the classic e = 17
    cout << "STEP 4  e = " << e << "   (gcd(e,phi) = " << gcd(e, phi) << ")\n";

    // ---- STEP 5 : private exponent d = e^-1 mod phi ---------------------
    ll d = modInverse(e, phi);
    cout << "STEP 5  d = " << d << "   check: (e*d) mod phi = "
         << (e * d) % phi << "\n";

    cout << "\n  PUBLIC  KEY (n, e) = (" << n << ", " << e << ")\n";
    cout << "  PRIVATE KEY (n, d) = (" << n << ", " << d << ")\n\n";

    // ---- STEP 6 : encrypt the message, one character at a time ----------
    const char* msg = "Ashik111";
    int len = myLength(msg);
    ll cipher[100];

    cout << "STEP 6  ENCRYPTION   c = m^e mod n\n";
    cout << "  i  char   m     c\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        ll m = (ll)(unsigned char)msg[i];      // char -> ASCII number
        cipher[i] = modPow(m, e, n);
        cout << "  " << i << "   '" << msg[i] << "'   " << m
             << "   " << cipher[i] << "\n";
    }

    // ---- STEP 7 : decrypt -----------------------------------------------
    char plain[101];
    cout << "\nSTEP 7  DECRYPTION   m = c^d mod n\n";
    cout << "  i    c     m   char\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        ll m = modPow(cipher[i], d, n);
        plain[i] = (char)m;
        cout << "  " << i << "  " << cipher[i] << "   " << m
             << "   '" << plain[i] << "'\n";
    }
    plain[len] = '\0';

    // ---- STEP 8 : verify -------------------------------------------------
    int same = 1;
    for (int i = 0; i < len; i++) if (msg[i] != plain[i]) same = 0;
    cout << "\nSTEP 8  original  = \"" << msg << "\"\n";
    cout << "        recovered = \"" << plain << "\"\n";
    cout << "        result    = " << (same ? "MATCH" : "MISMATCH") << "\n";
    return 0;
}
