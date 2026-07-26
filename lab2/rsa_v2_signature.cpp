// ===========================================================================
//  RSA -- VERSION 2 : Digital Signature  (authenticity + integrity)
//
//  Encryption uses the PUBLIC key to lock and the PRIVATE key to unlock.
//  A signature is the SAME maths run BACKWARDS:
//        sign   with the PRIVATE key  ->  only the owner can produce it
//        verify with the PUBLIC  key  ->  anybody can check it
//  Core toolkit derivations (gcd/extGCD/modPow/Miller-Rabin) are explained
//  in full in rsa_v1_string.cpp -- this file only comments the NEW idea.
//  Build : g++ -O2 -o v2 rsa_v2_signature.cpp
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;
typedef __int128 big;                 // see v1 STEP 9 for why not "ll"

ostream& operator<<(ostream& os, big x) {
    if (x < 0) { os << '-'; x = -x; }
    if (x > 9) os << (big)(x / 10);
    return os << (int)(x % 10);
}
big gcd(big a, big b) { while (b) { big t = a % b; a = b; b = t; } return a; }
big extGCD(big a, big b, big &x, big &y) {                 // Bezout: ax+by=gcd(a,b)
    if (b == 0) { x = 1; y = 0; return a; }
    big x1, y1, g = extGCD(b, a % b, x1, y1);
    x = y1; y = x1 - (a / b) * y1; return g;
}
big modInverse(big e, big phi) {                            // d = e^-1 mod phi
    big x, y; extGCD(e, phi, x, y); return ((x % phi) + phi) % phi;
}
big modPow(big base, big exp, big m) {                       // base^exp mod m
    big r = 1; base %= m; if (base < 0) base += m;
    while (exp > 0) { if (exp & 1) r = (r * base) % m; base = (base * base) % m; exp >>= 1; }
    return r;
}
int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }

// A tiny hash: fold the whole message into ONE number smaller than n.
// h starts at 7, and every character does  h = h*31 + c  (mod n).
// Changing any single character changes h completely -> tampering is visible.
// (this is a TEACHING hash, not SHA-256 -- real signatures always hash with a
//  cryptographic hash function first; the RSA maths shown here is identical
//  either way, only the size/quality of "h" changes.)
big simpleHash(const char* s, big n) {
    big h = 7;
    for (int i = 0; i < myLength(s); i++)
        h = (h * 31 + (big)(unsigned char)s[i]) % n;
    return h;
}

int main() {
    // ---- STEP 1 : Alice builds her key pair --------------------------------
    big p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    big e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Alice's PUBLIC (n,e) = (" << n << "," << e << ")"
         << "   PRIVATE (n,d) = (" << n << "," << d << ")\n\n";

    const char* msg = "Ashik111";

    // ---- STEP 2 : hash the message ------------------------------------------
    big h = simpleHash(msg, n);
    cout << "STEP 2  message = \"" << msg << "\"\n";
    cout << "        hash h  = " << h << "   (one number, always < n)\n\n";

    // ---- STEP 3 : SIGN with the PRIVATE key ----------------------------------
    // note the roles are flipped vs encryption: here the PRIVATE exponent d
    // is used to LOCK, and the PUBLIC exponent e is used to UNLOCK. Since RSA
    // is symmetric in its maths (modPow(modPow(x,e,n),d,n) == modPow(modPow(x,d,n),e,n)
    // == x, both directions rely on the very same Euler-theorem identity from v1),
    // whichever key you apply first, the other one undoes it.
    big sig = modPow(h, d, n);
    cout << "STEP 3  SIGN    s = h^d mod n = " << h << "^" << d
         << " mod " << n << " = " << sig << "\n";
    cout << "        Alice sends: message + signature " << sig << "\n\n";

    // ---- STEP 4 : VERIFY with the PUBLIC key ---------------------------------
    big h_from_sig = modPow(sig, e, n);          // undo the signature
    big h_recomputed = simpleHash(msg, n);       // hash what actually arrived
    cout << "STEP 4  VERIFY  h' = s^e mod n = " << h_from_sig << "\n";
    cout << "        recomputed hash of received message = " << h_recomputed << "\n";
    cout << "        " << (h_from_sig == h_recomputed
                           ? "VALID   -- message really came from Alice, untouched"
                           : "INVALID -- reject") << "\n\n";

    // ---- STEP 5 : attacker tampers with one character -------------------------
    const char* tampered = "Ashik112";          // last '1' changed to '2'
    big h_tampered = simpleHash(tampered, n);
    cout << "STEP 5  ATTACK  message changed to \"" << tampered << "\"\n";
    cout << "        signature is still " << sig << " (attacker cannot make a new one\n";
    cout << "        without Alice's private key d = " << d << ")\n";
    cout << "        h' from signature      = " << h_from_sig << "\n";
    cout << "        hash of tampered text  = " << h_tampered << "\n";
    cout << "        " << (h_from_sig == h_tampered ? "VALID" : "INVALID -- tampering detected")
         << "\n";
    return 0;
}
