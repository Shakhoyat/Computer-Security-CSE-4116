// ===========================================================================
//  RSA -- VERSION 2 : Digital Signature  (authenticity + integrity)
//
//  Encryption uses the PUBLIC key to lock and the PRIVATE key to unlock.
//  A signature is the SAME maths run BACKWARDS :
//        sign   with the PRIVATE key  ->  only the owner can produce it
//        verify with the PUBLIC  key  ->  anybody can check it
//  Build : g++ -o v2 rsa_v2_signature.cpp
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;

// --------------------------------------------------------------- THE CORE
int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }
ll gcd(ll a, ll b) { while (b != 0) { ll t = a % b; a = b; b = t; } return a; }
ll modPow(ll base, ll exp, ll m) {
    ll r = 1; base = base % m;
    while (exp > 0) { if (exp % 2 == 1) r = (r * base) % m;
                      base = (base * base) % m; exp = exp / 2; }
    return r;
}
ll modInverse(ll e, ll phi) {
    for (ll d = 2; d < phi; d++) if ((e * d) % phi == 1) return d;
    return -1;
}
// ------------------------------------------------------------ END OF CORE

// A tiny hash: fold the whole message into ONE number smaller than n.
// h starts at 7, and every character does  h = h*31 + c  (mod n).
// Changing any single character changes h completely -> tampering is visible.
ll simpleHash(const char* s, ll n) {
    ll h = 7;
    for (int i = 0; i < myLength(s); i++)
        h = (h * 31 + (ll)(unsigned char)s[i]) % n;
    return h;
}

int main() {
    // ---- STEP 1 : Alice builds her key pair ------------------------------
    ll p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    ll e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Alice's PUBLIC (n,e) = (" << n << "," << e << ")"
         << "   PRIVATE (n,d) = (" << n << "," << d << ")\n\n";

    const char* msg = "Ashik111";

    // ---- STEP 2 : hash the message ---------------------------------------
    ll h = simpleHash(msg, n);
    cout << "STEP 2  message = \"" << msg << "\"\n";
    cout << "        hash h  = " << h << "   (one number, always < n)\n\n";

    // ---- STEP 3 : SIGN with the PRIVATE key -------------------------------
    ll sig = modPow(h, d, n);
    cout << "STEP 3  SIGN    s = h^d mod n = " << h << "^" << d
         << " mod " << n << " = " << sig << "\n";
    cout << "        Alice sends: message + signature " << sig << "\n\n";

    // ---- STEP 4 : VERIFY with the PUBLIC key -------------------------------
    ll h_from_sig = modPow(sig, e, n);          // undo the signature
    ll h_recomputed = simpleHash(msg, n);       // hash what actually arrived
    cout << "STEP 4  VERIFY  h' = s^e mod n = " << h_from_sig << "\n";
    cout << "        recomputed hash of received message = " << h_recomputed << "\n";
    cout << "        " << (h_from_sig == h_recomputed
                           ? "VALID   -- message really came from Alice, untouched"
                           : "INVALID -- reject") << "\n\n";

    // ---- STEP 5 : attacker tampers with one character ----------------------
    const char* tampered = "Ashik112";          // last '1' changed to '2'
    ll h_tampered = simpleHash(tampered, n);
    cout << "STEP 5  ATTACK  message changed to \"" << tampered << "\"\n";
    cout << "        signature is still " << sig << " (attacker cannot make a new one)\n";
    cout << "        h' from signature      = " << h_from_sig << "\n";
    cout << "        hash of tampered text  = " << h_tampered << "\n";
    cout << "        " << (h_from_sig == h_tampered ? "VALID" : "INVALID -- tampering detected")
         << "\n";
    return 0;
}
