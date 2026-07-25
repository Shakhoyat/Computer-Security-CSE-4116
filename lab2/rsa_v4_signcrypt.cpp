// ===========================================================================
//  RSA -- VERSION 4 : Encrypt + Sign  (Alice -> Bob, two key pairs)
//
//  Encryption alone proves nothing about WHO sent the message.
//  Signing alone hides nothing from an eavesdropper.
//  Real communication needs BOTH, so each party owns a key pair:
//        Alice encrypts with BOB's PUBLIC key    -> only Bob can read it
//        Alice signs    with HER OWN PRIVATE key -> only Alice could sign it
//  Build : g++ -o v4 rsa_v4_signcrypt.cpp
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
ll simpleHash(const char* s, ll n) {
    ll h = 7;
    for (int i = 0; i < myLength(s); i++)
        h = (h * 31 + (ll)(unsigned char)s[i]) % n;
    return h;
}
// ------------------------------------------------------------ END OF CORE

int main() {
    // ---- STEP 1 : two independent key pairs -------------------------------
    ll pA = 61, qA = 53, nA = pA * qA, phiA = (pA - 1) * (qA - 1);
    ll eA = 17, dA = modInverse(eA, phiA);           // ALICE

    ll pB = 47, qB = 59, nB = pB * qB, phiB = (pB - 1) * (qB - 1);
    ll eB = 17, dB = modInverse(eB, phiB);           // BOB

    cout << "STEP 1  ALICE  public(n,e)=(" << nA << "," << eA << ")  private d=" << dA << "\n";
    cout << "        BOB    public(n,e)=(" << nB << "," << eB << ")  private d=" << dB << "\n";
    cout << "        gcd(eB,phiB) = " << gcd(eB, phiB) << ", nB = " << nB
         << " > 255 : OK\n\n";

    const char* msg = "Ashik111";
    int len = myLength(msg);

    // ---- STEP 2 : Alice SIGNS the hash with HER PRIVATE key ---------------
    ll h = simpleHash(msg, nA);
    ll sig = modPow(h, dA, nA);
    cout << "STEP 2  hash(msg) = " << h << "   signature = h^dA mod nA = " << sig << "\n\n";

    // ---- STEP 3 : Alice ENCRYPTS with BOB'S PUBLIC key --------------------
    ll cipher[100];
    cout << "STEP 3  encrypt each char with Bob's public key:  c = m^eB mod nB\n";
    cout << "  i  char  m     c\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        ll m = (ll)(unsigned char)msg[i];
        cipher[i] = modPow(m, eB, nB);
        cout << "  " << i << "   '" << msg[i] << "'   " << m << "   " << cipher[i] << "\n";
    }
    cout << "\n  Alice sends over the network:  ciphertext + signature " << sig << "\n\n";

    // ---- STEP 4 : Bob DECRYPTS with HIS PRIVATE key -----------------------
    char plain[101];
    for (int i = 0; i < len; i++) plain[i] = (char)modPow(cipher[i], dB, nB);
    plain[len] = '\0';
    cout << "STEP 4  Bob decrypts with dB  ->  \"" << plain << "\"\n\n";

    // ---- STEP 5 : Bob VERIFIES with ALICE'S PUBLIC key --------------------
    ll h_fromSig = modPow(sig, eA, nA);
    ll h_check   = simpleHash(plain, nA);
    cout << "STEP 5  h from signature   = " << h_fromSig << "\n";
    cout << "        hash of what Bob read = " << h_check << "\n";
    cout << "        " << (h_fromSig == h_check
            ? "AUTHENTIC -- confidentiality + integrity + non-repudiation"
            : "REJECTED") << "\n\n";

    // ---- STEP 6 : an impostor tries to forge Alice's signature -------------
    ll fakeSig = modPow(h, dB, nB);              // Eve only has Bob's key
    ll h_fake  = modPow(fakeSig, eA, nA);        // verified with Alice's key
    cout << "STEP 6  FORGERY  Eve signs with dB and claims to be Alice\n";
    cout << "        verified value = " << h_fake << "  vs real hash " << h << "\n";
    cout << "        " << (h_fake == h ? "accepted" : "REJECTED -- forgery detected") << "\n";
    return 0;
}
