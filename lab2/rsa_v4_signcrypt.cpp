// ===========================================================================
//  RSA -- VERSION 4 : Encrypt + Sign  (Alice -> Bob, two key pairs)
//
//  Encryption alone proves nothing about WHO sent the message.
//  Signing alone hides nothing from an eavesdropper.
//  Real communication needs BOTH, so each party owns a key pair:
//        Alice encrypts with BOB's PUBLIC key    -> only Bob can read it
//        Alice signs    with HER OWN PRIVATE key -> only Alice could sign it
//  Core toolkit derivations are explained in full in rsa_v1_string.cpp.
//  Build : g++ -O2 -o v4 rsa_v4_signcrypt.cpp
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
big simpleHash(const char* s, big n) {
    big h = 7;
    for (int i = 0; i < myLength(s); i++)
        h = (h * 31 + (big)(unsigned char)s[i]) % n;
    return h;
}

int main() {
    // ---- STEP 1 : two independent key pairs --------------------------------
    big pA = 61, qA = 53, nA = pA * qA, phiA = (pA - 1) * (qA - 1);
    big eA = 17, dA = modInverse(eA, phiA);           // ALICE

    big pB = 47, qB = 59, nB = pB * qB, phiB = (pB - 1) * (qB - 1);
    big eB = 17, dB = modInverse(eB, phiB);           // BOB

    cout << "STEP 1  ALICE  public(n,e)=(" << nA << "," << eA << ")  private d=" << dA << "\n";
    cout << "        BOB    public(n,e)=(" << nB << "," << eB << ")  private d=" << dB << "\n";
    cout << "        gcd(eB,phiB) = " << gcd(eB, phiB) << ", nB = " << nB
         << " > 255 : OK\n\n";

    const char* msg = "Ashik111";
    int len = myLength(msg);

    // ---- STEP 2 : Alice SIGNS the hash with HER PRIVATE key -----------------
    big h = simpleHash(msg, nA);
    big sig = modPow(h, dA, nA);
    cout << "STEP 2  hash(msg) = " << h << "   signature = h^dA mod nA = " << sig << "\n\n";

    // ---- STEP 3 : Alice ENCRYPTS with BOB'S PUBLIC key -----------------------
    big cipher[100];
    cout << "STEP 3  encrypt each char with Bob's public key:  c = m^eB mod nB\n";
    cout << "  i  char  m     c\n  ------------------------\n";
    for (int i = 0; i < len; i++) {
        big m = (big)(unsigned char)msg[i];
        cipher[i] = modPow(m, eB, nB);
        cout << "  " << i << "   '" << msg[i] << "'   " << m << "   " << cipher[i] << "\n";
    }
    cout << "\n  Alice sends over the network:  ciphertext + signature " << sig << "\n\n";

    // ---- STEP 4 : Bob DECRYPTS with HIS PRIVATE key ----------------------------
    char plain[101];
    for (int i = 0; i < len; i++) plain[i] = (char)(ll)modPow(cipher[i], dB, nB);
    plain[len] = '\0';
    cout << "STEP 4  Bob decrypts with dB  ->  \"" << plain << "\"\n\n";

    // ---- STEP 5 : Bob VERIFIES with ALICE'S PUBLIC key --------------------------
    big h_fromSig = modPow(sig, eA, nA);
    big h_check   = simpleHash(plain, nA);
    cout << "STEP 5  h from signature   = " << h_fromSig << "\n";
    cout << "        hash of what Bob read = " << h_check << "\n";
    cout << "        " << (h_fromSig == h_check
            ? "AUTHENTIC -- confidentiality + integrity + non-repudiation"
            : "REJECTED") << "\n\n";

    // ---- STEP 6 : an impostor tries to forge Alice's signature ------------------
    // Eve does NOT know dA (Alice's private key). All she has is her OWN
    // key pair. Signing with the wrong private key produces a number that
    // only verifies correctly under the matching public key -- so checking
    // with Alice's PUBLIC key eA immediately exposes the forgery.
    big fakeSig = modPow(h, dB, nB);              // Eve only has Bob's key
    big h_fake  = modPow(fakeSig, eA, nA);        // verified with Alice's public key
    cout << "STEP 6  FORGERY  Eve signs with dB and claims to be Alice\n";
    cout << "        verified value = " << h_fake << "  vs real hash " << h << "\n";
    cout << "        " << (h_fake == h ? "accepted" : "REJECTED -- forgery detected") << "\n";
    return 0;
}
