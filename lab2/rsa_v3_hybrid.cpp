// ===========================================================================
//  RSA -- VERSION 3 : Hybrid Encryption  (the way real systems use RSA)
//
//  RSA is SLOW and can only encrypt numbers smaller than n. So real systems
//  never encrypt the whole message with RSA. Instead:
//        1. pick a small random SESSION KEY  (fast symmetric key)
//        2. encrypt ONLY that key with RSA          <- 1 slow operation
//        3. encrypt the whole message with XOR       <- N fast operations
//  Core toolkit derivations are explained in full in rsa_v1_string.cpp.
//  Build : g++ -O2 -o v3 rsa_v3_hybrid.cpp
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

// Our own random generator (a Linear Congruential Generator).
// Same seed -> same sequence. That is exactly what we need: the receiver
// regenerates the identical keystream once he knows the seed.
ll rngState;
void seedRNG(ll s) { rngState = s; }
ll nextRandom() {
    rngState = (rngState * 1103515245 + 12345) % 2147483648LL;
    return rngState;
}

int main() {
    // ---- STEP 1 : Bob's RSA key pair ---------------------------------------
    big p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    big e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Bob PUBLIC (n,e)=(" << n << "," << e << ")  PRIVATE d=" << d << "\n\n";

    const char* msg = "Ashik111";
    int len = myLength(msg);

    // ---- STEP 2 : Alice picks ONE small random session key ------------------
    ll sessionKey = 1234 % (ll)n;      // in practice: from a secure RNG
    cout << "STEP 2  Alice's random session key K = " << sessionKey
         << "   (must be < n = " << n << ")\n\n";

    // ---- STEP 3 : RSA-encrypt ONLY the session key ---------------------------
    big encKey = modPow(sessionKey, e, n);
    cout << "STEP 3  RSA-encrypt the key:  K^e mod n = " << encKey
         << "     <-- ONE RSA operation only, however long the message is\n\n";

    // ---- STEP 4 : expand K into a keystream and XOR the message -------------
    seedRNG(sessionKey);
    int cipher[100];
    cout << "STEP 4  XOR-encrypt the message with the keystream from K\n";
    cout << "  i  char  m    ks   c = m XOR ks\n  --------------------------------\n";
    for (int i = 0; i < len; i++) {
        int m = (unsigned char)msg[i];
        int ks = (int)(nextRandom() % 256);      // one keystream byte
        cipher[i] = m ^ ks;
        cout << "  " << i << "   '" << msg[i] << "'   " << m
             << "   " << ks << "   " << cipher[i] << "\n";
    }
    cout << "\n  Alice transmits: encKey = " << encKey << "  +  ciphertext bytes\n\n";

    // ---- STEP 5 : Bob recovers the session key with his PRIVATE key ---------
    big recoveredKey = modPow(encKey, d, n);
    cout << "STEP 5  Bob decrypts the key: encKey^d mod n = " << recoveredKey
         << "   (matches K? " << (recoveredKey == (big)sessionKey ? "YES" : "NO") << ")\n\n";

    // ---- STEP 6 : same seed -> same keystream -> message recovered ----------
    seedRNG((ll)recoveredKey);
    char plain[101];
    cout << "STEP 6  Bob regenerates the SAME keystream and XORs it back\n";
    cout << "  i   c   ks    m   char\n  --------------------------------\n";
    for (int i = 0; i < len; i++) {
        int ks = (int)(nextRandom() % 256);
        int m = cipher[i] ^ ks;
        plain[i] = (char)m;
        cout << "  " << i << "  " << cipher[i] << "   " << ks
             << "   " << m << "   '" << plain[i] << "'\n";
    }
    plain[len] = '\0';

    // ---- STEP 7 : verify + cost comparison ------------------------------------
    bool same = true;
    for (int i = 0; i < len; i++) if (msg[i] != plain[i]) same = false;
    cout << "\nSTEP 7  recovered = \"" << plain << "\"  ->  "
         << (same ? "MATCH" : "MISMATCH") << "\n";
    cout << "        RSA operations used : 1 encrypt + 1 decrypt\n";
    cout << "        Pure-RSA would need : " << len << " encrypts + " << len << " decrypts\n";
    return 0;
}
