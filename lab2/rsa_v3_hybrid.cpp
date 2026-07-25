// ===========================================================================
//  RSA -- VERSION 3 : Hybrid Encryption  (the way real systems use RSA)
//
//  RSA is SLOW and can only encrypt numbers smaller than n. So real systems
//  never encrypt the whole message with RSA. Instead:
//        1. pick a small random SESSION KEY  (fast symmetric key)
//        2. encrypt ONLY that key with RSA          <- 1 slow operation
//        3. encrypt the whole message with XOR      <- N fast operations
//  Build : g++ -o v3 rsa_v3_hybrid.cpp
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;

// --------------------------------------------------------------- THE CORE
int myLength(const char* s) { int n = 0; while (s[n] != '\0') n++; return n; }
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
    // ---- STEP 1 : Bob's RSA key pair --------------------------------------
    ll p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    ll e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Bob PUBLIC (n,e)=(" << n << "," << e << ")  PRIVATE d=" << d << "\n\n";

    const char* msg = "Ashik111";
    int len = myLength(msg);

    // ---- STEP 2 : Alice picks ONE small random session key ----------------
    ll sessionKey = 1234 % n;          // in practice: from a secure RNG
    cout << "STEP 2  Alice's random session key K = " << sessionKey
         << "   (must be < n = " << n << ")\n\n";

    // ---- STEP 3 : RSA-encrypt ONLY the session key ------------------------
    ll encKey = modPow(sessionKey, e, n);
    cout << "STEP 3  RSA-encrypt the key:  K^e mod n = " << encKey
         << "     <-- ONE RSA operation only\n\n";

    // ---- STEP 4 : expand K into a keystream and XOR the message -----------
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

    // ---- STEP 5 : Bob recovers the session key with his PRIVATE key -------
    ll recoveredKey = modPow(encKey, d, n);
    cout << "STEP 5  Bob decrypts the key: encKey^d mod n = " << recoveredKey
         << "   (matches K? " << (recoveredKey == sessionKey ? "YES" : "NO") << ")\n\n";

    // ---- STEP 6 : same seed -> same keystream -> message recovered ---------
    seedRNG(recoveredKey);
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

    // ---- STEP 7 : verify + cost comparison --------------------------------
    int same = 1;
    for (int i = 0; i < len; i++) if (msg[i] != plain[i]) same = 0;
    cout << "\nSTEP 7  recovered = \"" << plain << "\"  ->  "
         << (same ? "MATCH" : "MISMATCH") << "\n";
    cout << "        RSA operations used : 1 encrypt + 1 decrypt\n";
    cout << "        Pure-RSA would need : " << len << " encrypts + " << len << " decrypts\n";
    return 0;
}
