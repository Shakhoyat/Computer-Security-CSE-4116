// ===========================================================================
//  RSA -- VERSION 6 : Challenge-Response Authentication
//
//  Problem: a server must be sure it is talking to Alice, WITHOUT Alice ever
//  sending her private key or password across the network.
//  Solution: the server sends a fresh random number (the "challenge").
//  Only the real Alice can sign it, because only she owns d.
//  Core toolkit derivations are explained in full in rsa_v1_string.cpp.
//  Build : g++ -O2 -o v6 rsa_v6_auth.cpp
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

// our own random generator, so no built-in rand() is used
ll rngState = 2026;
ll nextRandom() {
    rngState = (rngState * 1103515245 + 12345) % 2147483648LL;
    return rngState;
}

int main() {
    // ---- STEP 1 : Alice's key pair; the server stores only the PUBLIC part -
    big p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    big e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Server stores Alice's PUBLIC key only: (n,e) = ("
         << n << "," << e << ")\n";
    cout << "        Alice keeps her PRIVATE d = " << d << " secret, forever\n\n";

    // ---- STEP 2 : the server invents a fresh random challenge ---------------
    big challenge = nextRandom() % n;
    cout << "STEP 2  Server -> Alice :  challenge = " << challenge
         << "   (new random number every login)\n\n";

    // ---- STEP 3 : Alice signs the challenge with her PRIVATE key ------------
    big response = modPow(challenge, d, n);
    cout << "STEP 3  Alice -> Server :  response = challenge^d mod n = "
         << response << "\n";
    cout << "        note: d itself is NEVER transmitted\n\n";

    // ---- STEP 4 : the server checks with the PUBLIC key ----------------------
    big check = modPow(response, e, n);
    cout << "STEP 4  Server computes response^e mod n = " << check << "\n";
    cout << "        expected challenge          = " << challenge << "\n";
    cout << "        " << (check == challenge ? "LOGIN GRANTED -- it really is Alice"
                                              : "LOGIN DENIED") << "\n\n";

    // ---- STEP 5 : an impostor without d cannot answer --------------------------
    big fake = (challenge + 1) % n;                  // Eve just guesses
    big checkFake = modPow(fake, e, n);
    cout << "STEP 5  IMPOSTOR  Eve guesses response = " << fake << "\n";
    cout << "        server computes " << checkFake << " != " << challenge
         << "  ->  LOGIN DENIED\n\n";

    // ---- STEP 6 : replay protection ---------------------------------------------
    big challenge2 = nextRandom() % n;
    cout << "STEP 6  REPLAY  next login uses a NEW challenge = " << challenge2 << "\n";
    cout << "        Eve replays the old response " << response
         << " -> server gets " << modPow(response, e, n)
         << " != " << challenge2 << "  ->  DENIED\n";
    cout << "        This is why the challenge must be fresh every time.\n";
    return 0;
}
