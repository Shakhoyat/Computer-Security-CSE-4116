// ===========================================================================
//  RSA -- VERSION 6 : Challenge-Response Authentication
//
//  Problem: a server must be sure it is talking to Alice, WITHOUT Alice ever
//  sending her private key or password across the network.
//  Solution: the server sends a fresh random number (the "challenge").
//  Only the real Alice can sign it, because only she owns d.
//  Build : g++ -o v6 rsa_v6_auth.cpp
// ===========================================================================
#include <iostream>
using namespace std;
typedef long long ll;

// --------------------------------------------------------------- THE CORE
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

// our own random generator, so no built-in rand() is used
ll rngState = 2026;
ll nextRandom() {
    rngState = (rngState * 1103515245 + 12345) % 2147483648LL;
    return rngState;
}

int main() {
    // ---- STEP 1 : Alice's key pair; the server stores only the PUBLIC part
    ll p = 61, q = 53, n = p * q, phi = (p - 1) * (q - 1);
    ll e = 17, d = modInverse(e, phi);
    cout << "STEP 1  Server stores Alice's PUBLIC key only: (n,e) = ("
         << n << "," << e << ")\n";
    cout << "        Alice keeps her PRIVATE d = " << d << " secret, forever\n\n";

    // ---- STEP 2 : the server invents a fresh random challenge -------------
    ll challenge = nextRandom() % n;
    cout << "STEP 2  Server -> Alice :  challenge = " << challenge
         << "   (new random number every login)\n\n";

    // ---- STEP 3 : Alice signs the challenge with her PRIVATE key ----------
    ll response = modPow(challenge, d, n);
    cout << "STEP 3  Alice -> Server :  response = challenge^d mod n = "
         << response << "\n";
    cout << "        note: d itself is NEVER transmitted\n\n";

    // ---- STEP 4 : the server checks with the PUBLIC key -------------------
    ll check = modPow(response, e, n);
    cout << "STEP 4  Server computes response^e mod n = " << check << "\n";
    cout << "        expected challenge          = " << challenge << "\n";
    cout << "        " << (check == challenge ? "LOGIN GRANTED -- it really is Alice"
                                              : "LOGIN DENIED") << "\n\n";

    // ---- STEP 5 : an impostor without d cannot answer ---------------------
    ll fake = (challenge + 1) % n;                  // Eve just guesses
    ll checkFake = modPow(fake, e, n);
    cout << "STEP 5  IMPOSTOR  Eve guesses response = " << fake << "\n";
    cout << "        server computes " << checkFake << " != " << challenge
         << "  ->  LOGIN DENIED\n\n";

    // ---- STEP 6 : replay protection ---------------------------------------
    ll challenge2 = nextRandom() % n;
    cout << "STEP 6  REPLAY  next login uses a NEW challenge = " << challenge2 << "\n";
    cout << "        Eve replays the old response " << response
         << " -> server gets " << modPow(response, e, n)
         << " != " << challenge2 << "  ->  DENIED\n";
    cout << "        This is why the challenge must be fresh every time.\n";
    return 0;
}
