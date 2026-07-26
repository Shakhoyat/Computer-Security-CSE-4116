# RSA Lab Toolkit — file index & cheat sheet

Seven self-contained `.cpp` files. Each one compiles and runs alone (no
headers between them, no shared build system) — pick the file matching the
task you're handed, tweak `p`, `q`, and the message, done.

```
g++ -O2 -o run rsa_vX_whatever.cpp && ./run
```

Needs GCC or Clang (`__int128` is a compiler extension, not standard C++ —
MSVC's `cl.exe` does not support it; MinGW g++ does, confirmed working here).

## Which file for which task

| If the task says...                                            | Open           |
|------------------------------------------------------------------|----------------|
| "generate RSA keys", "encrypt/decrypt a message/string"          | `rsa_v1_string.cpp` |
| "why does RSA decryption work", "prove correctness"              | `rsa_v1_string.cpp` (Euler's-theorem proof block) |
| primes big enough that `long long` overflows                     | `rsa_v1_string.cpp` STEP 9 (live overflow demo, both failure modes) |
| "digital signature", "verify authenticity", "detect tampering"   | `rsa_v2_signature.cpp` |
| "hybrid encryption", "why not encrypt the whole message with RSA" | `rsa_v3_hybrid.cpp` |
| "confidentiality AND authentication", "sign then encrypt", two users | `rsa_v4_signcrypt.cpp` |
| "attack textbook RSA", "frequency analysis", "factor n", "small e attack" | `rsa_v5_attacks.cpp` |
| "authentication protocol", "challenge-response", "prove identity without sending a password" | `rsa_v6_auth.cpp` |
| "common modulus attack"                                          | `rsa_v7_attacks2.cpp` (Attack A) |
| "Fermat factorization", "primes too close"                       | `rsa_v7_attacks2.cpp` (Attack B) |
| "Wiener's attack", "small private exponent d is insecure"        | `rsa_v7_attacks2.cpp` (Attack C) |

## The 6 core functions (identical in every file, fully derived in v1)

| Function | Does | Cost | Why not the naive version |
|---|---|---|---|
| `gcd(a,b)` | Euclid's algorithm | O(log min(a,b)) | — |
| `extGCD(a,b,&x,&y)` | solves `a*x+b*y=gcd(a,b)` | O(log) | brute-force search for `d` is O(phi) — dies once phi > ~10^8 |
| `modInverse(e,phi)` | `d = e^-1 mod phi` | O(log phi) | same reason, built on extGCD |
| `modPow(base,exp,m)` | `base^exp mod m` | O(log exp) | repeated multiplication is O(exp) — computing `m^17` the slow way is fine, `m^(10^18)` is not |
| `isPrime(n)` | Miller-Rabin primality test | O(log³n) | trial division is O(sqrt n) — ~10^9 checks for n~10^18 |
| `nextPrime(x)` | smallest prime ≥ x | — | this is literally how real RSA key generation picks p, q |

`typedef __int128 big;` everywhere RSA numbers live (`p,q,n,phi,e,d,m,c`).
`typedef long long ll;` only for small loop/index counters. `cout` is taught
to print `__int128` via one `operator<<` overload (`__int128` has no built-in
stream support). See `rsa_v1_string.cpp` STEP 9 for exactly where and why
plain `long long` breaks and `__int128` doesn't.

## Formula cheat sheet (say this out loud in the viva)

```
choose primes p, q                       (distinct, both prime)
n   = p * q                              modulus
phi = (p-1)(q-1)                         Euler's totient of n
choose e : 1 < e < phi, gcd(e,phi) = 1   public exponent
d = e^-1 mod phi                         private exponent  (via extended Euclid)

encrypt:  c = m^e mod n     (public key  = (n,e))
decrypt:  m = c^d mod n     (private key = (n,d))

why it round-trips (Euler's theorem):
  gcd(m,n)=1  =>  m^phi(n) = 1 (mod n)
  e*d = 1 + k*phi   (that's what modInverse guarantees)
  (m^e)^d = m^(1+k*phi) = m * (m^phi)^k = m * 1 = m
```

**Signing is the same maths, roles swapped**: sign with the *private* key
(`s = h^d mod n`), verify with the *public* key (`h' = s^e mod n`) — only the
owner of `d` could have produced something that `e` undoes correctly.

## Adapting any file to a specific task in the exam

- Different message → change the `const char* msg = "...";` line.
- Different primes → change `p`, `q`; everything downstream recomputes.
- Task wants **input from the user** instead of hardcoded values → replace
  the hardcoded line with `cin >> p >> q;` (works for `big`/`__int128` too,
  since it inherits `long long`-sized input ranges through normal `cin`
  parsing — for values *larger* than `long long` typed at runtime, read as a
  `string` and pass it to `readBig()`, defined near the top of v1).
- Task wants a **plain number** encrypted instead of a string → skip the
  per-character loop, just do `big c = modPow(m, e, n);` directly.
- Numbers overflow `long long` → you're already covered, everything is
  `__int128` already (see v1 STEP 9 for the proof this was necessary, not
  just "extra safe").
