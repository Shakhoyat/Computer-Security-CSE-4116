# ElGamal Lab Toolkit — file index & cheat sheet

Five self-contained `.cpp` files. Each one compiles and runs alone (no shared
headers, no build system) — pick the file matching the task you're handed,
tweak the prime size or the message, done.

```
g++ -O2 -std=c++17 -o run elgamal_vX_whatever.cpp && ./run [seed]
```

Every file takes an optional integer seed so a run is reproducible, and every
file ends with a `N passed, 0 failed` line and a non-zero exit code if anything
broke. Needs GCC or Clang — `__int128` is a compiler extension, MSVC's `cl.exe`
does not have it. MinGW g++ 15.2 confirmed working here.

## Naming: theory sheet -> code

The variable names come straight off the lab theory sheet, not from the
textbook-agnostic `(g, x, y)` notation.

| Theory sheet | Code | What it is |
|---|---|---|
| `p` | `K.p` | large prime |
| `D` | `K.D` | decryption key = **private key** |
| `E1` | `K.E1` | 2nd part of the encryption key, a primitive root of `p` |
| `E2 = E1^D mod p` | `K.E2` | 3rd part of the encryption key |
| public key `(E1, E2, p)` | `Key` | what Bob publishes |
| private key `D` | `K.D` | what Bob keeps |
| `R` | `R` | fresh random integer, one per encryption |
| cipher text `(C1, C2)` | `Cipher` | what goes on the wire |
| signature `(S1, S2)` | `Sig` | file 4 only |
| verification `(V1, V2)` | local vars | file 4 only |

```
Bob      p prime, D private, E1 primitive root, E2 = E1^D mod p
Encrypt  C1 = E1^R mod p            C2 = (PT * E2^R) mod p
Decrypt  PT = [C2 * (C1^D)^-1] mod p        (or C2 * C1^(p-1-D), Fermat)
Sign     S1 = E1^R mod p            S2 = (M - D*S1) * R^-1 mod (p-1)
Verify   V1 = E1^M mod p            V2 = E2^S1 * S1^S2 mod p     accept iff V1 == V2
```

## Which file for which task

| If the task says... | Open |
|---|---|
| "implement ElGamal", "encrypt/decrypt a message" | `elgamal_v1_basic.cpp` |
| "show the p=11 book example" | `elgamal_v1_basic.cpp` block `[0]` |
| "decrypt without extended Euclid" | `elgamal_v1_basic.cpp` block `[4]` |
| "why is the same plaintext encrypted differently every time" | `elgamal_v1_basic.cpp` block `[5]` |
| "homomorphic property", "product cipher", "multiply two ciphertexts" | `elgamal_v2_product_cipher.cpp` |
| "malleability", "change the amount without the key" | `elgamal_v2_product_cipher.cpp` block `[5]` |
| "re-randomisation", "refresh a ciphertext", "mix-net", "e-voting" | `elgamal_v3_rerandomization.cpp` |
| "digital signature", "verify authenticity", "detect tampering" | `elgamal_v4_signature.cpp` |
| "what if the random R is reused" | `elgamal_v4_signature.cpp` block `[5]` |
| "forge a signature without the private key" | `elgamal_v4_signature.cpp` block `[6]` |
| "chosen-ciphertext attack", "decryption oracle" | `elgamal_v5_variations.cpp` block `[A]` |
| "what does the ciphertext leak about the plaintext" | `elgamal_v5_variations.cpp` block `[C]` |
| "solve the discrete log", "break a small key" | `elgamal_v5_variations.cpp` block `[D]` |
| "why must E1 be a primitive root" | `elgamal_v5_variations.cpp` block `[E]` |
| "encrypt a long string" | `elgamal_v5_variations.cpp` block `[G]` |

## Why 128-bit, and what it cost

Default prime is a **100-bit safe prime** `p = 2q+1` (30 decimal digits). Three
consequences the 64-bit version did not have to deal with:

| Problem | Fix in these files |
|---|---|
| `cout` cannot print `__int128` | `toStr()` + an `operator<<` overload |
| `a * b` overflows `u128` when `p > 64` bits (`p*p` needs 200 bits) | `mulmod()` by repeated doubling — additions only, never a product wider than `p` |
| `long long` goes negative in `(M - D*S1)` | `submod()`, and `i128` used **only** inside `egcd` where coefficients are genuinely signed |
| a random 100-bit prime is not findable by trial division | Miller-Rabin (`isPrime`), 12 fixed bases + 8 random ones |
| `p-1` with small factors makes the discrete log easy | `safePrime()` returns `p = 2q+1` with `q` prime, so the only subgroup orders are 1, 2, q, 2q |

`mulmod` is what makes the whole thing work — everything else is ordinary
modular arithmetic on a wider type.

## Variations worth rehearsing

Grouped by how the question usually gets phrased. The ones marked **[code]**
already run in one of these files.

**Change one line of the algorithm**

1. Decrypt with `C2 * C1^(p-1-D)` instead of inverting `C1^D`. Same answer, no
   extended Euclid — Fermat gives the inverse for free. **[code: v1 `[4]`]**
2. Encrypt with `R = 0`. Then `C1 = 1` and `C2 = PT`: the plaintext ships in the
   clear. **[code: v1 `[6]`]**
3. Encrypt `PT = 0`. `C2 = 0` no matter what `R` is, so the ciphertext announces
   its own plaintext. **[code: v5 `[F]`]**
4. Encrypt `PT >= p`. It silently comes back as `PT mod p`. **[code: v1 `[6]`]**
5. Use `E1 = p-1` (order 2 instead of order `p-1`). `C1` only ever takes two
   values, so two guesses decrypt anything. **[code: v5 `[E]`]**

**Give the attacker one extra thing**

6. Same `R` for two encryptions. `C1` repeats, and `C2b/C2a = PT2/PT1`, so one
   known plaintext hands over the other. **[code: v5 `[B]`]**
7. Same `R` for two *signatures*. `R = (Ma-Mb)/(S2a-S2b) mod (p-1)`, then
   `D = (Ma - R*S2a)/S1 mod (p-1)`. Full private-key recovery — the PS3 bug.
   **[code: v4 `[5]`]**
8. Leak `R` for a single signature. One line and `D` is gone. **[code: v4 `[7]`]**
9. Give Eve a decryption oracle that refuses only the target cipher. She sends
   `(C1, k*C2)`, gets `k*PT` back, divides by `k`. **[code: v5 `[A]`]**
10. Give Eve `p` small enough. Baby-step giant-step recovers `D` from `E2` in
    `sqrt(p)` steps. **[code: v5 `[D]`]**

**Attack with nothing but the public key**

11. Malleability: multiply `C2` by `k` and the payment 100 becomes 100k. Nobody
    notices, because there is nothing to notice with. **[code: v2 `[5]`]**
12. Product cipher: multiply two ciphers componentwise, get a valid cipher of
    `PT1*PT2`. Same maths as 11, framed as a feature. **[code: v2 `[3]`]**
13. Re-randomise: `(C1*E1^R', C2*E2^R')` is a fresh-looking cipher for the same
    plaintext. Public key only. **[code: v3 `[3]`]**
14. Legendre leak: `legendre(PT) = legendre(C2) * legendre(C1)^(D mod 2)`, and
    `D mod 2` is readable off the public `E2`. One bit of every plaintext, for
    free. Fix: square the message into the order-`q` subgroup first, and take
    the root back with `y^((p+1)/4)` since `p = 3 mod 4`. **[code: v5 `[C]`]**
15. Existential forgery on unhashed signatures: pick `a`, `b`, set
    `S1 = E1^a * E2^b`, `S2 = -S1*b^-1 mod (p-1)`, `M = a*S2 mod (p-1)`.
    Verifies against Alice's public key. Eve does not get to pick `M` — which is
    exactly why hashing kills it. **[code: v4 `[6]`]**

**Trick questions with no code**

16. "Signature on `M` also verifies `M + (p-1)`" — because `E1^M` only ever sees
    the exponent mod `p-1`. **[code: v4 `[3]`]**
17. "Why must `gcd(R, p-1) = 1` when signing but not when encrypting?" —
    signing inverts `R` mod `p-1`; encryption only exponentiates by it.
18. "Ciphertext is twice the plaintext length" — `(C1, C2)` are both mod `p`.
    That is ElGamal's standing cost versus RSA.
19. "Is ElGamal CPA-secure? CCA-secure?" — CPA yes (under DDH, *in the QR
    subgroup*), CCA no, and 9/11 above are the proof.
20. "Which part is Diffie-Hellman?" — `(E1^R, E2^R)` is exactly a DH exchange;
    `C2` is the plaintext masked by the shared secret. Encrypting `PT = 1`
    makes the DH pair visible on its own. **[code: v5 `[F]`]**
