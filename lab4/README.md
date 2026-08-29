# ElGamal Lab — file index & cheat sheet

Five short self-contained `.cpp` files. No structs, no classes — just
`mod_pow`, `egcd`, `mod_inv`, four key-generation helpers, and a `main()` that
prints every step with the formula beside it.

```
g++ -O2 -o eg1 elgamal_v1_basic.cpp && ./eg1
./eg1 2103021          # optional seed -> your own key pair
```

Needs GCC or Clang — `__int128` is a compiler extension, MSVC's `cl.exe` does
not have it. MinGW g++ confirmed working. Each run takes about 25 ms.

## The formulas

```
Bob      p prime,  D = private key,  E1 = primitive root,  E2 = E1^D mod p
         public key = (E1, E2, p)          private key = D

Encrypt  C1 = E1^R mod p                   C2 = (PT * E2^R) mod p
Decrypt  PT = [C2 * (C1^D)^-1] mod p       (or PT = C2 * C1^(p-1-D) mod p)

Sign     S1 = E1^R mod p                   S2 = (M - D*S1) * R^-1 mod (p-1)
Verify   V1 = E1^M mod p                   V2 = (E2^S1 * S1^S2) mod p
         valid  <=>  V1 == V2
```

Names are exactly the ones on the theory sheet: `p, D, E1, E2, R, PT, C1, C2,
S1, S2, V1, V2`.

## Key generation (in every file, printed step by step)

Nothing is hardcoded — the key is really generated, following Bob's five steps:

| Step | What happens | Function |
|---|---|---|
| 1 | pick a random 18-digit odd start, walk up to the first **safe prime** `p = 2q+1` (both `p` and `q` tested prime) | `next_safe_prime`, `is_prime` |
| 2 | draw `D` at random from `[2, p-2]` | `rand_range` |
| 3 | find the smallest **primitive root** `E1` | `find_primitive_root` |
| 4 | compute `E2 = E1^D mod p` | `mod_pow` |
| 5 | publish `(E1, E2, p)`, keep `D` | — |

`R` is drawn fresh for every message the same way. In the signature file `R`
also has to satisfy `gcd(R, p-1) = 1`, so `pick_R` keeps trying odd values
until it does.

Two shortcuts worth knowing, both printed by the programs:

- **Why a safe prime?** With `p = 2q+1` an element can only have order 1, 2,
  `q` or `2q`. So `g` is a primitive root the moment `g^2 != 1` and `g^q != 1`
  — a two-line test instead of factoring `p-1`.
- **Miller-Rabin** with the 12 bases `2..37` is *exact* for every `n` below
  `3 * 10^24`, and our `p` is about `10^18`, so the "probable prime" answer is
  actually a proof here.

The seed is the only thing that fixes the key. Same seed → same key every run
(good for a lab report); `./eg1 <your roll number>` → your own key pair.

## Where the inputs are

One block at the top of `main()` in every file:

```cpp
// ---------------- INPUT ----------------
unsigned long long SEED = 2026;    // different seed -> different key pair
i128 PT = 987654321;               // plain text, must be < p
```

## Why `__int128`

The generated `p` is about `10^18`. Inside `mod_pow` the line `a = a * a % m`
needs `10^36`, and `long long` stops at `9.2 * 10^18` — it would silently wrap
and decryption would return the wrong number.

| Problem | Fix |
|---|---|
| `a * a` overflows `long long` | everything is `typedef __int128 i128` |
| `cout` cannot print `__int128` | one `operator<<` that peels off digits |
| `M - D*S1` goes negative | `((x % n) + n) % n` before using it |

Same arithmetic, wider type. Nothing else changes.

## Which file for which task

| If the task says... | Open |
|---|---|
| "implement ElGamal", "encrypt / decrypt" | `elgamal_v1_basic.cpp` |
| "generate the keys", "find a primitive root" | any file — the block is identical |
| "show the p = 11 book example" | `elgamal_v1_basic.cpp`, last block |
| "decrypt without extended Euclid" | `elgamal_v1_basic.cpp`, "WHY IT WORKS" |
| "product cipher", "homomorphic", "multiply two ciphers" | `elgamal_v2_product_cipher.cpp` |
| "change the amount without the key", "malleability" | `elgamal_v2_product_cipher.cpp`, last block |
| "re-randomization", "mix-net", "e-voting" | `elgamal_v3_rerandomization.cpp` |
| "digital signature", "verify", "detect tampering" | `elgamal_v4_signature.cpp` |
| any attack question | `elgamal_v5_variations.cpp` |

`elgamal_v1_basic.cpp` ends by running the same functions on the theory-sheet
numbers (`p = 11, D = 3, E1 = 2, PT = 7, R = 4`) and printing `E2 = 8`, cipher
`(5, 6)`, `(C1^D)^-1 = 3`, `PT = 7` — matching the handwritten pages line for
line. (`11 = 2*5 + 1` is a safe prime and `2` is a primitive root of it, so the
generator above would have accepted this key too.)

## Variations that get asked

Blocks **[A]**–**[F]** are all inside `elgamal_v5_variations.cpp` and print
their own working.

| # | Question | Answer |
|---|---|---|
| A | "What if the same `R` is used for two messages?" | `C1` repeats, and `C2b/C2a = PT2/PT1`. One known plain text gives the other. |
| B | "What if the same `R` signs two messages?" | `R = (M1-M2)(S2a-S2b)^-1`, then `D = (M1-R*S2a)*S1^-1`, both mod `p-1`. Private key gone. |
| C | "What if Bob decrypts anything except the target?" | Send `(C1, k*C2)`, get `k*PT` back, divide by `k`. |
| D | "What if `p` is small?" | Generate a small key the same way, then loop `d = 1..p-1` until `E1^d == E2`. Instant at `p = 467`. |
| E | "Does the cipher leak anything?" | Yes — `legendre(C2) = legendre(PT) * legendre(C1)^(D mod 2)`, and `D mod 2` is readable from the public `E2`. One bit of every plain text. |
| F | "`R = 0`? `PT = 0`? `PT >= p`?" | `R=0` sends `PT` in the clear, `PT=0` forces `C2=0`, `PT>=p` comes back as `PT mod p`. |

Ones with no code, worth remembering:

- A signature on `M` also verifies `M + (p-1)`, because `E1^M` only sees the
  exponent mod `p-1`.
- `gcd(R, p-1) = 1` is needed for **signing** (we invert `R` mod `p-1`) but not
  for encryption (we only raise to the power `R`).
- The cipher text is twice the length of the plain text — `(C1, C2)` are both
  mod `p`. That is ElGamal's standing cost against RSA.
- `(E1^R, E2^R)` is exactly a Diffie-Hellman exchange; `C2` is just the plain
  text masked by the shared secret.
