Zig Tutorial: Wienernitz One Time Signature
===========================================

The [W-OTS](https://medium.com/asecuritysite-when-bob-met-alice/w-otss-the-problem-sleepwalking-into-a-broken-world-of-trust-7a6e027d1d9f) primitives
including implemented in [Zig](https://ziglang.org) including:

- `DRNG`
- `PrivatKey`
- `PublicKey`
- `Signature`

DRNG Braindump
--------------

I'm using the [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) primitives
(`ChaCha20Poly1305`) to generate a fast and portable deterministic random numbers.

With this primitive, it should be possible to implement a WOTS with constant disk space,
as we only need to persist the last used `nonce`.

The 12-byte nonce, facilitates 2^96 key generations. We need to invoke the DRNG 64-times,
to generate key material for each `Signature` in the default (128-bit security) setting.
This means that 2^90 (2^96 / 2^6) Signatures can be produced from each seed.

Key reuse is the weekness of the this DRNG. The probability of key re-use is equivalent to
the ChaCha20-Poly1305 cipher in TLS.
TODO: link to relevant security analysis.
