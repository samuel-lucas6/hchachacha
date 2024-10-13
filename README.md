# HChaChaCha
HChaChaCha is a 128-bit block cipher built from [HChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2) for use in the [PACT/comPACT](https://eprint.iacr.org/2024/1382) transforms for AEAD commitment. The motivation being that ChaCha20-Poly1305 users likely do not want to use AES for commitment.

> [!CAUTION]
> This is an experimental construction that has not been peer reviewed. I have also not done a proper literature review. Therefore, this **MUST NOT** be used in production.

## Design Rationale
- A balanced [Feistel network](https://en.wikipedia.org/wiki/Feistel_cipher) was chosen for simplicity and because it's been well researched.
- The block size is 128 bits because that's the length of the ChaCha20-Poly1305 tag, and the point of this construction is to avoid expansion.
- 8 rounds are used for [indifferentiability from a random permutation](https://eprint.iacr.org/2015/1069). 6 or 7 rounds may be sufficient, which would improve performance.
- [Whitening](https://en.wikipedia.org/wiki/Key_whitening) is used at the beginning/end because this is done in [similar block ciphers](https://en.wikipedia.org/wiki/Twofish). It could be removed/modified for better performance.
- HChaCha20 is used as the PRF because a) only a small output is needed so it should be [more efficient](https://cr.yp.to/snuffle/xsalsa-20110204.pdf) than ChaCha20, b) it offers domain separation from ChaCha20, and c) it's available in cryptographic libraries. If you ignore the last point, it makes more sense to use [HChaCha8](https://eprint.iacr.org/2019/1492) for a performance boost.
- The plaintext halves (64 bits) are padded with zeros to meet the HChaCha20 input length (128 bits). Then the PRF output (256 bits) is truncated to half the block size (64 bits) for the XOR, which is fine because PRF outputs can be safely truncated.
- HChaCha20 is also used for deriving the subkeys to avoid bringing in another primitive (ChaCha20) and for domain separation. The counter is on the opposite side to the plaintext to avoid an equivalent HChaCha20 input, even though the keys differ. One could also change the HChaCha20 constant for improved domain separation (e.g., from XChaCha20) but not every implementation allows this.

## Benchmarks
```
BenchmarkDotNet v0.14.0, Windows 11 (10.0.22631.4317/23H2/2023Update/SunValley3)

Intel Core i5-9600K CPU 3.70GHz (Coffee Lake), 1 CPU, 6 logical and 6 physical cores

.NET SDK 8.0.403
  [Host]     : .NET 8.0.10 (8.0.1024.46610), X64 RyuJIT AVX2
  DefaultJob : .NET 8.0.10 (8.0.1024.46610), X64 RyuJIT AVX2
```

| Method                                          | Mean       | Error     | StdDev   | Ratio         | RatioSD |
| ----------------------------------------------- | ---------: | --------: | -------: | ------------: | ------: |
| HChaChaCha.Encrypt()                            | 2,657.1 ns |  14.34 ns | 12.71 ns |  4.20x slower |   0.02x |
| HChaCha20 subkeys and whitening keys derivation | 1,287.1 ns |   0.75 ns |  0.59 ns |  2.03x slower |   0.00x |
| ChaCha20 subkeys and whitening keys derivation  |   262.5 ns |   0.15 ns |  0.14 ns |  2.41x faster |   0.00x |
| HChaCha20.DeriveKey()                           |   142.6 ns |   0.06 ns |  0.05 ns |  4.44x faster |   0.00x |
| ChaCha20.Fill()                                 |   114.0 ns |   0.03 ns |  0.03 ns |  5.55x faster |   0.00x |
| CTX with keyed BLAKE2b-256                      |   303.6 ns |   0.32 ns |  0.30 ns |  2.09x faster |   0.00x |
| AES-256.EncryptECB()                            |   633.4 ns |   0.39 ns |  0.33 ns |      baseline |         |

## Alternatives
There are two obvious alternatives if one wants to use something ChaCha20-based for commitment without expansion:

1. Replace the ChaCha20-Poly1305 tag with 128 bits of HChaCha20 output, with the encryption key or [a subkey](https://github.com/samuel-lucas6/kcChaCha20-Poly1305) as the HChaCha20 key and the tag as the HChaCha20 input. If you view the ChaCha20 permutation as a [random permutation](https://eprint.iacr.org/2020/1049), I believe this is key committing. I came up with this during my dissertation and named it CCP-C1 (ChaChaPoly-CMT-1), although that used a 256-bit tag.
2. Create a keyed sponge using the ChaCha20 permutation, with the encryption key or a subkey as the key and the ChaCha20-Poly1305 tag as the message. This again requires assuming the ChaCha20 permutation is a random permutation. I also came up with this during my dissertation and named it ChaChaMAC.

> [!CAUTION]
> Note that neither have been analysed, and the ChaCha20 permutation may not be a random permutation. Therefore, these ideas **MUST NOT** be used in practice.
