# HChaChaCha
HChaChaCha is a family of block ciphers built from [HChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2) for use in the [PACT/comPACT](https://eprint.iacr.org/2024/1382) and [SC](https://eprint.iacr.org/2024/875) transforms for AEAD commitment. The motivation being that ChaCha20-Poly1305 users likely don't want to use AES for commitment.

> [!CAUTION]
> These are experimental constructions that have not been peer reviewed. I have also not done a proper literature review. Therefore, they **MUST NOT** be used in production.

## Design Rationale
- A balanced [Feistel network](https://en.wikipedia.org/wiki/Feistel_cipher) was chosen for simplicity and because it's been well researched. However, I came up with another variant that uses [Lai-Massey](https://en.wikipedia.org/wiki/Lai%E2%80%93Massey_scheme) because I thought this would be more performant.
- With the Feistel design, 8 rounds are used for [indifferentiability from a random permutation](https://eprint.iacr.org/2015/1069). In reality, 6 or 7 rounds may be sufficient, which would improve performance. With the Lai–Massey design, 6 rounds are used for [BBB security](https://eprint.iacr.org/2023/1834) and [sequential indifferentiability](https://link.springer.com/article/10.1007/s10623-024-01361-6).
- The block size is 128 bits because that's the length of the ChaCha20-Poly1305 tag, and the point of this construction is to avoid expansion. However, it's easy to convert these constructions to 256-bit block ciphers.
- [Whitening](https://en.wikipedia.org/wiki/Key_whitening) is used at the beginning/end because this is done in [similar block ciphers](https://en.wikipedia.org/wiki/Twofish). It could be removed/modified for better performance.
- HChaCha20 is used as the PRF because a) only a small output is needed so it should be [more efficient](https://cr.yp.to/snuffle/xsalsa-20110204.pdf) than ChaCha20, b) it offers domain separation from ChaCha20, and c) it's available in cryptographic libraries. If you ignore the last point, it makes more sense to use [HChaCha8](https://eprint.iacr.org/2019/1492) for a performance boost.
- The plaintext halves (64 bits) are padded with zeros to meet the HChaCha20 input length (128 bits). Then the PRF output (256 bits) is truncated to half the block size (64 bits) for the XORs, which is fine because PRF outputs can be safely truncated.
- HChaCha20 is also used for deriving the subkeys to avoid bringing in another primitive (ChaCha20) and for domain separation. The counter is on the opposite side to the plaintext and starts at 1 to avoid an equivalent HChaCha20 input, even though the keys differ. One could also change the HChaCha20 constant for improved domain separation (e.g., from XChaCha20) but not every implementation allows this.

## Benchmarks
```
BenchmarkDotNet v0.14.0, Windows 11 (10.0.22631.4317/23H2/2023Update/SunValley3)

Intel Core i5-9600K CPU 3.70GHz (Coffee Lake), 1 CPU, 6 logical and 6 physical cores

.NET SDK 8.0.403
[Host] : .NET 8.0.10 (8.0.1024.46610), X64 RyuJIT AVX2
DefaultJob : .NET 8.0.10 (8.0.1024.46610), X64 RyuJIT AVX2
```

| Method                                                       |       Mean |   Error |  StdDev |        Ratio | RatioSD |
| ------------------------------------------------------------ | ---------: | ------: | ------: | -----------: | ------: |
| AES-256                                                      |   684.6 ns | 3.76 ns | 3.14 ns |     baseline |         |
| CTX with keyed BLAKE2b-256                                   |   285.3 ns | 0.28 ns | 0.25 ns | 2.40x faster |   0.01x |
| HChaChaCha (balanced Feistel)                                | 2,607.8 ns | 1.08 ns | 0.90 ns | 3.81x slower |   0.02x |
| HChaChaCha2 (Lai-Massey)                                     | 2,134.6 ns | 0.60 ns | 0.53 ns | 3.12x slower |   0.01x |
| HChaCha20 subkeys and whitening keys derivation (Feistel)    | 1,293.0 ns | 0.66 ns | 0.55 ns | 1.89x slower |   0.01x |
| HChaCha20 subkeys and whitening keys derivation (Lai-Massey) | 1,006.3 ns | 0.55 ns | 0.48 ns | 1.47x slower |   0.01x |
| ChaCha20 subkeys and whitening keys derivation (Feistel)     |   261.0 ns | 0.11 ns | 0.10 ns | 2.62x faster |   0.01x |
| ChaCha20 subkeys and whitening keys derivation (Lai-Massey)  |   326.2 ns | 0.13 ns | 0.12 ns | 2.10x faster |   0.01x |
| HChaCha20                                                    |   142.7 ns | 0.05 ns | 0.05 ns | 4.80x faster |   0.02x |
| ChaCha20 with 256-bit output                                 |   113.0 ns | 0.05 ns | 0.04 ns | 6.06x faster |   0.03x |

## Alternatives
There are two obvious alternatives if one wants to use something ChaCha20-based for commitment without expansion:

1. Replace the ChaCha20-Poly1305 tag with 128 bits of HChaCha20 output, with the encryption key or [a subkey](https://github.com/samuel-lucas6/kcChaCha20-Poly1305) as the HChaCha20 key and the tag as the HChaCha20 input. If you view the ChaCha20 permutation as a [random permutation](https://eprint.iacr.org/2020/1049), I believe this is key committing. I came up with this during my dissertation and named it CCP-C1 (ChaChaPoly-CMT-1), although that used a 256-bit tag.
2. Create a keyed sponge using the ChaCha20 permutation, with the encryption key or a subkey as the key and the ChaCha20-Poly1305 tag as the message. This again requires assuming the ChaCha20 permutation is a random permutation. I also came up with this during my dissertation and named it ChaChaMAC.

> [!CAUTION]
> Note that neither have been analysed, and the ChaCha20 permutation may not be a random permutation. Therefore, these ideas **MUST NOT** be used in production.
