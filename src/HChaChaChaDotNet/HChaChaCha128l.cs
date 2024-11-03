using System.Security.Cryptography;
using Geralt;

namespace HChaChaChaDotNet;

public static class HChaChaCha128l
{
    public const int KeySize = 32;
    public const int BlockSize = 16;
    private const int HalfSize = BlockSize / 2;
    private const int Rounds = 6;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, BlockSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, BlockSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> roundKeys = stackalloc byte[KeySize * Rounds];
        Span<byte> nonce = stackalloc byte[HChaCha20.NonceSize];
        nonce.Clear();

        // Derive 128-bit whitening keys
        Span<byte> whiteningKeys = stackalloc byte[KeySize];
        nonce[^1]++;
        HChaCha20.DeriveKey(whiteningKeys, key, nonce);

        // Derive 256-bit round keys
        for (int i = 0; i < Rounds; i++) {
            nonce[^1]++;
            HChaCha20.DeriveKey(roundKeys.Slice(i * KeySize, KeySize), key, nonce);
        }

        // Split the input into halves, padding the XOR result with zeros for HChaCha20
        nonce.Clear();
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize], input = nonce[..HalfSize];
        Span<byte> leftHalf = stackalloc byte[HalfSize], rightHalf = stackalloc byte[HalfSize];
        plaintext[..HalfSize].CopyTo(leftHalf);
        plaintext[HalfSize..].CopyTo(rightHalf);
        Span<byte> leftLeftHalf = leftHalf[..(HalfSize / 2)], rightLeftHalf = leftHalf[(HalfSize / 2)..];

        // Pre-whitening
        XorBytes(leftHalf, whiteningKeys[..HalfSize]);
        XorBytes(rightHalf, whiteningKeys[HalfSize..BlockSize]);
        // Lai-Massey with HChaCha20 as the PRF
        for (int i = 0; i < Rounds; i++) {
            XorBytes(input, leftHalf, rightHalf);
            HChaCha20.DeriveKey(output, roundKeys.Slice(i * KeySize, KeySize), nonce);
            XorBytes(leftHalf, output);
            XorBytes(rightHalf, output);

            // Linear orthomorphism on leftHalf - unnecessary in the final round since it has no cryptographic strength
            if (i < Rounds - 1) {
                // (xL, xR) => (xR, xL)
                for (int j = 0; j < leftLeftHalf.Length; j++) {
                    (leftLeftHalf[j], rightLeftHalf[j]) = (rightLeftHalf[j], leftLeftHalf[j]);
                }
                // (xR, xL ⊕ xR)
                XorBytes(rightLeftHalf, leftLeftHalf);
            }
        }
        // Post-whitening
        XorBytes(leftHalf, whiteningKeys[^BlockSize..^HalfSize]);
        XorBytes(rightHalf, whiteningKeys[^HalfSize..]);

        leftHalf.CopyTo(ciphertext[..HalfSize]);
        rightHalf.CopyTo(ciphertext[HalfSize..]);

        CryptographicOperations.ZeroMemory(roundKeys);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(whiteningKeys);
        CryptographicOperations.ZeroMemory(output);
        CryptographicOperations.ZeroMemory(leftHalf);
        CryptographicOperations.ZeroMemory(rightHalf);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key)
    {
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, BlockSize);
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, BlockSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> roundKeys = stackalloc byte[KeySize * Rounds];
        Span<byte> nonce = stackalloc byte[HChaCha20.NonceSize];
        nonce.Clear();

        Span<byte> whiteningKeys = stackalloc byte[KeySize];
        nonce[^1]++;
        HChaCha20.DeriveKey(whiteningKeys, key, nonce);

        for (int i = 0; i < Rounds; i++) {
            nonce[^1]++;
            HChaCha20.DeriveKey(roundKeys.Slice(i * KeySize, KeySize), key, nonce);
        }

        nonce.Clear();
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize], input = nonce[..HalfSize];
        Span<byte> leftHalf = stackalloc byte[HalfSize], rightHalf = stackalloc byte[HalfSize];
        ciphertext[..HalfSize].CopyTo(leftHalf);
        ciphertext[HalfSize..].CopyTo(rightHalf);
        Span<byte> leftLeftHalf = leftHalf[..(HalfSize / 2)], rightLeftHalf = leftHalf[(HalfSize / 2)..];

        XorBytes(leftHalf, whiteningKeys[^BlockSize..^HalfSize]);
        XorBytes(rightHalf, whiteningKeys[^HalfSize..]);
        for (int i = Rounds - 1; i >= 0; i--) {
            XorBytes(input, leftHalf, rightHalf);
            HChaCha20.DeriveKey(output, roundKeys.Slice(i * KeySize, KeySize), nonce);
            XorBytes(leftHalf, output);
            XorBytes(rightHalf, output);

            if (i > 0) {
                // (xL, xR) => (xR, xL)
                for (int j = 0; j < leftLeftHalf.Length; j++) {
                    (leftLeftHalf[j], rightLeftHalf[j]) = (rightLeftHalf[j], leftLeftHalf[j]);
                }
                // (xR ⊕ xL, xL)
                XorBytes(leftLeftHalf, rightLeftHalf);
            }
        }
        XorBytes(leftHalf, whiteningKeys[..HalfSize]);
        XorBytes(rightHalf, whiteningKeys[HalfSize..BlockSize]);

        leftHalf.CopyTo(plaintext[..HalfSize]);
        rightHalf.CopyTo(plaintext[HalfSize..]);

        CryptographicOperations.ZeroMemory(roundKeys);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(whiteningKeys);
        CryptographicOperations.ZeroMemory(output);
        CryptographicOperations.ZeroMemory(leftHalf);
        CryptographicOperations.ZeroMemory(rightHalf);
    }

    private static void XorBytes(Span<byte> output, ReadOnlySpan<byte> input1, ReadOnlySpan<byte> input2)
    {
        for (int i = 0; i < output.Length; i++) {
            output[i] = (byte)(input1[i] ^ input2[i]);
        }
    }

    private static void XorBytes(Span<byte> output, ReadOnlySpan<byte> input)
    {
        for (int i = 0; i < output.Length; i++) {
            output[i] ^= input[i];
        }
    }
}
