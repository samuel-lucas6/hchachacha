using System.Security.Cryptography;
using Geralt;

namespace HChaChaChaDotNet;

public static class HChaChaCha
{
    public const int KeySize = 32;
    public const int BlockSize = 16;
    private const int HalfSize = BlockSize / 2;
    private const int Rounds = 8;

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

        // Split the input into halves, padding with zeros for HChaCha20
        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> leftNonce = stackalloc byte[HChaCha20.NonceSize], rightNonce = stackalloc byte[HChaCha20.NonceSize];
        leftNonce.Clear(); rightNonce.Clear();
        plaintext[..HalfSize].CopyTo(leftNonce);
        plaintext[HalfSize..].CopyTo(rightNonce);
        Span<byte> leftHalf = leftNonce[..HalfSize], rightHalf = rightNonce[..HalfSize];

        // Pre-whitening
        XorBytes(leftHalf, whiteningKeys[..HalfSize]);
        XorBytes(rightHalf, whiteningKeys[HalfSize..BlockSize]);
        // Feistel network with HChaCha20 as the PRF
        for (int i = 0; i < Rounds; i += 2) {
            HChaCha20.DeriveKey(output, roundKeys.Slice(i * KeySize, KeySize), rightNonce);
            XorBytes(leftHalf, output);

            HChaCha20.DeriveKey(output, roundKeys.Slice((i + 1) * KeySize, KeySize), leftNonce);
            XorBytes(rightHalf, output);
        }
        // Post-whitening
        XorBytes(leftHalf, whiteningKeys[^BlockSize..^HalfSize]);
        XorBytes(rightHalf, whiteningKeys[^HalfSize..]);

        leftHalf.CopyTo(ciphertext[..HalfSize]);
        rightHalf.CopyTo(ciphertext[HalfSize..]);

        CryptographicOperations.ZeroMemory(roundKeys);
        CryptographicOperations.ZeroMemory(whiteningKeys);
        CryptographicOperations.ZeroMemory(output);
        CryptographicOperations.ZeroMemory(leftNonce);
        CryptographicOperations.ZeroMemory(rightNonce);
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

        Span<byte> output = stackalloc byte[HChaCha20.OutputSize];
        Span<byte> leftNonce = stackalloc byte[HChaCha20.NonceSize], rightNonce = stackalloc byte[HChaCha20.NonceSize];
        leftNonce.Clear(); rightNonce.Clear();
        ciphertext[..HalfSize].CopyTo(leftNonce);
        ciphertext[HalfSize..].CopyTo(rightNonce);
        Span<byte> leftHalf = leftNonce[..HalfSize], rightHalf = rightNonce[..HalfSize];

        XorBytes(leftHalf, whiteningKeys[^BlockSize..^HalfSize]);
        XorBytes(rightHalf, whiteningKeys[^HalfSize..]);
        for (int i = Rounds - 1; i >= 0; i -= 2) {
            HChaCha20.DeriveKey(output, roundKeys.Slice(i * KeySize, KeySize), leftNonce);
            XorBytes(rightHalf, output);

            HChaCha20.DeriveKey(output, roundKeys.Slice((i - 1) * KeySize, KeySize), rightNonce);
            XorBytes(leftHalf, output);
        }
        XorBytes(leftHalf, whiteningKeys[..HalfSize]);
        XorBytes(rightHalf, whiteningKeys[HalfSize..BlockSize]);

        leftHalf.CopyTo(plaintext[..HalfSize]);
        rightHalf.CopyTo(plaintext[HalfSize..]);

        CryptographicOperations.ZeroMemory(roundKeys);
        CryptographicOperations.ZeroMemory(whiteningKeys);
        CryptographicOperations.ZeroMemory(output);
        CryptographicOperations.ZeroMemory(leftNonce);
        CryptographicOperations.ZeroMemory(rightNonce);
    }

    private static void XorBytes(Span<byte> output, ReadOnlySpan<byte> input)
    {
        for (int i = 0; i < output.Length; i++) {
            output[i] ^= input[i];
        }
    }
}
