using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Geralt;

namespace HChaChaChaDotNet.Benchmarks;

[Config(typeof(Configuration))]
public class Program
{
    private readonly byte[] _ciphertext = new byte[HChaChaCha.BlockSize];
    private readonly byte[] _plaintext = new byte[HChaChaCha.BlockSize];
    private readonly byte[] _key = new byte[HChaChaCha.KeySize];
    private readonly byte[] _output = new byte[HChaCha20.OutputSize];
    private readonly byte[] _nonce = new byte[ChaCha20.NonceSize];
    private readonly byte[] _feistelRoundKeys = new byte[HChaCha20.KeySize * 9];
    private readonly byte[] _laiMasseyRoundKeys = new byte[HChaCha20.KeySize * 7];
    private readonly byte[] _tag = new byte[Poly1305.TagSize];

    [GlobalSetup]
    public void Setup()
    {
        RandomNumberGenerator.Fill(_key);
        RandomNumberGenerator.Fill(_plaintext);
        RandomNumberGenerator.Fill(_nonce);
        RandomNumberGenerator.Fill(_tag);
    }

    [Benchmark(Description = "AES-256", Baseline = true)]
    public void RunAes256()
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.EncryptEcb(_plaintext, _ciphertext, PaddingMode.None);
    }

    [Benchmark(Description = "CTX with keyed BLAKE2b-256")]
    public void RunCtx()
    {
        using var blake2b = new IncrementalBLAKE2b(_output.Length, _key);
        blake2b.Update(_nonce);
        // Skipping associated data
        blake2b.Update(ReadOnlySpan<byte>.Empty);
        blake2b.Update(_tag);
        blake2b.Finalize(_output);
    }

    [Benchmark(Description = "HChaChaCha (balanced Feistel)")]
    public void RunHChaChaCha()
    {
        HChaChaCha.Encrypt(_ciphertext, _plaintext, _key);
    }

    [Benchmark(Description = "HChaChaCha2 (Lai-Massey)")]
    public void RunHChaChaCha2()
    {
        HChaChaCha2.Encrypt(_ciphertext, _plaintext, _key);
    }

    [Benchmark(Description = "HChaCha20 subkeys and whitening keys derivation (Feistel)")]
    public void RunHChaCha20FeistelKdf()
    {
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
    }

    [Benchmark(Description = "HChaCha20 subkeys and whitening keys derivation (Lai-Massey)")]
    public void RunHChaCha20LaiMasseyKdf()
    {
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
        _plaintext[^1]++;
        HChaCha20.DeriveKey(_output, _key, _plaintext);
    }

    [Benchmark(Description = "ChaCha20 subkeys and whitening keys derivation (Feistel)")]
    public void RunChaCha20FeistelKdf()
    {
        ChaCha20.Fill(_feistelRoundKeys, _nonce, _key);
    }

    [Benchmark(Description = "ChaCha20 subkeys and whitening keys derivation (Lai-Massey)")]
    public void RunChaCha20LaiMasseyKdf()
    {
        ChaCha20.Fill(_laiMasseyRoundKeys, _nonce, _key);
    }

    [Benchmark(Description = "HChaCha20")]
    public void RunHChaCha20()
    {
        HChaCha20.DeriveKey(_output, _key, _plaintext);
    }

    [Benchmark(Description = "ChaCha20 with 256-bit output")]
    public void RunChaCha20()
    {
        ChaCha20.Fill(_output, _nonce, _key);
    }

    static void Main(string[] args)
    {
        BenchmarkRunner.Run<Program>();
    }
}
