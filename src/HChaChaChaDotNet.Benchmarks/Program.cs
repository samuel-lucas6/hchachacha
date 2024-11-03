using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Geralt;

namespace HChaChaChaDotNet.Benchmarks;

[Config(typeof(Configuration))]
public class Program
{
    private readonly byte[] _ciphertext = new byte[HChaChaCha128f.BlockSize];
    private readonly byte[] _plaintext = new byte[HChaChaCha128f.BlockSize];
    private readonly byte[] _key = new byte[HChaChaCha128f.KeySize];
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

    [Benchmark(Description = "AES-256 (EncryptEcb)", Baseline = true)]
    public void RunAes256EncryptEcb()
    {
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.EncryptEcb(_plaintext, _ciphertext, PaddingMode.None);
    }

    [Benchmark(Description = "AES-256 (TransformBlock)")]
    public void RunAes256TransformBlock()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        using var encryptor = aes.CreateEncryptor(_key, rgbIV: null);
        encryptor.TransformBlock(_plaintext, inputOffset: 0, _plaintext.Length, _ciphertext, outputOffset: 0);
    }

    [Benchmark(Description = "CTX (keyed BLAKE2b-256)")]
    public void RunCtx()
    {
        using var blake2b = new IncrementalBLAKE2b(_output.Length, _key);
        blake2b.Update(_nonce);
        // Skipping associated data
        blake2b.Update(ReadOnlySpan<byte>.Empty);
        blake2b.Update(_tag);
        blake2b.Finalize(_output);
    }

    [Benchmark(Description = "HChaChaCha128f (balanced Feistel)")]
    public void RunHChaChaCha128f()
    {
        HChaChaCha128f.Encrypt(_ciphertext, _plaintext, _key);
    }

    [Benchmark(Description = "HChaChaCha128l (Lai-Massey)")]
    public void RunHChaChaCha128l()
    {
        HChaChaCha128l.Encrypt(_ciphertext, _plaintext, _key);
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
