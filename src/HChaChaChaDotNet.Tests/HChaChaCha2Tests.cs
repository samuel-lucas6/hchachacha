namespace HChaChaChaDotNet.Tests;

[TestClass]
public class HChaChaCha2Tests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "e05fd6955ab1cf7f2cc53359d0363a96",
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
        yield return
        [
            "d3db76e492773056f0a8d9cb9c798f23",
            "00000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "39a5037d34b1f9424e39115c3a2779d7",
            "c1c0e58bd913006feba00f4b3cc3594e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ HChaChaCha2.BlockSize + 1, HChaChaCha2.BlockSize, HChaChaCha2.KeySize ];
        yield return [ HChaChaCha2.BlockSize - 1, HChaChaCha2.BlockSize, HChaChaCha2.KeySize ];
        yield return [ HChaChaCha2.BlockSize, HChaChaCha2.BlockSize + 1, HChaChaCha2.KeySize ];
        yield return [ HChaChaCha2.BlockSize, HChaChaCha2.BlockSize - 1, HChaChaCha2.KeySize ];
        yield return [ HChaChaCha2.BlockSize, HChaChaCha2.BlockSize, HChaChaCha2.KeySize + 1 ];
        yield return [ HChaChaCha2.BlockSize, HChaChaCha2.BlockSize, HChaChaCha2.KeySize - 1 ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);

        HChaChaCha2.Encrypt(c, p, k);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaChaCha2.Encrypt(c, p, k));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);

        HChaChaCha2.Decrypt(p, c, k);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaChaCha2.Decrypt(p, c, k));
    }
}
