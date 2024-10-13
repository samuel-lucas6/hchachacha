namespace HChaChaChaDotNet.Tests;

[TestClass]
public class HChaChaChaTests
{
    public static IEnumerable<object[]> TestVectors()
    {
        yield return
        [
            "9e16adbfb3922e0d544230ffed5a0b70",
            "00000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
        yield return
        [
            "8be3abc3b41ffe0ea7fa9756824b63da",
            "00000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000"
        ];
        yield return
        [
            "aac6ad4b7e52bbc6aef51aad628f3aa1",
            "c1c0e58bd913006feba00f4b3cc3594e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        ];
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return [ HChaChaCha.BlockSize + 1, HChaChaCha.BlockSize, HChaChaCha.KeySize ];
        yield return [ HChaChaCha.BlockSize - 1, HChaChaCha.BlockSize, HChaChaCha.KeySize ];
        yield return [ HChaChaCha.BlockSize, HChaChaCha.BlockSize + 1, HChaChaCha.KeySize ];
        yield return [ HChaChaCha.BlockSize, HChaChaCha.BlockSize - 1, HChaChaCha.KeySize ];
        yield return [ HChaChaCha.BlockSize, HChaChaCha.BlockSize, HChaChaCha.KeySize + 1 ];
        yield return [ HChaChaCha.BlockSize, HChaChaCha.BlockSize, HChaChaCha.KeySize - 1 ];
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);

        HChaChaCha.Encrypt(c, p, k);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaChaCha.Encrypt(c, p, k));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);

        HChaChaCha.Decrypt(p, c, k);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HChaChaCha.Decrypt(p, c, k));
    }
}
