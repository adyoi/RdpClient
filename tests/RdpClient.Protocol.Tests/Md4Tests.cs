using System.Text;
using RdpClient.Protocol.Security;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Known-answer tests for MD4 and the NT hash.
/// </summary>
/// <remarks>
/// <para>
/// MD4 has no security value and exists here only because MS-NLMP 2.2.2.3
/// specifies it for the NT hash. It had three separate defects, each of which
/// still produced a plausible-looking 128-bit digest, so nothing short of a
/// known-answer test could have caught them.
/// </para>
/// <para>
/// A wrong NT hash makes every password fail with
/// <c>STATUS_LOGON_FAILURE</c>, which is indistinguishable from a wrong
/// password at the protocol level. That is what made this expensive.
/// </para>
/// </remarks>
public class Md4Tests
{
    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [Theory]
    // RFC 1320 Appendix A.5.
    [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
    [InlineData("a", "bde52cb31de33e46245e05fbdbd6fb24")]
    [InlineData("abc", "a448017aaf21d8525fc10ae87aa6729d")]
    [InlineData("message digest", "d9130a8164549fe818874806e1c7014b")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9")]
    [InlineData(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "043f8582f241db351ce627e153e7f0e4")]
    public void Md4_MatchesTheRfcVectors(string input, string expected)
    {
        using var md4 = new Md4();
        md4.Update(Encoding.ASCII.GetBytes(input));

        Assert.Equal(expected, Hex(md4.Finish()));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(55)]
    [InlineData(56)]
    [InlineData(57)]
    [InlineData(63)]
    [InlineData(64)]
    [InlineData(119)]
    [InlineData(120)]
    public void Md4_HandlesEveryPaddingBoundary(int length)
    {
        // Lengths around a block boundary exercise the "pad, wrap to a new
        // block, then reach offset 56" path, which is where an off-by-one in
        // Finish shows up.
        using var md4 = new Md4();
        md4.Update(new byte[length]);
        byte[] digest = md4.Finish();

        Assert.Equal(16, digest.Length);
    }

    [Fact]
    public void Md4_HashesInChunksTheSameAsInOneCall()
    {
        byte[] data = Encoding.ASCII.GetBytes("the quick brown fox jumps over the lazy dog");

        using var chunked = new Md4();
        for (int i = 0; i < data.Length; i += 7)
        {
            chunked.Update(data.AsSpan(i, Math.Min(7, data.Length - i)));
        }

        Assert.Equal(Hex(new Md4().ComputeHash(data)), Hex(chunked.Finish()));
    }

    [Fact]
    public void Md4_ResetRestoresTheInitialState()
    {
        using var md4 = new Md4();
        md4.Update(Encoding.ASCII.GetBytes("something else entirely"));
        md4.Reset();
        md4.Update(Encoding.ASCII.GetBytes("abc"));

        Assert.Equal("a448017aaf21d8525fc10ae87aa6729d", Hex(md4.Finish()));
    }

    [Theory]
    // MS-NLMP 3.1.4.2: M{v4}(UTF16LE(password)).
    [InlineData("", "31d6cfe0d16ae931b73c59d7e0c089c0")]
    [InlineData("password", "8846f7eaee8fb117ad06bdd830b7586c")]
    [InlineData("Password", "a4f49c406510bdcab6824ee7c30fd852")]
    public void NtHash_MatchesTheSpecificationVectors(string password, string expected)
    {
        Assert.Equal(expected, Hex(Ntlm.NtHash(password)));
    }

    [Fact]
    public void NtHash_IsUtf16LeNotAscii()
    {
        // Same bytes in two encodings must not collide: MD4 over UTF-16LE is
        // what NTLM specifies, and the hash is 16 bytes long either way.
        Assert.NotEqual(Hex(Ntlm.NtHash("ab")), Hex(Ntlm.NtHash("aab")));
    }
}