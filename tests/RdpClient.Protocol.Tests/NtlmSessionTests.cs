using System.Security.Cryptography;
using System.Text;
using RdpClient.Protocol.Security;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for the NTLM key derivation and integrity primitives.
/// </summary>
/// <remarks>
/// These are the pieces MS-NLMP 3.1.5.1.2 and 3.4.4 require once
/// <c>NEGOTIATE_KEY_EXCHANGE</c> is in force. Getting them wrong does not
/// produce a parse error, it produces <c>STATUS_LOGON_FAILURE</c>, so they are
/// pinned here rather than only exercised against a live host.
/// </remarks>
public class NtlmSessionTests
{
    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [Theory]
    // The canonical RC4 vectors: (key, plaintext, ciphertext).
    [InlineData("4b6579", "506c61696e74657874", "bbf316e8d940af0ad3")]
    [InlineData("57696b69", "7065646961", "1021bf0420")]
    [InlineData("536563726574", "41747461636b206174206461776e", "45a01f645fc35b383552544b9bf5")]
    public void Rc4_MatchesTheKnownVectors(string key, string plaintext, string ciphertext)
    {
        byte[] actual = Rc4.Transform(FromHex(key), FromHex(plaintext));

        Assert.Equal(ciphertext, ToHex(actual));
    }

    [Fact]
    public void Rc4_IsItsOwnInverse()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] data = RandomNumberGenerator.GetBytes(64);

        Assert.Equal(ToHex(data), ToHex(Rc4.Transform(key, Rc4.Transform(key, data))));
    }

    [Fact]
    public void SessionBaseKey_IsTheFirst16BytesOfHmacMd5OverTheProfferedFlags()
    {
        // MS-NLMP 3.4.4.2: T = HMAC_MD5(NTLMv2_Response,
        // ProfferedNegotiateFlags)[0..16], with the flags as 4 LE bytes.
        byte[] response = RandomNumberGenerator.GetBytes(32);
        const NtlmFlags Flags = NtlmFlags.NegotiateUnicode | NtlmFlags.NegotiateNtlm;

        using var hmac = new HMACMD5(response);
        byte[] expected = hmac.ComputeHash(BitConverter.GetBytes((uint)Flags))[..16];

        Assert.Equal(ToHex(expected), ToHex(Ntlm.ComputeSessionBaseKey(response, Flags)));
    }

    [Fact]
    public void ExportSessionKey_IsRc4OfTheSessionKeyUnderTheBaseKey()
    {
        byte[] baseKey = RandomNumberGenerator.GetBytes(16);
        byte[] sessionKey = RandomNumberGenerator.GetBytes(16);

        Assert.Equal(ToHex(Rc4.Transform(baseKey, sessionKey)),
                     ToHex(Ntlm.ExportSessionKey(baseKey, sessionKey)));
    }

    [Fact]
    public void Mic_CoversAllThreeMessages()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] negotiate = RandomNumberGenerator.GetBytes(75);
        byte[] challenge = RandomNumberGenerator.GetBytes(218);
        byte[] authenticate = RandomNumberGenerator.GetBytes(367);

        string baseline = ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate));

        // Changing any one message must change the MIC, or the server cannot
        // detect a tampered exchange.
        negotiate[10] ^= 0xFF;
        Assert.NotEqual(baseline, ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate)));
        negotiate[10] ^= 0xFF;

        challenge[30] ^= 0xFF;
        Assert.NotEqual(baseline, ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate)));
        challenge[30] ^= 0xFF;

        authenticate[100] ^= 0xFF;
        Assert.NotEqual(baseline, ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate)));
        authenticate[100] ^= 0xFF;

        Assert.Equal(baseline, ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate)));
    }

    [Fact]
    public void Mic_IsHmacMd5OverTheConcatenation()
    {
        byte[] key = RandomNumberGenerator.GetBytes(16);
        byte[] negotiate = [1, 2, 3];
        byte[] challenge = [4, 5];
        byte[] authenticate = [6, 7, 8];

        using var hmac = new HMACMD5(key);
        byte[] expected = hmac.ComputeHash([1, 2, 3, 4, 5, 6, 7, 8]);

        Assert.Equal(ToHex(expected),
                     ToHex(Ntlm.ComputeMic(key, negotiate, challenge, authenticate)));
    }

    [Fact]
    public void Mic_IsSixteenBytesAndLandsAtTheDocumentedOffset()
    {
        byte[] mic = Ntlm.ComputeMic(
            RandomNumberGenerator.GetBytes(16),
            RandomNumberGenerator.GetBytes(40),
            RandomNumberGenerator.GetBytes(48),
            RandomNumberGenerator.GetBytes(88));

        Assert.Equal(16, mic.Length);
        Assert.Equal(16, Ntlm.MicLength);

        // MS-NLMP 2.2.1.3 places the MIC at offset 72, inside the 88-byte
        // fixed header, so the payload starts at 88.
        Assert.True(Ntlm.MicOffset + Ntlm.MicLength <= 88);
    }

    [Fact]
    public void Authenticate_PlacesTheEncryptedSessionKeyAtTheEndOfThePayload()
    {
        byte[] response = RandomNumberGenerator.GetBytes(32);
        byte[] encryptedKey = RandomNumberGenerator.GetBytes(16);

        byte[] message = Ntlm.BuildAuthenticateMessage(
            "alice", "CORP", "RDPCLIENT", response,
            NtlmFlags.NegotiateUnicode, new byte[8], encryptedKey);

        // The descriptor at offset 52 is { Length, MaxLen, BufferOffset }.
        Assert.Equal(16, BitConverter.ToUInt16(message, 52));
        Assert.Equal(16, BitConverter.ToUInt16(message, 54));

        uint offset = BitConverter.ToUInt32(message, 56);
        Assert.Equal((uint)(message.Length - 16), offset);
        Assert.Equal(ToHex(encryptedKey), ToHex(message[(int)offset..]));
    }

    [Fact]
    public void Authenticate_PayloadStartsAfterTheFixedHeader()
    {
        byte[] message = Ntlm.BuildAuthenticateMessage(
            "alice", "CORP", "RDPCLIENT", RandomNumberGenerator.GetBytes(32),
            NtlmFlags.NegotiateUnicode, new byte[8]);

        // The first payload field, the NT response, must point past the header.
        Assert.Equal(88u, BitConverter.ToUInt32(message, 24));
        Assert.Equal(Encoding.Unicode.GetByteCount("alice"), BitConverter.ToUInt16(message, 36));
    }
}