using RdpClient.Protocol.Security;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for the CredSSP <c>TSRequest</c> envelope.
/// </summary>
/// <remarks>
/// <para>
/// The expected byte strings are computed by hand from MS-CSSP 2.2.1 rather than
/// recorded from a client, because the failure this guards against is one no
/// capture would have shown: a server resets the connection with no diagnostic
/// when the envelope is wrong, so the only way to know the encoding is right is
/// to derive it from the specification and pin it.
/// </para>
/// <para>
/// Wrapping the NTLM message in <c>TSRequest</c> was a real defect here. The
/// client sent the NTLM message bare and the host closed the connection after
/// receiving it, which reads identically to a TLS problem.
/// </para>
/// </remarks>
public class CredSspTests
{
    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    [Fact]
    public void BuildRequest_WrapsOneNegoTokenInTheDocumentedStructure()
    {
        byte[] token = FromHex("deadbe");

        // Derivation, innermost first:
        //   negoToken  [0] OCTET STRING  -> 04 03 de ad be
        //   NegoDataItem ::= SEQUENCE    -> 30 07 a0 05 04 03 de ad be
        //   NegoData ::= SEQUENCE OF     -> 30 09 30 07 a0 05 04 03 de ad be
        //   negoTokens [1]                -> a1 0b <above>
        //   version [0] { INTEGER 6 }    -> a0 03 02 01 06
        //   TSRequest ::= SEQUENCE        -> 30 12 a0 03 02 01 06 a1 0b ...
        byte[] actual = CredSsp.BuildRequest([token]);

        Assert.Equal("3012a003020106a10b30093007a0050403deadbe",
                     Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void BuildRequest_WrapsTheVersionInAnIntegerTagNotBareContentOctets()
    {
        // The [0] field must carry a complete INTEGER TLV. Emitting a0 01 06
        // declares a single content byte holding a bare 0x06, which is not a
        // valid INTEGER, so the whole request stops being valid DER. The
        // reference encoding in sspi's own test vector begins a0 03 02 01 06.
        byte[] actual = CredSsp.BuildRequest();

        Assert.Equal("3005a003020106", Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void BuildRequest_CarriesClientNonceAtTag5NotTag4()
    {
        // errorCode is [4] and is client-originated only on the error path, so
        // the nonce occupies [5]. Getting this wrong shifts every later field.
        // clientNonce [5] OCTET STRING -> a5 04 04 02 aa bb, and version
        // [0] { INTEGER 6 } -> a0 03 02 01 06, so the outer length is 5 + 6 = 11.
        byte[] actual = CredSsp.BuildRequest(clientNonce: FromHex("aabb"));

        Assert.Equal("300ba003020106a5040402aabb", Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void BuildRequest_UsesLongFormLengthAbove127Bytes()
    {
        byte[] actual = CredSsp.BuildRequest([new byte[200]]);

        // A 200-byte token grows the encoding past 127 bytes at every level, so
        // each length must cross to the long form (0x81 nn) rather than wrap.
        // Sizes nest outwards: 203, 206, 209, 212, then 5 + 215 = 220.
        Assert.Equal(0x30, actual[0]);
        Assert.Equal(0x81, actual[1]);
        Assert.Equal(220, actual[2]);
    }

    [Fact]
    public void BuildRequest_EncodesALengthThatNeedsTwoOctets()
    {
        byte[] token = new byte[300];

        byte[] actual = CredSsp.BuildRequest([token]);

        // 300 does not fit in one length octet, so the long form announces two:
        // 0x82 hi lo, most significant octet first. Every nesting level that
        // outgrows one octet does the same, and each of them costs one extra
        // octet for the second length byte:
        //   negoToken [0] OCTET STRING  04 82 01 2C <300>          304
        //   NegoDataItem   SEQUENCE      30 82 01 34 <304>          312
        //   NegoData       SEQUENCE OF   30 82 01 38 <312>          316
        //   negoTokens [1]               A1 82 01 3C <316>          320
        //   version [0] { INTEGER 6 }   A0 03 02 01 06                5
        //   TSRequest       SEQUENCE     30 82 01 45 <325>          329
        Assert.Equal(0x30, actual[0]);
        Assert.Equal(0x82, actual[1]);
        Assert.Equal(0x01, actual[2]);
        Assert.Equal(0x45, actual[3]);
        Assert.Equal(329, actual.Length);

        // The length octets must be read back most significant first, not in the
        // order the encoder collected them.
        CredSsp.Request parsed = CredSsp.ParseRequest(actual);
        byte[] parsedToken = Assert.Single(parsed.NegoTokens);
        Assert.Equal(300, parsedToken.Length);
        Assert.Equal(token, parsedToken);
    }

    [Fact]
    public void ParseRequest_RoundTripsTheNegotiateRequest()
    {
        byte[] token = FromHex("4e544c4d5353500001000000");
        CredSsp.Request parsed = CredSsp.ParseRequest(CredSsp.BuildRequest([token]));

        Assert.Equal(CredSsp.ProtocolVersion, parsed.Version);
        byte[] negoToken = Assert.Single(parsed.NegoTokens);
        Assert.Equal(Convert.ToHexString(token).ToLowerInvariant(),
                     Convert.ToHexString(negoToken).ToLowerInvariant());
        Assert.Null(parsed.ErrorCode);
    }

    [Fact]
    public void ParseRequest_RoundTripsSeveralNegoTokensInOrder()
    {
        byte[] first = FromHex("aa");
        byte[] second = FromHex("bbcc");

        CredSsp.Request parsed = CredSsp.ParseRequest(CredSsp.BuildRequest([first, second]));

        Assert.Equal(2, parsed.NegoTokens.Count);
        Assert.Equal(0xAA, parsed.NegoTokens[0][0]);
        Assert.Equal("bbcc", Convert.ToHexString(parsed.NegoTokens[1]).ToLowerInvariant());
    }

    [Fact]
    public void ParseRequest_ReportsAServerErrorEvenWhenTheCodeIsZero()
    {
        // Presence of errorCode is the error signal; MS-CSSP 3.1.5 requires the
        // client to fail immediately with the status it carries.
        CredSsp.Request parsed = CredSsp.ParseRequest(CredSsp.BuildErrorRequest(0));

        Assert.NotNull(parsed.ErrorCode);
        Assert.Equal(0, parsed.ErrorCode!.Value);
        var error = Assert.Throws<NtlmAuthenticationException>(() => CredSsp.TryThrowServerError(parsed));
        Assert.Contains("NTSTATUS", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TryThrowServerError_IgnoresASuccessRequest()
    {
        CredSsp.Request parsed = CredSsp.ParseRequest(CredSsp.BuildRequest([new byte[] { 1 }]));

        Assert.False(CredSsp.TryThrowServerError(parsed));
    }
}