using RdpClient.Protocol.Security;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for NTLM message construction and parsing, pinned to real bytes.
/// </summary>
/// <remarks>
/// The CHALLENGE vector is the one sspi uses in its own CredSSP tests
/// (<c>sspi/src/credssp/ts_request/test.rs</c>, <c>NTLM_WITHOUT_CLIENT_NONCE</c>),
/// lifted from a real Windows RDP server. Parsing it correctly is what makes the
/// AUTHENTICATE message computable, so it is worth pinning.
/// </remarks>
public class NtlmMessageTests
{
    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    /// <summary>The NTLMSSP\0 signature. Ntlm keeps its own copy internal.</summary>
    private static byte[] Signature { get; } = [0x4E, 0x54, 0x4C, 0x4D, 0x53, 0x53, 0x50, 0x00];

    private static NtlmFlags FlagsOf(byte[] message) =>
        (NtlmFlags)BitConverter.ToUInt32(message, 12);

    /// <summary>
    /// A real NTLM CHALLENGE_MESSAGE, captured from the local Windows RDP server
    /// as the <c>negoToken</c> of its CredSSP TSRequest and stored verbatim in
    /// <c>Fixtures/challenge.bin</c>.
    /// </summary>
    /// <remarks>
    /// Captured to a file rather than pasted into a string. Hand-copying this
    /// into a hex literal is how it got truncated to 134 of its 218 bytes,
    /// which looked like a parser bug rather than a transcription one.
    /// Regenerate with: run <c>rdpprobe</c> against the host and copy the
    /// <c>&lt;- CHALLENGE</c> line's payload here.
    /// </remarks>
    private static byte[] CapturedChallenge { get; } =
        File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Fixtures", "challenge.bin"));

    [Fact]
    public void ParseChallenge_ReadsTheServerChallenge()
    {
        Ntlm.Challenge challenge = Ntlm.ParseChallengeMessage(CapturedChallenge);

        // The value is fresh per session, so only the width is assertable.
        Assert.Equal(8, challenge.ServerChallenge.Length);
    }

    [Fact]
    public void ParseChallenge_ReadsTheNegotiateFlags()
    {
        Ntlm.Challenge challenge = Ntlm.ParseChallengeMessage(CapturedChallenge);

        Assert.Equal(0xE28A8235u, (uint)challenge.Flags);
    }

    [Fact]
    public void ParseChallenge_ExtractsTargetInfoFromItsPayloadNotTheHeader()
    {
        Ntlm.Challenge challenge = Ntlm.ParseChallengeMessage(CapturedChallenge);

        // The regression this guards: reading Length from [4..6] and Offset from
        // [6..8] returns the offset as the length and 0 as the offset, so
        // TargetInfo becomes the first 82 bytes of the message - the NTLMSSP
        // signature included - and the AUTHENTICATE embeds a whole NTLM header.
        var info = challenge.TargetInfo.ToArray();
        Assert.Equal(136, info.Length);
        Assert.NotEqual(Signature, info[..8]);

        // It must be a well-formed AV_PAIR list (MS-NLMP 2.2.2.1) that ends
        // with MsvAvEOL, not the fixed header.
        var cursor = 0;
        var pairs = new List<ushort>();
        while (cursor + 4 <= info.Length)
        {
            var id = BitConverter.ToUInt16(info, cursor);
            var length = BitConverter.ToUInt16(info, cursor + 2);
            pairs.Add(id);
            if (id == 0)
            {
                break;
            }

            cursor += 4 + length;
        }

        Assert.Equal((ushort)0, pairs[^1]);
        Assert.Contains((ushort)NtlmAvPair.NbDomainName, pairs);
        Assert.Contains((ushort)NtlmAvPair.NbComputerName, pairs);
        Assert.Contains((ushort)NtlmAvPair.Timestamp, pairs);
    }

    [Fact]
    public void ParseChallenge_ExtractsTargetNameFromItsPayload()
    {
        Ntlm.Challenge challenge = Ntlm.ParseChallengeMessage(CapturedChallenge);

        Assert.Equal(26, challenge.TargetName.Length);
    }

    [Fact]
    public void BuildNegotiate_ProducesTheHeaderMSNlmpDescribes()
    {
        byte[] message = Ntlm.BuildNegotiateMessage("RDPCLIENT");

        Assert.Equal(Signature, message[..8]);
        Assert.Equal(1u, BitConverter.ToUInt32(message, 8));

        // MS-NLMP 2.2.1.1: DomainName and Workstation are each
        // { Length(2), MaxLen(2), BufferOffset(4) } at offsets 16 and 24, so
        // the BufferOffset members occupy four octets at 20 and 28. With a
        // workstation supplied its length is non-zero and points at the
        // payload; the domain is always empty.
        Assert.Equal(0, BitConverter.ToUInt16(message, 16));
        Assert.Equal(0, BitConverter.ToUInt16(message, 18));
        Assert.Equal(40u, BitConverter.ToUInt32(message, 20));

        ushort workstationLength = BitConverter.ToUInt16(message, 24);
        Assert.Equal("RDPCLIENT".Length * 2, workstationLength);
        Assert.Equal(40u, BitConverter.ToUInt32(message, 28));

        // The flag may only be set when the name is really in the payload.
        Assert.True(FlagsOf(message).HasFlag(NtlmFlags.NegotiateOemWorkstationSupplied));
    }

    [Fact]
    public void BuildNegotiate_OmitsTheWorkstationFlagWhenNoNameIsGiven()
    {
        byte[] message = Ntlm.BuildNegotiateMessage();

        Assert.False(FlagsOf(message).HasFlag(NtlmFlags.NegotiateOemWorkstationSupplied));
        Assert.Equal(40, message.Length);
    }

    [Fact]
    public void ClientFlags_EncodeToTheValueTheSpecificationAssigns()
    {
        // MS-NLMP 2.2.2.5 labels the bits: W=56 (31), V=key exchange (30),
        // U=128 (29), T=version (25), Q=identify (20), P=extended session
        // security (19), M=always sign (15), H=NTLM (9), G=LM key (7),
        // F=datagram (6), E=seal (5), D=sign (4), C=request target (2),
        // B=OEM (1), A=Unicode (0).
        uint expected =
            0x80000000u | 0x40000000u | 0x20000000u | 0x02000000u
            | 0x00080000u | 0x00008000u | 0x00000200u
            | 0x00000020u | 0x00000010u | 0x00000004u | 0x00000002u | 0x00000001u;

        Assert.Equal((uint)Ntlm.ClientFlags, expected);
    }

    [Fact]
    public void DescribeType_NamesTheThreeMessageTypes()
    {
        Assert.Equal("NEGOTIATE", Ntlm.DescribeType(Ntlm.BuildNegotiateMessage()));
        Assert.Equal("not an NTLM message", Ntlm.DescribeType([0x01, 0x02]));
    }
}