using RdpClient.Protocol;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Wire-format tests pinned to bytes captured from a real RDP client.
/// </summary>
/// <remarks>
/// The expected values come from recording <c>mstsc.exe</c> through a logging
/// TCP proxy pointed at a Windows Server 2025 RDP host. Three framing bugs
/// (TPKT length endianness, X.224 field order, and a 16-bit TSFC header written
/// as one byte) each produced a silently malformed PDU that a server answered
/// with an immediate reset. These tests exist so that cannot regress.
/// </remarks>
public class NegotiationTests
{
    /// <summary>
    /// Bytes captured from mstsc.exe for a minimal negotiation request:
    /// 03 00 00 13 | 0e e0 00 00 00 00 00 | 01 00 08 00 | 0b 00 00 00
    /// </summary>
    private const string CapturedMstscRequest = "030000130ee00000000000010008000b000000";

    private static byte[] FromHex(string hex) => Convert.FromHexString(hex);

    [Fact]
    public void Tpkt_LengthIsBigEndian_AndCountsTheHeader()
    {
        byte[] payload = [0xde, 0xad, 0xbe, 0xef];
        byte[] framed = Negotiation.Tpkt(payload);

        Assert.Equal(8, framed.Length);
        Assert.Equal(0x03, framed[0]);                       // TPKT version
        Assert.Equal(0x00, framed[1]);                       // reserved
        Assert.Equal(0x00, framed[2]);                       // length, high byte
        Assert.Equal(0x08, framed[3]);                       // length, low byte
        Assert.Equal(payload, framed[4..]);
    }

    [Fact]
    public void Tpkt_LengthIsTheOnlyBigEndianField()
    {
        // A byte-identical body must not change when only the TPKT length is
        // re-encoded; if RDP_NEG_REQ lengths were big-endian this would break.
        byte[] request = Negotiation.BuildConnectionRequest(Rdp.ProtocolSsl | Rdp.ProtocolHybrid);
        var reader = new ByteReader(request);
        reader.Skip(13);                    // TPKT(4) + X.224 fixed(7) + type/flags(2)
        Assert.Equal(0x08, reader.U16());   // RDP_NEG_REQ length: little-endian
    }

    [Fact]
    public void ConnectionRequest_MatchesBytesCapturedFromMstsc()
    {
        byte[] actual = Negotiation.BuildConnectionRequest(
            Rdp.ProtocolSsl | Rdp.ProtocolHybrid | Rdp.ProtocolHybridEx);
        Assert.Equal(FromHex(CapturedMstscRequest), actual);
    }

    [Fact]
    public void ConnectionRequest_X224LengthIndicatorPrecedesTheTpdUCode()
    {
        byte[] request = Negotiation.BuildConnectionRequest(Rdp.ProtocolSsl);
        Assert.Equal(19, request.Length);

        // TPKT(4) then length indicator(1) then CR code(1).
        Assert.Equal(0x0e, request[4]);
        Assert.Equal(0xe0, request[5]);

        // Class 0 with zeroed references.
        Assert.Equal(0x00, request[6]);
        Assert.Equal(0x00, request[7]);
        Assert.Equal(0x00, request[8]);
        Assert.Equal(0x00, request[9]);
        Assert.Equal(0x00, request[10]);

        // RDP_NEG_REQ follows: type, flags, little-endian length 8.
        Assert.Equal(0x01, request[11]);
        Assert.Equal(0x00, request[12]);
        Assert.Equal(0x08, request[13]);
        Assert.Equal(0x00, request[14]);
    }

    [Fact]
    public void ConnectionRequest_WithCorrelation_RaisesThePresentFlag()
    {
        byte[] correlation = new byte[16];
        Random.Shared.NextBytes(correlation);

        byte[] request = Negotiation.BuildConnectionRequest(Rdp.ProtocolSsl, correlation);

        // MS-RDPBCGR 2.2.1.1.1: CORRELATION_INFO_PRESENT must accompany the block.
        Assert.Equal(0x08, request[12]);

        // The vector starts after TPKT(4) + X.224 fixed header(7) + RDP_NEG_REQ(8)
        // + the correlation block's own type/flags/length(4).
        Assert.Equal(correlation, request[23..39]);

        // The block must be as long as the length it declares. xrdp walks 35
        // octets after the type and aborts with "expected 35, remaining 23"
        // when only the 24 named fields are present. Windows tolerates the
        // short form, but mstsc.exe never sends the block at all, so nothing
        // on the Windows side contradicts the stricter reader.
        Assert.Equal(36, Negotiation.CorrelationInfoLength);
        Assert.Equal(Negotiation.CorrelationInfoLength, BitConverter.ToUInt16(request, 21));
        Assert.Equal(19 + Negotiation.CorrelationInfoLength, request.Length);

        // The 12 octets of padding that bring the block up to its declared
        // length are zero.
        Assert.All(request[43..], b => Assert.Equal(0, b));
    }

    [Fact]
    public void ParseConnectionConfirm_ReadsAServerNegotiatingHybridEx()
    {
        // Captured from the Windows Server 2025 host:
        // 03 00 00 13 | 0e d0 00 00 12 34 00 | 02 2f 08 00 | 08 00 00 00
        byte[] captured = FromHex("030000130ed0000012340002" + "2f080008000000");

        var confirm = Negotiation.ParseConnectionConfirm(captured);

        Assert.False(confirm.Failed);
        Assert.Equal(Rdp.ProtocolHybridEx, confirm.SelectedProtocol);
        Assert.Equal("HYBRID_EX", confirm.SelectedProtocol is { } mask
            ? Negotiation.DescribeSelectedProtocol(mask)
            : string.Empty);
    }

    [Fact]
    public void ParseConnectionConfirm_RejectsATruncatedDatagram()
    {
        // MS-RDPBCGR 3.3.5.3.1: the server drops connections whose TPKT length
        // disagrees with the payload, so the client should refuse them too.
        byte[] inconsistent = FromHex("0300ffff" + "0ee00000000000010008" + "000b000000");
        Assert.Throws<InvalidDataException>(() => Negotiation.ParseConnectionConfirm(inconsistent));
    }

    [Fact]
    public void DisconnectRequest_PutsLengthIndicatorFirst()
    {
        byte[] request = Negotiation.BuildDisconnectRequest();
        Assert.Equal(0x06, request[4]);   // length indicator
        Assert.Equal(0x80, request[5]);   // DR TPDU code
    }
}

public class ClientPduTests
{
    /// <summary>
    /// The GCC user data header is four octets: type then length.
    /// </summary>
    /// <remarks>
    /// There is no flags field. Treating the header as type/flags/length shifts
    /// every payload field by two octets and misreads the type of whatever
    /// follows, which is how a whole block of settings goes missing without a
    /// single diagnostic.
    /// </remarks>
    [Fact]
    public void EveryBlockStartsWithAFourOctetUserDataHeader()
    {
        foreach ((string name, byte[] block, int type) in new (string, byte[], int)[]
                 {
                     ("core", ClientPdu.BuildCore(), Rdp.TsUdCsCore),
                     ("security", ClientPdu.BuildSecurity(), Rdp.TsUdCsSecurity),
                     ("net", ClientPdu.BuildNet(ClientPdu.DefaultChannels()), Rdp.TsUdCsNet),
                     ("cluster", ClientPdu.BuildCluster(), Rdp.TsUdCsCluster),
                 })
        {
            Assert.Equal(type, BitConverter.ToUInt16(block, 0));
            Assert.Equal(block.Length, BitConverter.ToUInt16(block, 2));
            Assert.True(block.Length >= 4, $"{name} is too short to hold a header");
        }
    }

    [Fact]
    public void CoreData_IsTheTwoHundredAndThirtyFourOctetBlockTheSpecDescribes()
    {
        // 4 header + 4 version + 2 width + 2 height + 2 depth + 2 sas + 4 layout
        // + 4 build + 32 name + 12 keyboard + 64 ime + 2 postBeta2 + 2 productId
        // + 4 serial + 2 highDepth + 2 supported + 2 earlyCaps + 64 digProductId
        // + 1 connectionType + 1 pad + 4 selectedProtocol + 4 physW + 4 physH
        // + 2 orientation + 4 scale + 4 deviceScale.
        byte[] core = ClientPdu.BuildCore();

        Assert.Equal(234, core.Length);
        Assert.Equal(234, BitConverter.ToUInt16(core, 2));
    }

    [Fact]
    public void CoreData_FixedWidthNameFieldsStayTheirDeclaredSize()
    {
        byte[] core = ClientPdu.BuildCore(new ClientPdu.CoreOptions
        {
            ClientName = "a-name-far-longer-than-eight-characters",
            ImeFileName = "also-far-too-long-for-thirty-two-characters-abcdef",
        });

        // The truncation must not change the total structure length.
        Assert.Equal(234, core.Length);
    }

    [Fact]
    public void SecurityData_IsAFixedTwelveOctetBlock()
    {
        // 4 header + 4 encryptionMethods + 4 encryptionLevel.
        byte[] security = ClientPdu.BuildSecurity();

        Assert.Equal(12, security.Length);
        Assert.Equal(12, BitConverter.ToUInt16(security, 2));
    }

    [Fact]
    public void NetData_LengthIsEightPlusTwelvePerChannel()
    {
        // CHANNEL_DEF is a fixed 12 octets: an 8-octet name and a 4-octet options
        // mask. The header is 4 and channelCount is 4, so the total is 12*N + 8.
        IReadOnlyList<ClientPdu.VirtualChannelOption> channels = ClientPdu.DefaultChannels();

        byte[] net = ClientPdu.BuildNet(channels);

        Assert.Equal(12 * channels.Count + 8, net.Length);
        Assert.Equal(net.Length, BitConverter.ToUInt16(net, 2));
    }

    [Fact]
    public void NetData_RejectsChannelNamesLongerThanTheEightByteField()
    {
        // CHANNEL_DEF::name is a fixed 8-octet field. Silently truncating would
        // announce one channel to the client log and a different one to the
        // server.
        Assert.Throws<ArgumentException>(() => ClientPdu.BuildNet([new("toolongname")]));
    }

    [Fact]
    public void NetData_AdvertisesEveryDefaultChannel()
    {
        byte[] net = ClientPdu.BuildNet(ClientPdu.DefaultChannels());
        var reader = new ByteReader(net);
        reader.Skip(4);                       // type(2) + length(2)
        Assert.Equal((uint)ClientPdu.DefaultChannels().Count, reader.U32());
    }

    [Fact]
    public void UserData_LengthsAreByteCountsNotCharacterCounts()
    {
        byte[] user = ClientPdu.BuildUser(new ClientPdu.UserOptions
        {
            UserName = "alice",
            Domain = "CORP",
        });

        var reader = new ByteReader(user);
        reader.Skip(4);        // type(2) + length(2)
        reader.U32();          // code page
        reader.U32();          // flags
        Assert.Equal(8, reader.U16());    // CORP -> 4 chars * 2 bytes
        Assert.Equal(10, reader.U16());   // alice -> 5 chars * 2 bytes
    }

    /// <summary>
    /// Every block must declare the size of the whole block.
    /// </summary>
    /// <remarks>
    /// MS-RDPBCGR 2.2.1.3.1: the length is "the size in bytes of the data
    /// block, including this header". A reader walks that length to find the
    /// next block, so declaring a fixed portion while sending more
    /// desynchronises every block after it. xrdp walks it as <c>length</c> and
    /// steps to <c>header + size</c>, and refused the whole GCC user data when
    /// NET declared 8 and sent 114.
    /// </remarks>
    [Theory]
    [InlineData("net")]
    [InlineData("cluster")]
    [InlineData("user")]
    public void DeclaredLength_CoversTheWholeBlock(string which)
    {
        byte[] block = which switch
        {
            "net" => ClientPdu.BuildNet(ClientPdu.DefaultChannels()),
            "cluster" => ClientPdu.BuildCluster(),
            "user" => ClientPdu.BuildUser(new ClientPdu.UserOptions { UserName = "alice" }),
            _ => throw new ArgumentException($"unknown block '{which}'", nameof(which)),
        };

        Assert.Equal(block.Length, BitConverter.ToUInt16(block, 2));
    }
}

public class McsTests
{
    /// <summary>Universal tag: SEQUENCE, as T.125 writes it.</summary>
    private const byte Asn1TagSequence = 0x30;

    /// <summary>Universal tag: INTEGER.</summary>
    private const byte Asn1TagInteger = 0x02;

    /// <summary>
    /// The octets after the [APPLICATION 101] tag and its length.
    /// </summary>
    /// <remarks>
    /// The length is read rather than assumed because it changes form: a body
    /// under 128 octets is written in the short form and a larger one in the
    /// long form, and every offset after it moves when that happens. A test
    /// that hard-codes the offsets passes on one client data block and fails on
    /// the next.
    /// </remarks>
    private static byte[] ConnectInitialBody(byte[] initial)
    {
        Assert.Equal(0x7F, initial[0]);
        Assert.Equal(0x65, initial[1]);

        int cursor = 2;
        int length = initial[cursor++];

        if ((length & 0x80) != 0)
        {
            int count = length & 0x7F;
            length = 0;
            for (int i = 0; i < count; i++)
            {
                length = (length << 8) | initial[cursor++];
            }
        }

        Assert.Equal(initial.Length - cursor, length);

        return initial[cursor..];
    }

    [Fact]
    public void ConnectInitial_OpensWithTheSplitApplicationTag()
    {
        byte[] initial = Mcs.BuildConnectInitial(new Mcs.ConnectInitialOptions
        {
            ClientInfo = ClientPdu.BuildSecurity(),
        });

        // Connect-Initial is [APPLICATION 101]. 101 does not fit the five tag
        // bits of one octet, so it is split: 0x7f then the number, 0x65.
        Assert.Equal(0x7F, initial[0]);
        Assert.Equal(0x65, initial[1]);

        byte[] body = ConnectInitialBody(initial);

        // The two domain selectors and the upward flag, in T.125's order.
        Assert.Equal(0x04, body[0]);         // callingDomainSelector, an OCTET STRING
        Assert.Equal(0x01, body[1]);
        Assert.Equal(0x01, body[2]);
        Assert.Equal(0x04, body[3]);         // calledDomainSelector
        Assert.Equal(0x01, body[4]);
        Assert.Equal(0x01, body[5]);
        Assert.Equal(0x01, body[6]);         // upwardFlag, a BOOLEAN
        Assert.Equal(0x01, body[7]);
        Assert.Equal(0xFF, body[8]);         // TRUE

        // Then the three sets of domain parameters, each a SEQUENCE, then the
        // user data as an OCTET STRING.
        var reader = new ByteReader(body);
        reader.Skip(9);
        Assert.Equal(Asn1TagSequence, reader.U8());
        reader.Skip(reader.U8());
        Assert.Equal(Asn1TagSequence, reader.U8());
        reader.Skip(reader.U8());
        Assert.Equal(Asn1TagSequence, reader.U8());
        reader.Skip(reader.U8());

        Assert.Equal(0x04, reader.U8());                // userData, an OCTET STRING
        int userDataLength = reader.U8();
        Assert.True(userDataLength > 0);

        // What is inside is the GCC Conference Create Request, which opens
        // with the From Key choice.
        Assert.Equal(0x00, reader.PeekRest()[0]);
        Assert.Equal(userDataLength, reader.Remaining);
    }

    [Fact]
    public void DomainParameters_AreEightBigEndianIntegers()
    {
        // BER integers are big-endian and minimal, the opposite of everything
        // else in RDP. A value above 127 is what shows it, so the maximum PDU
        // size is set to one that needs two octets.
        byte[] initial = Mcs.BuildConnectInitial(new Mcs.ConnectInitialOptions
        {
            ClientInfo = ClientPdu.BuildSecurity(),
            TargetParameters = new McsDomainParameters
            {
                MaxChannelIds = 34,
                MaxUserIds = 2,
                MaxTokenIds = 0,
                MaxMcsPduSize = 0xFFFF,
            },
        });

        // maxMcsPduSize is the seventh. 0xFFFF does not fit a signed octet, so
        // it takes three content octets with a leading zero - and the two 0xFF
        // come first because BER is big-endian.
        var values = ReadDomainParameterIntegers(ConnectInitialBody(initial));

        Assert.Equal(8, values.Count);
        Assert.Equal(34u, values[0]);       // maxChannelIds
        Assert.Equal(2u, values[1]);        // maxUserIds
        Assert.Equal(0u, values[2]);        // maxTokenIds
        Assert.Equal(1u, values[3]);        // numPriorities
        Assert.Equal(0u, values[4]);        // minThroughput
        Assert.Equal(1u, values[5]);        // maxHeight
        Assert.Equal(0xFFFFu, values[6]);   // maxMcsPduSize
        Assert.Equal(2u, values[7]);        // protocolVersion
    }

    /// <summary>
    /// The eight integers of the first DomainParameters set, read in order.
    /// </summary>
    private static List<uint> ReadDomainParameterIntegers(byte[] body)
    {
        var reader = new ByteReader(body);
        reader.Skip(9);

        // The tag and the length, then straight into the content: the eight
        // integers are inside the SEQUENCE, so skipping the declared length
        // would step over all of them.
        Assert.Equal(Asn1TagSequence, reader.U8());
        Assert.True(reader.U8() >= 8);

        var values = new List<uint>(8);
        for (int i = 0; i < 8; i++)
        {
            Assert.Equal(Asn1TagInteger, reader.U8());
            int length = reader.U8();

            uint value = 0;
            for (int octet = 0; octet < length; octet++)
            {
                // Accumulated left to right: BER is big-endian, so the first
                // octet is the most significant.
                value = (value << 8) | reader.U8();
            }

            values.Add(value);
        }

        return values;
    }

    [Fact]
    public void ConnectInitial_UsesADomainParameterFloorThatLetsTheUserAttach()
    {
        // The client attaches itself as a user straight after the connect, so a
        // floor of zero user ids would leave the server with nowhere to put it.
        Assert.True(McsDomainParameters.Minimum.MaxUserIds >= 1);
        Assert.True(McsDomainParameters.Target.MaxUserIds >= McsDomainParameters.Minimum.MaxUserIds);
        Assert.True(McsDomainParameters.Maximum.MaxUserIds >= McsDomainParameters.Target.MaxUserIds);
    }

    [Fact]
    public void ConferenceCreateRequest_PacksTheNameAsANumericString()
    {
        byte[] conference = Mcs.BuildConferenceCreateRequest([0xDE, 0xAD]);

        // From Key choice, then the object identifier with its own length octet.
        Assert.Equal(0x00, conference[0]);
        Assert.Equal(0x05, conference[1]);
        Assert.Equal(0x00, conference[2]);
        Assert.Equal(0x14, conference[3]);
        Assert.Equal(0x7C, conference[4]);
        Assert.Equal(0x00, conference[5]);
        Assert.Equal(0x01, conference[6]);

        // connectPDU length: the two client data octets, twelve of fixed
        // framing, and the one-octet client-data length. 15, not 16 - this is
        // the value mstscax.dll writes, and it is one lower than the old
        // constant of 14 because the length field is a single octet here.
        Assert.Equal(0x0F, conference[7]);

        Assert.Equal(0x00, conference[8]);      // ConnectGCCPDU: conferenceCreateRequest
        Assert.Equal(0x08, conference[9]);      // selection: userData present

        // The conference name is a numeric string: digit pairs packed one to
        // an octet, so a single digit becomes 0x10 and not 0x01.
        Assert.Equal(0x00, conference[10]);     // length, one less than the minimum
        Assert.Equal(0x10, conference[11]);
        Assert.Equal(0x00, conference[12]);     // padding
        Assert.Equal(0x01, conference[13]);     // one set of user data
        Assert.Equal(0xC0, conference[14]);     // value present, h221NonStandard
        Assert.Equal(0x00, conference[15]);     // H.221 key length
        Assert.Equal("Duca"u8.ToArray(), conference[16..20]);

        // Then the client data, length-prefixed.
        Assert.Equal(0x02, conference[20]);
        Assert.Equal(0xDE, conference[21]);
        Assert.Equal(0xAD, conference[22]);
        Assert.Equal(23, conference.Length);
    }

    /// <summary>
    /// The connectPDU length counts the client-data length field along with
    /// the client data and twelve octets of framing.
    /// </summary>
    /// <remarks>
    /// This was a constant 14, which is right only once the client data is
    /// large enough for its own length to take two octets. Measured in
    /// mstscax.dll, which builds the value as
    /// <c>(0xe - (uint)(uVar3 &lt; 0x80)) + uVar3</c>: +14 for a total at or above
    /// 0x80 and +13 below it. Both agree everywhere, so the declared value
    /// always describes the octets that follow it.
    /// </remarks>
    [Theory]
    [InlineData(2, 15, 1)]      // one-octet length field
    [InlineData(100, 113, 1)]
    [InlineData(114, 127, 1)]   // last client data that still yields a one-octet total
    [InlineData(115, 128, 2)]   // the total crosses 0x80 although the client data does not
    [InlineData(127, 140, 2)]
    [InlineData(200, 214, 2)]
    [InlineData(4096, 4110, 2)] // a realistic GCC client data size
    public void ConnectPduLength_CountsItsOwnLengthField(
        int clientDataLength, int expectedLength, int expectedLengthOctets)
    {
        byte[] conference = Mcs.BuildConferenceCreateRequest(new byte[clientDataLength]);

        // The From Key choice, the object identifier and its length, then the
        // connectPDU length field itself.
        const int connectPduLengthAt = 7;
        int connectPduLengthOctets = conference[connectPduLengthAt] > 0x7F ? 2 : 1;
        Assert.Equal(expectedLengthOctets, connectPduLengthOctets);

        int actual = conference[connectPduLengthAt] > 0x7F
            ? ((conference[connectPduLengthAt] & 0x7F) << 8) | conference[connectPduLengthAt + 1]
            : conference[connectPduLengthAt];
        Assert.Equal(expectedLength, actual);

        // The declared value must describe what actually follows it, whatever
        // width it ended up taking: everything past the two octets of the
        // field that holds it.
        int afterLengthField = connectPduLengthAt + connectPduLengthOctets;
        Assert.Equal(expectedLength, conference.Length - afterLengthField);

        // The twelve fixed octets that follow are the ConnectGCCPDU choice, the
        // selection, the conference name length, the name, the padding, the set
        // count, the UserData choice, and the H.221 key length and key.
        int clientDataLengthAt = afterLengthField + 12;
        Assert.Equal(
            clientDataLength,
            ReadPerLength(conference, clientDataLengthAt));

        // And the client data must begin where that says it does.
        int clientDataAt = clientDataLengthAt
            + (clientDataLength > 0x7F ? 2 : 1);
        Assert.Equal(clientDataLength, conference.Length - clientDataAt);
    }

    private static int ReadPerLength(byte[] buffer, int at) =>
        buffer[at] > 0x7F
            ? ((buffer[at] & 0x7F) << 8) | buffer[at + 1]
            : buffer[at];

    [Fact]
    public void ConferenceCreateRequest_RejectsANonNumericName()
    {
        // "McsCnxn" is the H.221 node label, not a conference name. Encoding it
        // as a numeric string has to fail rather than send garbage digits.
        Assert.Throws<ArgumentException>(() =>
            Mcs.BuildConferenceCreateRequest([0x00], "McsCnxn"));
    }

    [Fact]
    public void ConferenceCreateRequest_LengthCountsTheClientData()
    {
        // Past 127 octets the PER length becomes two octets with the high bit
        // set, which is a different shape from a BER length.
        byte[] conference = Mcs.BuildConferenceCreateRequest(new byte[200]);

        // Two octets, most significant first, with the high bit marking the
        // long form rather than counting octets the way a BER length does.
        Assert.Equal(0x80, conference[7] & 0x80);
        Assert.Equal(200 + 14, ((conference[7] & 0x7F) << 8) | conference[8]);
        Assert.Equal(200 + 14 + 9, conference.Length);
    }

    /// <summary>
    /// Pinned to the annotated PDUs MS-RDPBCGR publishes: 4.1.5 (Erect Domain
    /// Request), 4.1.6 (Attach User Request) and 2.2.1.3.8 (Channel Join
    /// Request). Each is compared byte for byte, TPKT header included.
    /// </summary>
    /// <remarks>
    /// These three used to be emitted unframed and with the opcode taken as the
    /// PDU code. The opcode is the DomainMCSPDU CHOICE index in the top six bits
    /// with the option bits in the low two, so a raw code lands on a different
    /// PDU entirely and no server accepts it.
    /// </remarks>
    [Theory]
    // 03 00 00 0c | 02 f0 80 | 04 01 00 01 00
    [InlineData("erect", "0300000c02f0800401000100")]
    // 03 00 00 08 | 02 f0 80 | 28
    [InlineData("attach", "0300000802f08028")]
    public void DomainPdu_MatchesTheAnnotatedExample(string which, string expected)
    {
        byte[] actual = which switch
        {
            "erect" => Mcs.BuildErectDomainRequest(),
            "attach" => Mcs.BuildAttachUserRequest(),
            _ => throw new ArgumentException($"unknown PDU '{which}'", nameof(which)),
        };

        Assert.Equal(expected, Convert.ToHexString(actual).ToLowerInvariant());
    }

    [Fact]
    public void ChannelJoinRequest_CarriesTheAssignedUserIdAndTheGlobalChannel()
    {
        // The initiator is the id from the Attach User Confirm, written as a PER
        // integer relative to 1001, and the global channel is 1003.
        byte[] join = Mcs.BuildChannelJoinRequest(1004, Rdp.McsGlobalChannel);

        Assert.Equal("0300000c02f08038000303eb", Convert.ToHexString(join).ToLowerInvariant());

        Mcs.DomainPdu pdu = Mcs.ParseDomainPdu(join);
        Assert.Equal(Rdp.McsChoiceChannelJoinRequest, pdu.Choice);

        var r = new ByteReader(pdu.Payload);
        Assert.Equal(3u, r.U16BigEndian());          // 1004 - 1001
        Assert.Equal((uint)Rdp.McsGlobalChannel, r.U16BigEndian());
    }

    [Fact]
    public void ChannelJoinRequest_RefusesAUserIdBelowTheMcsBase()
    {
        // Below 1001 the PER-relative value would underflow rather than encode.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Mcs.BuildChannelJoinRequest(1000, Rdp.McsGlobalChannel));
    }

    [Fact]
    public void AttachUserConfirm_YieldsTheUserIdTheJoinMustUse()
    {
        // 03 00 00 0b | 02 f0 80 | 2e 00 00 07
        // 0x2e = (11 << 2) | 2: the choice is 11 and the option bit says the
        // OPTIONAL initiator is present. 7 + 1001 = 1008.
        byte[] confirm = Convert.FromHexString("0300000b02f0802e000007");

        var result = Mcs.ParseAttachUserConfirm(confirm);

        Assert.True(result.Success);
        Assert.Equal((ushort)1008, result.UserId);
    }

    [Fact]
    public void AttachUserConfirm_ReportsARefusalRatherThanInventingAnId()
    {
        // result 5 is rt-no-such-user in T.125.
        byte[] confirm = Convert.FromHexString("0300000b02f8802e050007");

        var result = Mcs.ParseAttachUserConfirm(confirm);

        Assert.False(result.Success);
        Assert.Null(result.UserId);
        Assert.Contains("result 5", result.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void ChannelJoinConfirm_IsDistinguishedFromTheRequest()
    {
        // 03 00 00 0f | 02 f0 80 | 3e 00 00 01 03eb 03eb
        byte[] confirm = Convert.FromHexString("0300000f02f0803e00000103eb03eb");

        var result = Mcs.ParseChannelJoinConfirm(confirm);

        Assert.True(result.Success);
        Assert.Equal((ushort)1003, result.ChannelId);

        // Feeding the request to the confirm parser must be an error, not a
        // silent success: the two differ only in the opcode.
        Assert.False(Mcs.ParseChannelJoinConfirm(Mcs.BuildErectDomainRequest()).Success);
    }

    [Fact]
    public void SendDataRequest_ChunksLargePayloadsInsideTheMcsEnvelope()
    {
        byte[] payload = new byte[5000];
        var frames = Mcs.BuildSendDataRequest(1004, Rdp.McsGlobalChannel, payload);

        Assert.Equal(4, frames.Count);   // 1598 + 1598 + 1598 + 206
        foreach (byte[] frame in frames)
        {
            // Every frame must be a complete TPKT datagram, not a bare MCS PDU.
            Mcs.DomainPdu pdu = Mcs.ParseDomainPdu(frame);
            Assert.Equal(Rdp.McsChoiceSendDataRequest, pdu.Choice);

            var r = new ByteReader(pdu.Payload);
            Assert.Equal(3u, r.U16BigEndian());                 // initiator - 1001
            Assert.Equal((uint)Rdp.McsGlobalChannel, r.U16BigEndian());
            r.U8();                                              // dataPriority/segmentation
            Assert.True(r.U16BigEndian() > 2);
        }
    }

    [Fact]
    public void SendDataRequest_RejectsAnEmptyPayloadAndABadUserId()
    {
        Assert.Throws<ArgumentException>(
            () => Mcs.BuildSendDataRequest(1004, Rdp.McsGlobalChannel, []));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Mcs.BuildSendDataRequest(1000, Rdp.McsGlobalChannel, [0x01]));
    }
}

public class ByteCodecTests
{
    [Fact]
    public void McsVariableByte_WritesTheNarrowestRepresentation()
    {
        foreach ((int value, int width) in new (int, int)[]
                 { (0, 1), (1, 1), (0xFF, 1), (0x100, 2), (0xFFFF, 2), (0x10000, 4), (-1, 4) })
        {
            var w = new ByteWriter();
            w.McsVariableByte(value);

            Assert.Equal(width, w.Length);
            Assert.Equal(value, new ByteReader(w.ToArray()).McsVariableByte(width));
        }
    }

    [Fact]
    public void McsVariableByte_RejectsAnUnknownWidth()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new ByteReader(new byte[] { 0 }).McsVariableByte(3));
    }

    [Fact]
    public void FixedUtf16_PadsToTheDeclaredByteLength()
    {
        var w = new ByteWriter();
        w.FixedUtf16("ab", 32);
        Assert.Equal(32, w.Length);
    }

    [Fact]
    public void Writer_GrowsPastItsInitialCapacity()
    {
        var w = new ByteWriter(4);
        for (int i = 0; i < 100; i++)
        {
            w.U32(i);
        }

        Assert.Equal(400, w.Length);
        var r = new ByteReader(w.ToArray());
        for (int i = 0; i < 100; i++)
        {
            Assert.Equal((uint)i, r.U32());
        }
    }
}