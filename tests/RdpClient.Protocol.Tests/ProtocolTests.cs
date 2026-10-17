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

    /// <summary>
    /// A Confirm that names a different channel is a failed join, not a success.
    /// </summary>
    /// <remarks>
    /// The result octet alone said "success", and the old code reported whatever
    /// channel it found afterwards. That is the same shape of defect as the one
    /// this connection sequence was rewritten for: reporting a success the
    /// server did not grant.
    /// </remarks>
    [Fact]
    public void ChannelJoinConfirm_RejectsAChannelTheServerDidNotJoin()
    {
        // 03 00 00 0f | 02 f0 80 | 3e | 00 | 0001 | 03eb | 03eb
        byte[] confirm = Convert.FromHexString("0300000f02f8803e00000103eb03eb");

        Assert.True(Mcs.ParseChannelJoinConfirm(confirm, expectedChannel: 1003).Success);

        var wrong = Mcs.ParseChannelJoinConfirm(confirm, expectedChannel: 1001);
        Assert.False(wrong.Success);
        Assert.Equal((ushort)1003, wrong.ChannelId);
        Assert.Contains("1001 was requested", wrong.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// The optional channel id is marked by opcode bit 0x02, not assumed.
    /// </summary>
    /// <remarks>
    /// The bit means something different in each Confirm: xrdp sets it for the
    /// initiator in the Attach User Confirm and for the channel id in the Channel
    /// Join Confirm. Reading the channel id without checking the bit produced a
    /// value out of whatever followed.
    /// </remarks>
    [Fact]
    public void ChannelJoinConfirm_FailsWhenTheChannelIdIsAbsent()
    {
        // Same PDU with the channel id bit cleared: 3c rather than 3e.
        byte[] confirm = Convert.FromHexString("0300000d02f8803c00000103eb");

        var result = Mcs.ParseChannelJoinConfirm(confirm, expectedChannel: 1003);

        Assert.False(result.Success);
        Assert.Null(result.ChannelId);
        Assert.Contains("no channel id", result.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// Static channel ids are positional, from one above the global channel.
    /// </summary>
    /// <remarks>
    /// xrdp expects <c>channel_list-&gt;count + 2</c> joins and assigns the Nth
    /// static channel <c>MCS_GLOBAL_CHANNEL + (index + 1)</c>; FreeRDP sets
    /// <c>baseChannelId = MCS_GLOBAL_CHANNEL_ID + 1</c>. Both derive from the
    /// global channel rather than hardcoding 1004, and both are 1004 + N.
    /// </remarks>
    [Theory]
    [InlineData(0, 1004)]
    [InlineData(1, 1005)]
    [InlineData(7, 1011)]
    public void McsStaticChannel_IsOneAboveTheGlobalChannel(int index, int expected)
    {
        Assert.Equal(expected, Rdp.McsStaticChannel(index));
        Assert.Equal(1003, Rdp.McsGlobalChannel);
        Assert.Equal(1001, Rdp.McsUserChannel);
        Assert.Throws<ArgumentOutOfRangeException>(() => Rdp.McsStaticChannel(-1));
    }

    /// <summary>
    /// The join sequence a server counts: one per static channel, then the user
    /// channel, then the global channel.
    /// </summary>
    [Fact]
    public void ChannelJoinSequence_CoversStaticThenUserThenGlobal()
    {
        int staticChannels = ClientPdu.DefaultChannels().Count;

        var targets = new List<ushort>();
        for (int i = 0; i < staticChannels; i++)
        {
            targets.Add(Rdp.McsStaticChannel(i));
        }

        targets.Add(Rdp.McsUserChannel);
        targets.Add(Rdp.McsGlobalChannel);

        // xrdp: expected_join_count = channel_list->count + 2
        Assert.Equal(staticChannels + 2, targets.Count);
        Assert.Equal((ushort)1004, targets[0]);
        Assert.Equal((ushort)1001, targets[^2]);
        Assert.Equal((ushort)1003, targets[^1]);
    }

    [Fact]
    public void BuildNet_RejectsMoreThan31StaticChannels()
    {
        var tooMany = Enumerable.Range(0, 32)
            .Select(i => new ClientPdu.VirtualChannelOption($"ch{i:00}"))
            .ToArray();

        Assert.Throws<ArgumentException>(() => ClientPdu.BuildNet(tooMany));

        // 31 is the documented maximum, so it must be accepted: the 4-byte
        // header, the 4-byte channelCount, then 12 octets per CHANNEL_DEF.
        Assert.Equal(8 + 31 * 12, ClientPdu.BuildNet(tooMany.Take(31).ToArray()).Length);
    }

    /// <summary>
    /// The skip-channel-join flag lives in CORE's earlyCapabilityFlags, and it
    /// is the thing that tells the server the client owes it no joins.
    /// </summary>
    [Fact]
    public void Core_CarriesTheSkipChannelJoinFlagInEarlyCapabilityFlags()
    {
        Assert.Equal(0x0800, Rdp.EarlyCapSupportSkipChannelJoin);

        byte[] core = ClientPdu.BuildCore(new ClientPdu.CoreOptions
        {
            EarlyCapabilityFlags = Rdp.EarlyCapSupportSkipChannelJoin,
        });

        // The block is the 234 octets MS-RDPBCGR 2.2.1.3.2 lays out, header
        // included, and earlyCapabilityFlags sits between supportedColorDepths
        // and the 64-octet clientDigProductId.
        Assert.Equal(234, core.Length);
        Assert.Equal(234, core[2] | (core[3] << 8));
        Assert.Equal(Rdp.EarlyCapSupportSkipChannelJoin, core[144] | (core[145] << 8));
    }

    /// <summary>
    /// The pduType field keeps the PDU type in its four least significant bits,
    /// with PDUVersion above them: a Demand Active encodes 0x0011 on the wire.
    /// </summary>
    /// <remarks>
    /// MS-RDPBCGR 2.2.8.1.1.1.1 packs it as <c>(type | (TS_PROTOCOL_VERSION
    /// &lt;&lt; 4))</c> with TS_PROTOCOL_VERSION 0x1; xrdp reads it back with
    /// <c>pdu_code &amp; 0xf</c> and FreeRDP writes <c>type | 0x10</c>. The
    /// earlier type-in-the-top-bits packing mistook every real Demand Active
    /// for "type 0" and put bytes no peer speaks on the wire.
    /// </remarks>
    [Theory]
    [InlineData(1, 0x11)]   // Demand Active
    [InlineData(3, 0x13)]   // Confirm Active
    public void ShareControlHeader_EncodesTheTypeInItsLeastSignificantBits(int pduType, int expectedPduType)
    {
        byte[] header = Capability.BuildShareControlHeader(pduType, totalLength: 0x2e);

        Assert.Equal(6, header.Length);
        Assert.Equal(0x2e, header[0] | (header[1] << 8));               // totalLength
        Assert.Equal(expectedPduType, header[2] | (header[3] << 8));    // pduType
        Assert.Equal(Rdp.McsGlobalChannel, header[4] | (header[5] << 8)); // pduSource

        var parsed = Capability.ParseShareControlHeader(header);
        Assert.Equal(pduType, parsed.PduType);
        Assert.Equal(1, parsed.PduVersion);
        Assert.Equal(6, parsed.PayloadOffset);
    }

    /// <summary>
    /// The General Capability Set is a fixed 24 octets, and 18 of them are
    /// fields the specification requires to be zero for this client.
    /// </summary>
    [Fact]
    public void GeneralCapabilitySet_MatchesTheSpecificationLayout()
    {
        byte[] set = Capability.BuildGeneralCapabilitySet();

        Assert.Equal(24, set.Length);
        Assert.Equal("010018000100030000020000000000000000000000000000", Convert.ToHexString(set).ToLowerInvariant());
    }

    /// <summary>
    /// A Demand Active PDU walks to its capability sets and its session id.
    /// </summary>
    [Fact]
    public void ParseDemandActive_ReadsTheCapabilitySetsAndTheSessionId()
    {
        // Share Control Header(6) shareID(4) lengthSourceDescriptor(2)
        // lengthCombinedCapabilities(2) numberCapabilities(2) pad2Octets(2)
        // General set(24) sessionId(4) = 46 octets.
        byte[] pdu = Convert.FromHexString(
            "2e00" +     // totalLength 46
            "1100" +     // pduType: Demand Active (1) | PDUVersion 0x1 << 4
            "eb03" +     // pduSource 1003
            "34120000" + // shareID 0x1234
            "0000" +     // lengthSourceDescriptor 0
            "1c00" +     // lengthCombinedCapabilities 28 = 4 + 24
            "0100" +     // numberCapabilities 1
            "0000" +     // pad2Octets
            "010018000100030000020000000000000000000000000000" +
            "01000000"); // sessionId 1

        var demand = Capability.ParseDemandActive(pdu);

        Assert.Equal(0x1234, demand.ShareId);
        Assert.Equal(1u, demand.SessionId);
        var only = Assert.Single(demand.Capabilities);
        Assert.Equal((ushort)1, only.Type);
        Assert.Equal(24, only.Length);
        Assert.Contains("General", demand.Summary, StringComparison.Ordinal);
    }

    /// <summary>
    /// A capability count that disagrees with the sets actually present is a
    /// malformed PDU, not something to carry on from.
    /// </summary>
    [Fact]
    public void ParseDemandActive_RejectsACountThatDoesNotMatchTheSets()
    {
        byte[] pdu = Convert.FromHexString(
            "2e00" + "1100" + "0000" + "34120000" + "0000" + "1c00" +
            "0200" +     // claims two capability sets
            "0000" +
            "010018000100030000020000000000000000000000000000" +
            "01000000");

        var ex = Assert.Throws<InvalidDataException>(() => Capability.ParseDemandActive(pdu));
        Assert.Contains("declares 2 capability sets but 1", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The Confirm Active PDU is a Confirm Active header, the server channel as
    /// originator, the T.128 "RDP" source descriptor, and the capability sets.
    /// </summary>
    [Fact]
    public void BuildConfirmActivePdu_CarriesTheServerChannelAsItsOriginator()
    {
        byte[] pdu = Capability.BuildConfirmActivePdu(shareId: 0x1234, [Capability.BuildGeneralCapabilitySet()]);

        Assert.Equal(Capability.ConfirmActiveSetsOffset + 24, pdu.Length);

        var header = Capability.ParseShareControlHeader(pdu);
        Assert.Equal(Capability.PduTypeConfirmActive, header.PduType);
        Assert.Equal(pdu.Length, header.TotalLength);

        Assert.Equal(0x1234, pdu[6] | (pdu[7] << 8) | (pdu[8] << 16) | (pdu[9] << 24)); // shareID
        Assert.Equal(1002, pdu[10] | (pdu[11] << 8));                                   // originatorID
        Assert.Equal(Capability.SourceDescriptorLength, pdu[12] | (pdu[13] << 8));      // lengthSourceDescriptor
        Assert.Equal(28, pdu[14] | (pdu[15] << 8));                                    // lengthCombinedCapabilities
        Assert.Equal("52445000", Convert.ToHexString(pdu, 16, 4).ToLowerInvariant());   // sourceDescriptor "RDP\0"
        Assert.Equal(1, pdu[20] | (pdu[21] << 8));                                     // numberCapabilities
    }

    /// <summary>
    /// A Send Data Indication is how every server PDU after the joins arrives.
    /// </summary>
    /// <remarks>
    /// The userData length behind the 0x70 octet is an [ITU-T X.691] length
    /// determinant, one plain octet here because 8 octets sit below 128. The
    /// earlier synthetic frame wrote a little-endian u16 "including itself";
    /// nothing on the wire speaks that encoding, and it was corrected together
    /// with the sender after xrdp read the stray octet as its security header.
    /// </remarks>
    [Fact]
    public void SendDataIndication_ReadsTheChannelAndTheFragmentation()
    {
        // 03 00 00 16 | 02 f0 80 | 68 | 0001 | 03eb | 70 | 08 | 8 octets
        byte[] indication = Convert.FromHexString("0300001602f08068000103eb70080011223344556677");

        var parsed = Mcs.ParseSendDataIndication(indication);

        Assert.Equal((ushort)1003, parsed.ChannelId);
        Assert.Equal(Mcs.SegmentationLast, parsed.Segmentation);
        Assert.Equal(8, parsed.Payload.Length);
        Assert.Equal("0011223344556677", Convert.ToHexString(parsed.Payload).ToLowerInvariant());
    }

    /// <summary>
    /// Fragments above 127 octets arrive in the two-octet 0x8x length form.
    /// </summary>
    [Fact]
    public void SendDataIndication_ReadsTheTwoOctetLengthForm()
    {
        // Length 300 = 0x012C -> determinant 0x8128 + 0x2C, then 300 octets. The
        // TPKT length covers the whole frame: 4 + 3 + 1 + 2 + 2 + 1 + 2 + 300
        // = 315 = 0x13B.
        var payload = new byte[300];
        payload[0] = 0xAB;
        var frame = new List<byte>
        {
            0x03, 0x00, 0x01, 0x3B, 0x02, 0xF0, 0x80, 0x68, 0x00, 0x01, 0x03, 0xEB, 0x70, 0x81, 0x2C,
        };
        frame.AddRange(payload);

        var parsed = Mcs.ParseSendDataIndication(frame.ToArray());

        Assert.Equal((ushort)1003, parsed.ChannelId);
        Assert.Equal(300, parsed.Payload.Length);
        Assert.Equal(0xAB, parsed.Payload[0]);
    }

    /// <summary>
    /// A Send Data Indication that claims more data than it carries is malformed.
    /// </summary>
    [Fact]
    public void SendDataIndication_RejectsAFragmentLengthBeyondThePDU()
    {
        // Declares a 16-octet fragment in the single-octet form, but carries 2.
        // The TPKT length is consistent on purpose, so the failure comes from
        // the fragment length rather than from the envelope.
        byte[] indication = Convert.FromHexString("0300001002f08068000103eb70100011");

        var ex = Assert.Throws<InvalidDataException>(() => Mcs.ParseSendDataIndication(indication));
        Assert.Contains("declares a 16-octet fragment but only 2", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SendDataRequest_ChunksLargePayloadsInsideTheMcsEnvelope()
    {
        byte[] payload = new byte[5000];
        var frames = Mcs.BuildSendDataRequest(1004, Rdp.McsGlobalChannel, payload);

        Assert.Equal(4, frames.Count);   // 1598 + 1598 + 1598 + 206
        int offset = 0;
        foreach (byte[] frame in frames)
        {
            // Every frame must be a complete TPKT datagram, not a bare MCS PDU.
            Mcs.DomainPdu pdu = Mcs.ParseDomainPdu(frame);
            Assert.Equal(Rdp.McsChoiceSendDataRequest, pdu.Choice);

            int chunkLength = Math.Min(1598, payload.Length - offset);
            offset += chunkLength;

            var r = new ByteReader(pdu.Payload);
            Assert.Equal(3u, r.U16BigEndian());                 // initiator - 1001
            Assert.Equal((uint)Rdp.McsGlobalChannel, r.U16BigEndian());
            r.U8();                                              // dataPriority/segmentation

            // The length is an [ITU-T X.691] determinant, matching the octets
            // that actually follow in this frame.
            byte lengthByte = r.U8();
            int declared = (lengthByte & 0xC0) == 0x80
                ? (((lengthByte & 0x3F) << 8) | r.U8())
                : lengthByte;
            Assert.Equal(chunkLength, declared);
        }
    }

    /// <summary>
    /// The length determinant switches between its one- and two-octet forms at
    /// the 128-octet boundary.
    /// </summary>
    /// <remarks>
    /// [ITU-T X.691] 11.9.3.6-11.9.3.7, as xrdp's sender applies it in both
    /// directions. The 128-byte edge is a real one: a payload of 127 or fewer
    /// octets must stay one octet long, or a strict reader counts one too many.
    /// </remarks>
    [Fact]
    public void SendDataRequest_KeepsTheLengthDeterminantShortBelow128Octets()
    {
        byte[] small = Mcs.BuildSendDataRequest(1004, Rdp.McsGlobalChannel, new byte[127])[0];
        byte[] edge = Mcs.BuildSendDataRequest(1004, Rdp.McsGlobalChannel, new byte[128])[0];

        var smallPdu = Mcs.ParseDomainPdu(small);
        var r = new ByteReader(smallPdu.Payload);
        r.Skip(5);                                        // initiator, channel, priority
        Assert.Equal(127, r.U8());                        // single plain octet

        var edgePdu = Mcs.ParseDomainPdu(edge);
        var e = new ByteReader(edgePdu.Payload);
        e.Skip(5);
        byte first = e.U8();
        Assert.Equal(0x80, first & 0xC0);                 // two octets, 0x8x marker
        Assert.Equal(128, ((first & 0x3F) << 8) | e.U8());
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

/// <summary>
/// The Client Info PDU (MS-RDPBCGR 2.2.1.11) and the licensing skip it needs.
/// </summary>
/// <remarks>
/// The layout is pinned by field, not by value: the PDU carries credentials, so
/// the test inputs are synthetic and the assertions point at fixed offsets with
/// their spec numbers. This is the PDU whose absence stalled the handshake
/// after the channel joins; if its layout shifts, xrdp answers with
/// "received wrong flags" and the Demand Active never comes.
/// </remarks>
public class ClientInfoTests
{
    /// <summary>
    /// Overall length with an empty domain, "jane" as the user, "pw" as the
    /// password and empty shell and working dir: header + info packet strings
    /// + the extended info block, per the offsets the members assert.
    /// </summary>
    public const int ExpectedTotalLength = 270;

    private static readonly byte[] JaneUtf16 =
        System.Text.Encoding.Unicode.GetBytes("jane");

    [Fact]
    public void ClientInfoPdu_FieldOffsetsFollowTheSpec()
    {
        byte[] pdu = ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions
        {
            UserName = "jane",
            Password = "pw",
        });

        Assert.Equal(ExpectedTotalLength, pdu.Length);

        // TS_SECURITY_HEADER (2.2.8.1.1.2.1): SEC_INFO_PKT = 0x0040, not the
        // 0x0080 that reader intuition picks, because that is SEC_LICENSE_PKT.
        Assert.Equal((byte)0x40, pdu[0]);
        Assert.Equal((byte)0x00, pdu[1]);
        Assert.Equal(0, BitConverter.ToInt16(pdu, 2));   // flagsHi

        // CodePage under INFO_UNICODE is a language id, here en-US (0x0409).
        Assert.Equal(0x0409u, BitConverter.ToUInt32(pdu, 4));

        // flags: the base set xrdp's INFO_LOGON_NORMAL check demands bits of,
        // plus InfoAutoLogon because a password was given.
        uint expectedFlags = ClientInfo.DefaultFlags | ClientInfo.InfoAutoLogon;
        Assert.Equal(expectedFlags, BitConverter.ToUInt32(pdu, 8));

        // The five declared counts exclude the mandatory null terminator.
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 12)); // cbDomain, empty
        Assert.Equal(JaneUtf16.Length, BitConverter.ToUInt16(pdu, 14));
        Assert.Equal(4, BitConverter.ToUInt16(pdu, 16)); // "pw" -> 2 chars * 2
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 18)); // cbAlternateShell
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 20)); // cbWorkingDir

        // 22..24 domain terminator, then the user name at 24 and its terminator.
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 22));
        Assert.Equal(JaneUtf16, pdu[24..32]);
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 32));
        Assert.Equal(System.Text.Encoding.Unicode.GetBytes("pw"), pdu[34..38]);
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 38));
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 40)); // shell terminator
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 42)); // working dir terminator

        // TS_EXTENDED_INFO_PACKET (2.2.1.11.1.1.1). cbClientAddress and
        // cbClientDir INCLUDE the terminator, unlike the five counts above.
        Assert.Equal((short)ClientInfo.AddressFamilyInet, BitConverter.ToInt16(pdu, 44));
        Assert.Equal(2 * (ClientInfo.ClientAddress.Length + 1), BitConverter.ToUInt16(pdu, 46));
        Assert.Equal(System.Text.Encoding.Unicode.GetBytes(ClientInfo.ClientAddress), pdu[48..66]);
        Assert.Equal(2 * (ClientInfo.ClientDir.Length + 1), BitConverter.ToUInt16(pdu, 68));
        Assert.Equal(System.Text.Encoding.Unicode.GetBytes(ClientInfo.ClientDir), pdu[70..88]);

        // UTC: timezone (172), clientSessionId, performanceFlags - all zero.
        Assert.All(pdu[90..270], b => Assert.Equal(0, b));
    }

    [Fact]
    public void ClientInfoPdu_AutoLogonFlagFollowsThePassword()
    {
        byte[] withPassword = ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions
        {
            UserName = "jane",
            Password = "pw",
        });
        byte[] without = ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions
        {
            UserName = "jane",
        });

        Assert.Equal(
            ClientInfo.DefaultFlags | ClientInfo.InfoAutoLogon,
            BitConverter.ToUInt32(withPassword, 8));
        Assert.Equal(ClientInfo.DefaultFlags, BitConverter.ToUInt32(without, 8));

        // A packet whose flags request auto logon and whose password field is
        // empty is refusable server-side: xrdp logs "Client enable auto logon
        // with credentials, but the client did not...", so the flag owns the
        // bit only when the password is real.
        Assert.Equal(0, BitConverter.ToUInt16(without, 16));   // cbPassword
        Assert.Equal(0, BitConverter.ToUInt16(without, 34));   // password terminator
    }

    [Fact]
    public void ClientInfoPdu_RejectsAStringLongerThanTheSpecAllows()
    {
        // 2.2.1.11.1.1: maximum 512 bytes including the terminator, so 510
        // octets of text is the ceiling - 255 characters fit, 256 do not.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions
            {
                UserName = new string('a', 256),
            }));
        byte[] pdu = ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions
        {
            UserName = new string('a', 255),
        });
        Assert.Equal(510, BitConverter.ToUInt16(pdu, 14));
    }

    [Fact]
    public void ClientInfoPdu_KeysOffTheDefaultFlagSet()
    {
        // The mask xrdp requires before it will parse the packet at all:
        // (flags & 0x33) == 0x33, its own INFO_LOGON_NORMAL constant.
        Assert.Equal(0x33u, ClientInfo.DefaultFlags & 0x33);
    }

    [Fact]
    public void LicensePdu_IsRecognizedAndSkippedByItsOwnSize()
    {
        // The structure xrdp writes in xrdp_sec_send_lic_response: a basic
        // security header carrying SEC_LICENSE_PKT | SEC_LICENSE_ENCRYPT_CS
        // flagsHi zero, then the 16-octet valid-client message.
        var w = new ByteWriter(4 + 16);
        w.U16(ClientInfo.SecLicensePkt | 0x0200);
        w.U16(0);
        w.U8(0xFF);        // LICENSE_PREAMBLE bMsgType (ERROR_ALERT)
        w.U8(0x03);        // bVersion
        w.U16(16);         // wMessageSize, counting the preamble
        w.U32(0);          // dwErrorCode
        w.U32(0);          // dwStateTransition
        w.U16(0);          // wBlobType
        w.U16(0);          // wBlobLen
        var payload = w.ToArray();

        Assert.True(ClientInfo.IsLicensePdu(payload, out int totalLength));
        Assert.Equal(4 + 16, totalLength);
    }

    [Fact]
    public void LicensePdu_DoesNotMistakeAShareControlHeaderForItself()
    {
        // A Share Control Header whose totalLength is 0x0280 has the same first
        // two bytes as the licensing flag word. Its third field is pduType2,
        // which is never zero, while a licensing security header's flagsHi is.
        var lookalike = new byte[] { 0x80, 0x02, 0x11, 0x00 };
        Assert.False(ClientInfo.IsLicensePdu(lookalike, out _));

        // And a real Client Info PDU is not a licensing PDU either.
        byte[] info = ClientInfo.BuildClientInfoPdu(new ClientPdu.UserOptions());
        Assert.False(ClientInfo.IsLicensePdu(info, out _));
    }
}