using RdpClient.Protocol;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for the Connection Finalization PDUs (MS-RDPBCGR 2.2.1.14-2.2.1.18).
/// </summary>
/// <remarks>
/// The expected byte strings are derived from the specification's own annotated
/// dumps and field tables rather than from this client's output, for the reason
/// that applies to every encoder in this repository: a PDU that round-trips
/// through its own reader proves nothing when no peer accepts it.
/// </remarks>
public class ConnectionFinalisationTests
{
    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [Fact]
    public void Synchronize_MatchesTheAnnotatedDumpInTheSpecification()
    {
        // MS-RDPBCGR 2.2.1.14.1 and the annotated dump under it:
        //   shareControlHeader 16 00 17 00 <pduSource:2>
        //   shareDataHeader    <shareId:4> 00 00 16 00 1f 00 00 00
        //   messageType        01 00
        //   targetUser         00 00
        byte[] pdu = ConnectionFinalisation.BuildSynchronizePdu(0x000103EA, 1001);

        // totalLength is 22, which is the whole PDU including both headers.
        Assert.Equal("16001700", ToHex(pdu[..4]));
        Assert.Equal(0x1F, pdu[14]);            // pduType2 = PDUTYPE2_SYNCHRONIZE
        Assert.Equal(22, pdu.Length);
    }

    [Fact]
    public void Synchronize_IsTwentyTwoOctetsAndStampsTheUserChannel()
    {
        byte[] pdu = ConnectionFinalisation.BuildSynchronizePdu(0x000103EA, 1001);

        Assert.Equal(6 + 12 + 4, pdu.Length);

        // pduSource is the MCS user channel, not the global channel it travels on.
        Assert.Equal(1001, BitConverter.ToUInt16(pdu, 4));
    }

    [Fact]
    public void Synchronize_WritesThePduTypeWithTheVersionInTheUpperTwelveBits()
    {
        byte[] pdu = ConnectionFinalisation.BuildSynchronizePdu(0x000103EA, 1001);

        // 0x0017 = TS_PROTOCOL_VERSION (0x1) << 4 | PDUTYPE_DATAPDU (7).
        Assert.Equal(0x0017, BitConverter.ToUInt16(pdu, 2));
    }

    [Fact]
    public void Synchronize_WritesShareIdAndZeroesItsOwnUncompressedLength()
    {
        byte[] pdu = ConnectionFinalisation.BuildSynchronizePdu(0x000103EA, 1001);

        Assert.Equal(0x000103EAu, BitConverter.ToUInt32(pdu, 6));

        // uncompressedLength counts the whole PDU, not just what follows it.
        Assert.Equal(22, BitConverter.ToUInt16(pdu, 12));

        // SYNCMSGTYPE_SYNC, and a targetUser of zero.
        Assert.Equal(1, BitConverter.ToUInt16(pdu, 18));
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 20));
    }

    [Fact]
    public void Synchronize_SendsTheBatchUncompressed()
    {
        byte[] pdu = ConnectionFinalisation.BuildSynchronizePdu(1, 1001);

        // compressedType and compressedLength: a zero compressedLength is what
        // says the payload is not compressed, so a peer must not try to inflate it.
        Assert.Equal(0, pdu[15]);
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 16));
    }

    [Fact]
    public void Cooperate_CarriesActionFourAndZeroesBothIds()
    {
        // MS-RDPBCGR 2.2.1.15: action MUST be CTRLACTION_COOPERATE (0x0004),
        // and grantId and controlId MUST both be zero.
        byte[] pdu = ConnectionFinalisation.BuildControlPdu(1, ConnectionFinalisation.ActionCooperate, 1001);

        Assert.Equal(0x14, pdu[14]);                    // pduType2 = PDUTYPE2_CONTROL
        Assert.Equal(0x0004, BitConverter.ToUInt16(pdu, 18));
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 20));        // grantId
        Assert.Equal(0u, BitConverter.ToUInt32(pdu, 22));       // controlId
        Assert.Equal(26, pdu.Length);
    }

    [Fact]
    public void RequestControl_CarriesActionOneAndZeroesBothIds()
    {
        // MS-RDPBCGR 2.2.1.16: action MUST be CTRLACTION_REQUEST_CONTROL (0x0001).
        byte[] pdu = ConnectionFinalisation.BuildControlPdu(1, ConnectionFinalisation.ActionRequestControl, 1001);

        Assert.Equal(0x0001, BitConverter.ToUInt16(pdu, 18));
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 20));
        Assert.Equal(0u, BitConverter.ToUInt32(pdu, 22));
    }

    [Fact]
    public void FontList_MatchesTheAnnotatedDumpInTheSpecification()
    {
        // MS-RDPBCGR 2.2.1.18 and its annotated dump: numberFonts 0,
        // totalNumFonts 0, listFlags 0x0003, entrySize 0x0032.
        byte[] pdu = ConnectionFinalisation.BuildFontListPdu(0x000103EA, 1001);

        Assert.Equal(0x27, pdu[14]);            // pduType2 = PDUTYPE2_FONTLIST
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 18));
        Assert.Equal(0, BitConverter.ToUInt16(pdu, 20));
        Assert.Equal(0x0003, BitConverter.ToUInt16(pdu, 22));
        Assert.Equal(0x0032, BitConverter.ToUInt16(pdu, 24));
        Assert.Equal(26, pdu.Length);
    }

    [Fact]
    public void Batch_IsSynchronizeCooperateRequestControlFontListInThatOrder()
    {
        // MS-RDPBCGR 1.3.1.1 fixes this order, and the specification states these
        // PDUs may be sent as one batch precisely because they have no
        // dependency on any server-to-client PDU.
        IReadOnlyList<byte[]> batch = ConnectionFinalisation.BuildBatch(1, 1001);

        Assert.Equal(4, batch.Count);
        Assert.Equal(ConnectionFinalisation.PduType2Synchronize, batch[0][14]);
        Assert.Equal(ConnectionFinalisation.ActionCooperate, BitConverter.ToUInt16(batch[1], 18));
        Assert.Equal(ConnectionFinalisation.ActionRequestControl, BitConverter.ToUInt16(batch[2], 18));
        Assert.Equal(ConnectionFinalisation.PduType2FontList, batch[3][14]);
    }

    [Fact]
    public void Parse_ReadsBackTheSynchronizePdu()
    {
        ConnectionFinalisation.ShareDataPduInfo info =
            ConnectionFinalisation.Parse(ConnectionFinalisation.BuildSynchronizePdu(0x000103EA, 1001));

        Assert.Equal(22, info.TotalLength);
        Assert.Equal(ConnectionFinalisation.PduTypeData, info.PduType);
        Assert.Equal(1001, info.PduSource);
        Assert.Equal(0x000103EAu, info.ShareId);
        Assert.Equal(22, info.UncompressedLength);
        Assert.Equal(ConnectionFinalisation.PduType2Synchronize, info.PduType2);
        Assert.Equal(ConnectionFinalisation.SyncMessageTypeSync, info.Action);
    }

    [Fact]
    public void Parse_ReadsTheGrantedControlActionFromAServerControlPdu()
    {
        // The annotated dump of the server's Granted Control PDU carries
        // action 0x0002 at the first two octets of the body.
        byte[] granted = ConnectionFinalisation.BuildControlPdu(1, ConnectionFinalisation.ActionGrantedControl, 1002);

        ConnectionFinalisation.ShareDataPduInfo info = ConnectionFinalisation.Parse(granted);

        Assert.Equal(ConnectionFinalisation.PduType2Control, info.PduType2);
        Assert.Equal(ConnectionFinalisation.ActionGrantedControl, info.Action);
    }

    [Fact]
    public void Parse_KeepsThePduTypeInTheFourLeastSignificantBits()
    {
        // 2.2.8.1.1.1.1: the type subfield is the low nibble with PDUVersion in
        // the twelve bits above it. Reading the top bits reads a real
        // PDUTYPE_DATAPDU as "type 0".
        ConnectionFinalisation.ShareDataPduInfo info =
            ConnectionFinalisation.Parse(ConnectionFinalisation.BuildFontListPdu(1, 1001));

        Assert.Equal(ConnectionFinalisation.PduTypeData, info.PduType);
    }

    [Fact]
    public void Parse_RejectsAPduTooShortToHoldBothHeaders()
    {
        var truncated = new byte[10];

        var error = Assert.Throws<InvalidDataException>(
            () => ConnectionFinalisation.Parse(truncated));
        Assert.Contains("Share Data PDU", error.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ConnectionFinalisation.PduType2Synchronize, "Synchronize")]
    [InlineData(ConnectionFinalisation.PduType2Control, "Control")]
    [InlineData(ConnectionFinalisation.PduType2FontList, "Font List")]
    [InlineData(ConnectionFinalisation.PduType2FontMap, "Font Map")]
    public void DescribePduType2_NamesTheFinalizationPdus(byte type2, string expected) =>
        Assert.Equal(expected, ConnectionFinalisation.DescribePduType2(type2));

    [Fact]
    public void DescribePduType2_ReportsAnUnknownTypeRatherThanGuessing()
    {
        Assert.Equal("PDU type 0x99", ConnectionFinalisation.DescribePduType2(0x99));
    }
}