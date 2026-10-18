namespace RdpClient.Protocol;

/// <summary>
/// The Connection Finalization PDUs (MS-RDPBCGR 2.2.1.14-2.2.1.18): the client
/// Synchronize, Control (Cooperate), Control (Request Control) and Font List
/// PDUs, plus a parser for the server's replies.
/// </summary>
/// <remarks>
/// <para>
/// MS-RDPBCGR 1.3.1.1 states that the client-to-server PDUs of this phase "have
/// no dependencies on any of the server-to-client PDUs; they can be sent as a
/// single batch, provided that sequencing is maintained". They are therefore
/// built here and sent in one run, rather than interleaved with reads: reading
/// between them is what stalled this client, because the server is waiting for
/// the batch, not for the next read.
/// </para>
/// <para>
/// Nothing here carries pixels. The server may begin sending graphics once it
/// has the Font List PDU, but rendering those updates is a separate, unimplemented
/// layer.
/// </para>
/// </remarks>
public static class ConnectionFinalisation
{
    /// <summary>PDUTYPE_DATAPDU, the Share Control Header type for a data PDU (2.2.8.1.1.1.1).</summary>
    public const int PduTypeData = 7;

    /// <summary>PDUTYPE2_SYNCHRONIZE (2.2.8.1.1.1.2).</summary>
    public const byte PduType2Synchronize = 0x1F;

    /// <summary>PDUTYPE2_CONTROL.</summary>
    public const byte PduType2Control = 0x14;

    /// <summary>PDUTYPE2_FONTLIST.</summary>
    public const byte PduType2FontList = 0x27;

    /// <summary>PDUTYPE2_FONTMAP.</summary>
    public const byte PduType2FontMap = 0x28;

    /// <summary>PDUTYPE2_SET_ERROR_INFO_PDU, which may arrive at any time.</summary>
    public const byte PduType2SetErrorInfo = 0x2F;

    /// <summary>PDUTYPE2_STATUS_INFO_PDU.</summary>
    public const byte PduType2StatusInfo = 0x36;

    /// <summary>CTRLACTION_REQUEST_CONTROL (2.2.1.16).</summary>
    public const ushort ActionRequestControl = 0x0001;

    /// <summary>CTRLACTION_GRANTED_CONTROL (2.2.1.21), sent by the server.</summary>
    public const ushort ActionGrantedControl = 0x0002;

    /// <summary>CTRLACTION_DETACH.</summary>
    public const ushort ActionDetach = 0x0003;

    /// <summary>CTRLACTION_COOPERATE (2.2.1.15).</summary>
    public const ushort ActionCooperate = 0x0004;

    /// <summary>SYNCMSGTYPE_SYNC (2.2.1.14.1).</summary>
    public const ushort SyncMessageTypeSync = 0x0001;

    /// <summary>STREAM_UNDEFINED.</summary>
    public const byte StreamUndefined = 0x00;

    /// <summary>STREAM_LOW, which the Font List PDU uses.</summary>
    public const byte StreamLow = 0x01;

    /// <summary>
    /// The Share Data Header is twelve octets (2.2.8.1.1.1.2):
    /// <c>shareID(4) pad1(1) streamID(1) uncompressedLength(2) pduType2(1)
    /// compressedType(1) compressedLength(2)</c>.
    /// </summary>
    public const int ShareDataHeaderSize = 12;

    /// <summary>
    /// Build the whole client-side Connection Finalization batch, in the order
    /// 1.3.1.1 requires: Synchronize, Control (Cooperate), Control (Request
    /// Control), Font List. The optional Persistent Key List PDUs are not sent.
    /// </summary>
    /// <param name="shareId">The share id copied from the Demand Active PDU.</param>
    /// <param name="userChannel">
    /// The MCS user channel, written as the Share Control Header's pduSource.
    /// </param>
    public static IReadOnlyList<byte[]> BuildBatch(int shareId, ushort userChannel) =>
    [
        BuildSynchronizePdu(shareId, userChannel),
        BuildControlPdu(shareId, ActionCooperate, userChannel),
        BuildControlPdu(shareId, ActionRequestControl, userChannel),
        BuildFontListPdu(shareId, userChannel),
    ];

    /// <summary>
    /// Build a Synchronize PDU (MS-RDPBCGR 2.2.1.14.1). Twenty-two octets.
    /// </summary>
    /// <param name="shareId">The share id copied from the Demand Active PDU.</param>
    /// <param name="pduSource">The MCS user channel.</param>
    public static byte[] BuildSynchronizePdu(int shareId, ushort pduSource)
    {
        const int total = 6 + ShareDataHeaderSize + 4;

        var w = new ByteWriter(total);
        WriteShareControlHeader(w, PduTypeData, pduSource, (ushort)total);
        WriteShareDataHeader(w, shareId, StreamUndefined, (ushort)total, PduType2Synchronize);
        w.U16(SyncMessageTypeSync);
        w.U16(0);      // targetUser: the MCS channel ID of the target user
        return w.ToArray();
    }

    /// <summary>
    /// Build a Control PDU (MS-RDPBCGR 2.2.1.15.1). Twenty-six octets.
    /// </summary>
    /// <remarks>
    /// Both <c>grantId</c> and <c>controlId</c> MUST be zero for both client
    /// Control PDUs; only the action distinguishes Cooperate (0x0004) from
    /// Request Control (0x0001).
    /// </remarks>
    public static byte[] BuildControlPdu(int shareId, ushort action, ushort pduSource)
    {
        const int total = 6 + ShareDataHeaderSize + 8;

        var w = new ByteWriter(total);
        WriteShareControlHeader(w, PduTypeData, pduSource, (ushort)total);
        WriteShareDataHeader(w, shareId, StreamUndefined, (ushort)total, PduType2Control);
        w.U16(action);
        w.U16(0);      // grantId
        w.U32(0);      // controlId
        return w.ToArray();
    }

    /// <summary>
    /// Build a Font List PDU (MS-RDPBCGR 2.2.1.18.1). Twenty-six octets.
    /// </summary>
    /// <remarks>
    /// <c>numberFonts</c> and <c>totalNumFonts</c> are zero, so the
    /// <c>fontList</c> array is absent; <c>listFlags</c> is
    /// <c>FONTLIST_FIRST | FONTLIST_LAST</c> (0x0003) and <c>entrySize</c>
    /// is 50 (0x0032), the values the specification's own annotated dump
    /// carries.
    /// </remarks>
    public static byte[] BuildFontListPdu(int shareId, ushort pduSource)
    {
        const int total = 6 + ShareDataHeaderSize + 8;

        var w = new ByteWriter(total);
        WriteShareControlHeader(w, PduTypeData, pduSource, (ushort)total);
        WriteShareDataHeader(w, shareId, StreamLow, (ushort)total, PduType2FontList);
        w.U16(0);          // numberFonts
        w.U16(0);          // totalNumFonts
        w.U16(0x0003);     // listFlags: FONTLIST_FIRST | FONTLIST_LAST
        w.U16(0x0032);     // entrySize
        return w.ToArray();
    }

    /// <summary>
    /// A parsed Share Data PDU: its two headers, the PDU body, and the raw
    /// octets it was parsed from.
    /// </summary>
    /// <param name="TotalLength">
    /// The Share Control Header's <c>totalLength</c>, which counts both headers
    /// and the body.
    /// </param>
    /// <param name="PduType">The low nibble of the control header's pduType.</param>
    /// <param name="PduSource">The channel the PDU is sent on.</param>
    /// <param name="ShareId">The share id from the Demand Active PDU.</param>
    /// <param name="StreamId">The T.128 stream id.</param>
    /// <param name="UncompressedLength">The length of the PDU once inflated.</param>
    /// <param name="PduType2">The type of the PDU carried in the body.</param>
    /// <param name="Action">
    /// The first body field, which is the <c>messageType</c> of a Synchronize
    /// PDU and the <c>action</c> of a Control PDU.
    /// </param>
    /// <param name="BodyOffset">Where the body begins, past both headers.</param>
    /// <param name="CompressedType">
    /// The Share Data Header's <c>compressedType</c>: the low nibble is the
    /// compression package, and 0x20, 0x40 and 0x80 are the PACKET_COMPRESSED,
    /// PACKET_AT_FRONT and PACKET_FLUSHED flags.
    /// </param>
    /// <param name="CompressedLength">
    /// The Share Data Header's <c>compressedLength</c>: zero when the body is not
    /// compressed, otherwise the size of the compressed payload.
    /// </param>
    /// <param name="RawPdu">The octets the PDU was parsed from.</param>
    public sealed record ShareDataPduInfo(
        int TotalLength,
        int PduType,
        int PduSource,
        uint ShareId,
        byte StreamId,
        ushort UncompressedLength,
        byte PduType2,
        ushort Action,
        int BodyOffset,
        byte CompressedType,
        ushort CompressedLength,
        byte[] RawPdu);

    /// <summary>
    /// Parse the two headers of a received Share Data PDU.
    /// </summary>
    /// <remarks>
    /// The Share Control Header's <c>totalLength</c> is the authority on how
    /// long the PDU is; it counts both headers and the body. A
    /// <c>totalLength</c> of 0x8000 introduces a T.128 FlowPDU instead, which
    /// carries no Share Data PDU and is skipped by the caller.
    /// </remarks>
    public static ShareDataPduInfo Parse(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        if (buffer.Length < 6 + ShareDataHeaderSize)
        {
            throw new InvalidDataException(
                $"a Share Data PDU is at least {6 + ShareDataHeaderSize} octets, got {buffer.Length}");
        }

        var r = new ByteReader(buffer);
        int totalLength = r.U16();
        int pduType = r.U16() & 0x0F;      // type in the 4 least significant bits (2.2.8.1.1.1.1)
        int pduSource = r.U16();
        uint shareId = r.U32();
        r.U8();                            // pad1
        byte streamId = r.U8();
        ushort uncompressedLength = r.U16();
        byte pduType2 = r.U8();
        byte compressedType = r.U8();
        ushort compressedLength = r.U16();

        int bodyOffset = 6 + ShareDataHeaderSize;
        // The first body field is the messageType of a Synchronize PDU and the
        // action of a Control PDU, so one read serves both.
        ushort action = r.Remaining >= 2 ? r.U16() : (ushort)0;

        return new ShareDataPduInfo(totalLength, pduType, pduSource, shareId, streamId,
            uncompressedLength, pduType2, action, bodyOffset,
            compressedType, compressedLength, buffer);
    }

    /// <summary>Name a client PDU for the handshake log.</summary>
    public static string Describe(byte[] pdu)
    {
        ArgumentNullException.ThrowIfNull(pdu);

        ShareDataPduInfo info = Parse(pdu);
        return DescribePduType2(info.PduType2);
    }

    /// <summary>Name a <c>pduType2</c> value for the handshake log.</summary>
    public static string DescribePduType2(byte pduType2) => pduType2 switch
    {
        PduType2Synchronize => "Synchronize",
        PduType2Control => "Control",
        PduType2FontList => "Font List",
        PduType2FontMap => "Font Map",
        PduType2SetErrorInfo => "Set Error Info",
        PduType2StatusInfo => "Status Info",
        _ => $"PDU type 0x{pduType2:x2}",
    };

    /// <summary>Keep a log honest about what the parser saw in a Share Data PDU.</summary>
    public static string Describe(ShareDataPduInfo info) =>
        $"type2 0x{info.PduType2:x2} flags 0x{info.CompressedType:x2} "
        + $"clen {info.CompressedLength} ulen {info.UncompressedLength} "
        + $"shareId 0x{info.ShareId:x8} stream {info.StreamId}";

    private static void WriteShareControlHeader(ByteWriter w, int pduType, ushort pduSource, ushort totalLength)
    {
        w.U16(totalLength);
        // PDUVersion (0x1) occupies the twelve bits above the type, so a data
        // PDU encodes as 0x0017 on the wire.
        w.U16((pduType & 0xF) | (Capability.ProtocolVersion << 4));
        w.U16(pduSource);
    }

    private static void WriteShareDataHeader(ByteWriter w, int shareId, byte streamId, ushort uncompressedLength, byte pduType2)
    {
        w.U32((uint)shareId);
        w.U8(0);               // pad1
        w.U8(streamId);
        w.U16(uncompressedLength);
        w.U8(pduType2);
        w.U8(0);               // compressedType: the batch is sent uncompressed
        w.U16(0);              // compressedLength
    }
}