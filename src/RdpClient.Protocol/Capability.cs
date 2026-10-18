namespace RdpClient.Protocol;

/// <summary>
/// The mandatory capability exchange: the server's Demand Active PDU and the
/// client's Confirm Active PDU (MS-RDPBCGR 2.2.1.13).
/// </summary>
/// <remarks>
/// This is the first stage that is not MCS. From here on the server sends
/// T.128 PDUs, each one a Share Control Header followed by a structure. The
/// exchange itself is a single request and a single response, but it is what
/// makes every later PDU possible: a server will not send a Synchronize PDU to a
/// client that has not answered the Demand Active.
/// </remarks>
public static class Capability
{
    // Share Control Header pduType values (MS-RDPBCGR 2.2.8.1.1.1.1).
    public const int PduTypeDemandActive = 1;
    public const int PduTypeConfirmActive = 3;

    /// <summary>
    /// TS_PROTOCOL_VERSION (MS-RDPBCGR 2.2.1.13.1.1): the value of the 12-bit
    /// PDUVersion subfield of the pduType field.
    /// </summary>
    public const int ProtocolVersion = 0x1;

    /// <summary>
    /// The Share Control Header is totalLength(2), pduType(2), pduSource(2)
    /// (MS-RDPBCGR 2.2.8.1.1.1.1).
    /// </summary>
    public const int ShareControlHeaderSize = 6;

    /// <summary>
    /// The T.128 source descriptor, "RDP" plus its NUL (T128 8.4.1). xrdp
    /// writes the same four octets in its own Demand Active PDU.
    /// </summary>
    public const int SourceDescriptorLength = 4;

    /// <summary>
    /// Where the capability sets begin in a Confirm Active PDU this class
    /// builds (TS_CONFIRM_ACTIVE_PDU, MS-RDPBCGR 2.2.1.13.2.1): after the
    /// Share Control Header, shareID, originatorID, lengthSourceDescriptor,
    /// lengthCombinedCapabilities, the source descriptor, numberCapabilities
    /// and pad2Octets.
    /// </summary>
    public const int ConfirmActiveSetsOffset =
        ShareControlHeaderSize + 4 + 2 + 2 + 2 + SourceDescriptorLength + 2 + 2;

    /// <summary>CAPSTYPE_GENERAL, from MS-RDPBCGR 2.2.7.1.1.</summary>
    public const ushort CapSetGeneral = Rdp.CapSetGeneral;

    /// <summary>CAPSTYPE_BITMAP, from MS-RDPBCGR 2.2.7.1.2.</summary>
    public const ushort CapSetBitmap = Rdp.CapSetBitmap;

    /// <summary>CAPSTYPE_FONT, from MS-RDPBCGR 2.2.7.2.5.</summary>
    public const ushort CapSetFont = Rdp.CapSetFont;

    /// <summary>CAPSTYPE_BITMAPCACHE_REV2, from MS-RDPBCGR 2.2.7.1.4.2.</summary>
    public const ushort CapSetBitmapCacheRev2 = Rdp.CapSetBmpCacheRev2;

    /// <summary>
    /// TS_BITMAPCACHE_CAPABILITYSET_REV2 is 40 octets: the two header octets
    /// pairs, CacheFlags, Pad2, NumCellCaches, five four-octet cell infos and
    /// the twelve-octet Pad3 (2.2.7.1.4.2).
    /// </summary>
    public const int BitmapCacheRev2CapabilitySetLength = 40;

    /// <summary>The three cell caches this client advertises (2.2.7.1.4.2).</summary>
    public const byte BitmapCacheCellCount = 3;

    /// <summary>
    /// Cell counts for caches 0, 1 and 2, from the values Microsoft's own
    /// protocol test suite uses (2.2.7.1.4.2, <c>BITMAP_CACHE_CELL1_VALUE</c>
    /// and friends).
    /// </summary>
    public static readonly ushort[] BitmapCacheEntries = [120, 120, 2555];

    /// <summary>
    /// Per-cache maximum cell sizes. Cache 0 holds bitmaps of about 16 KiB,
    /// cache 1 about 64 KiB, and cache 2 about 256 KiB, which is the ladder the
    /// test suite advertises and which xrdp's own default matches.
    /// </summary>
    public static readonly int[] BitmapCacheMaxCellSize = [16 * 1024, 64 * 1024, 256 * 1024];

    /// <summary>TS_BITMAP_CAPABILITYSET is a fixed 28 octets.</summary>
    public const int BitmapCapabilitySetLength = 28;

    /// <summary>TS_FONT_CAPABILITYSET is a fixed 8 octets.</summary>
    public const int FontCapabilitySetLength = 8;

    /// <summary>DRAW_UNUSED_FLAG, which MS-RDPBCGR 2.2.7.1.2 says to ignore.</summary>
    public const byte DrawingFlagUnused = 0x10;

    /// <summary>TS_CAPS_PROTOCOLVERSION, from MS-RDPBCGR 2.2.7.1.1.</summary>
    public const ushort CapsProtocolVersion = 0x0200;

    /// <summary>OSMAJORTYPE_WINDOWS, from MS-RDPBCGR 2.2.7.1.1.</summary>
    public const ushort OsMajorWindows = 0x0001;

    /// <summary>OSMINORTYPE_WINDOWS_NT, from MS-RDPBCGR 2.2.7.1.1.</summary>
    public const ushort OsMinorWindowsNt = 0x0003;

    /// <summary>TS_GENERAL_CAPABILITYSET is a fixed 24 octets.</summary>
    public const int GeneralCapabilitySetLength = 24;

    // extraFlags (MS-RDPBCGR 2.2.7.1.1). Nothing here is honoured yet, so
    // nothing is advertised: announcing a capability the client does not
    // implement makes the server send PDUs and wait for replies that never come.
    public const ushort ExtraFlagFastPathOutputSupported = 0x0001;
    public const ushort ExtraFlagLongCredentialsSupported = 0x0004;
    public const ushort ExtraFlagAutoReconnectSupported = 0x0008;

    /// <summary>
    /// Build the Share Control Header (MS-RDPBCGR 2.2.8.1.1.1.1).
    /// </summary>
    /// <remarks>
    /// The pduType field keeps the PDU type in its 4 <c>least</c> significant
    /// bits with PDUVersion in the 12 bits above them, so the whole field is
    /// <c>(pduType &amp; 0xF) | (ProtocolVersion &lt;&lt; 4)</c> and a Demand
    /// Active encodes 0x0011. The field is read back the same way by xrdp
    /// (<c>pdu_code &amp; 0xf</c> in xrdp_rdp_recv) and written the same way by
    /// FreeRDP (<c>type | 0x10</c>); packing the type into the top bits
    /// produced bytes no peer speaks, and reading the top bits mistook every
    /// real Demand Active for "type 0".
    /// </remarks>
    /// <param name="pduType">One of the <c>PduType*</c> values.</param>
    /// <param name="totalLength">Length of the whole PDU, header included.</param>
    public static byte[] BuildShareControlHeader(int pduType, int totalLength)
    {
        if (totalLength > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(totalLength), totalLength,
                "a slow-path PDU length is a 16-bit field");
        }

        var w = new ByteWriter(ShareControlHeaderSize);
        w.U16(totalLength);
        w.U16((pduType & 0xF) | (ProtocolVersion << 4));
        w.U16(Rdp.McsGlobalChannel);  // pduSource - the channel the PDU is sent on
        return w.ToArray();
    }

    public sealed record ShareControlHeader(int TotalLength, int PduType, int PduVersion, int PayloadOffset);

    /// <summary>Read the Share Control Header and say where the structure begins.</summary>
    public static ShareControlHeader ParseShareControlHeader(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        if (buffer.Length < ShareControlHeaderSize)
        {
            throw new InvalidDataException(
                $"a Share Control Header is {ShareControlHeaderSize} octets, got {buffer.Length}");
        }

        var r = new ByteReader(buffer);
        int totalLength = r.U16();
        int pduType2 = r.U16();
        r.U16();     // pduSource

        // totalLength 0x8000 signals a T.128 FlowPDU (MS-RDPBCGR 2.2.8.1.1.1.1;
        // FreeRDP treats it the same way in rdp_read_share_control_header). It
        // is not a slow-path PDU and its remaining bytes mean nothing here.
        if (totalLength == 0x8000)
        {
            throw new InvalidDataException(
                "the Share Control Header reads as a FlowPDU (totalLength 0x8000), "
                + "which carries no slow-path PDU");
        }

        return new ShareControlHeader(
            totalLength,
            pduType2 & 0xF,           // type: 4 least significant bits (2.2.8.1.1.1.1)
            (pduType2 >> 4) & 0xFFF,  // PDUVersion: TS_PROTOCOL_VERSION = 0x1
            ShareControlHeaderSize);
    }

    public sealed record CapabilitySet(ushort Type, int Length, byte[] Raw);

    /// <summary>
    /// Walk the capability sets in a Demand Active or Confirm Active PDU.
    /// </summary>
    /// <remarks>
    /// Each set is <c>capabilitySetType(2)</c>, <c>lengthCapability(2)</c> and
    /// then that many octets - and <c>lengthCapability</c> counts the four
    /// octets of its own header, the same way a TS_UD_HEADER length does. A set
    /// that declares more than remains would otherwise be read as the next set.
    /// </remarks>
    public static IReadOnlyList<CapabilitySet> ParseCapabilitySets(byte[] data, int offset, int length)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        var sets = new List<CapabilitySet>();
        int cursor = offset;
        int end = offset + length;

        while (cursor < end)
        {
            if (end - cursor < 4)
            {
                throw new InvalidDataException(
                    $"a capability set header needs 4 octets, {end - cursor} remain");
            }

            var r = new ByteReader(data.AsMemory(cursor, end - cursor));
            ushort type = r.U16();
            int declared = r.U16();

            if (declared < 4 || declared > end - cursor)
            {
                throw new InvalidDataException(
                    $"capability set 0x{type:x4} declares {declared} octets but only "
                    + $"{end - cursor} remain");
            }

            sets.Add(new CapabilitySet(type, declared, data.AsSpan(cursor, declared).ToArray()));
            cursor += declared;
        }

        return sets;
    }

    /// <summary>
    /// Build the General Capability Set (MS-RDPBCGR 2.2.7.1.1).
    /// </summary>
    /// <remarks>
    /// A fixed 24 octets, of which 18 are fields the specification requires to
    /// be zero for this client: no compression, no update capability, no remote
    /// unsharing, no compression level. Only <c>extraFlags</c> carries anything,
    /// and it is left at zero for the same reason this client announces no
    /// capability it does not honour.
    /// </remarks>
    public static byte[] BuildGeneralCapabilitySet(ushort extraFlags = 0)
    {
        var w = new ByteWriter(GeneralCapabilitySetLength);
        w.U16(CapSetGeneral);
        w.U16(GeneralCapabilitySetLength);
        w.U16(OsMajorWindows);
        w.U16(OsMinorWindowsNt);
        w.U16(CapsProtocolVersion);
        w.U16(0);         // pad2octetsA
        w.U16(0);         // compressionTypes, must be zero
        w.U16(extraFlags);
        w.U16(0);         // updateCapabilityFlag, must be zero
        w.U16(0);         // remoteUnshareFlag, must be zero
        w.U16(0);         // compressionLevel, must be zero
        w.U8(0);          // refreshRectSupport, server-only
        w.U8(0);          // suppressOutputSupport, server-only
        return w.ToArray();
    }

    /// <summary>
    /// Build the Bitmap Capability Set (MS-RDPBCGR 2.2.7.1.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Sending this set is what makes the server send bitmap updates
    /// (2.2.9.1.1.3.1.2) rather than GDI drawing orders, because the Order
    /// Capability Set is what asks for orders and this client deliberately does
    /// not send it - the order vocabulary in [MS-RDPEGDI] is not implemented.
    /// </para>
    /// <para>
    /// Two fields are not free choices. <c>bitmapCompressionFlag</c> and
    /// <c>multipleRectangleSupport</c> MUST both be 1 "because multiple
    /// rectangle support is required for a connection to proceed", so a client
    /// that cannot decompress interleaved RLE or handle several rectangles per
    /// update cannot claim this set at all - it would be lying about what it can
    /// accept.
    /// </para>
    /// <para>
    /// The <c>receive{1,4,8}BitsPerPixel</c> fields are documented as ignored
    /// but SHOULD be TRUE, so they are written as 1 rather than 0.
    /// </para>
    /// </remarks>
    /// <param name="desktopWidth">The requested desktop width in pixels.</param>
    /// <param name="desktopHeight">The requested desktop height in pixels.</param>
    /// <param name="preferredBitsPerPixel">
    /// The colour depth requested, which must match what the client can decode.
    /// </param>
    public static byte[] BuildBitmapCapabilitySet(
        int desktopWidth, int desktopHeight, int preferredBitsPerPixel = 16)
    {
        if (desktopWidth is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(desktopWidth));
        }

        if (desktopHeight is < 1 or > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(desktopHeight));
        }

        if (preferredBitsPerPixel is not (15 or 16 or 24 or 32))
        {
            throw new ArgumentOutOfRangeException(
                nameof(preferredBitsPerPixel), preferredBitsPerPixel,
                "the Bitmap Capability Set carries 15, 16, 24 or 32");
        }

        var w = new ByteWriter(BitmapCapabilitySetLength);
        w.U16(CapSetBitmap);
        w.U16(BitmapCapabilitySetLength);
        w.U16(preferredBitsPerPixel);
        w.U16(1);          // receive1BitPerPixel, ignored but SHOULD be TRUE
        w.U16(1);          // receive4BitsPerPixel
        w.U16(1);          // receive8BitsPerPixel
        w.U16(desktopWidth);
        w.U16(desktopHeight);
        w.U16(0);          // pad2octets
        w.U16(0);          // desktopResizeFlag: this client does not resize
        w.U16(1);          // bitmapCompressionFlag: MUST be TRUE to proceed
        w.U8(0);           // highColorFlags: ignored, SHOULD be zero
        w.U8(DrawingFlagUnused);    // drawingFlags; the bit is documented as ignored
        w.U16(1);          // multipleRectangleSupport: MUST be TRUE to proceed
        w.U16(0);          // pad2octetsB
        return w.ToArray();
    }

    /// <summary>
    /// Build the Revision 2 Bitmap Cache Capability Set (MS-RDPBCGR 2.2.7.1.4.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without this set the server has nowhere to put a bitmap: xrdp answers
    /// every Cache Bitmap order with <c>error in xrdp_cache_add_bitmap, too
    /// big</c> and repeats it for each one, so nothing reaches the screen even
    /// though the orders themselves decode.
    /// </para>
    /// <para>
    /// A <c>TS_BITMAPCACHE_CELL_CACHE_INFO</c> packs two nibbles and two
    /// octets: the low seven bits of the first octet are the number of cells,
    /// its high bit is the wait flag, and the second octet holds two more
    /// nibbles for the per-cell maximum size. That packing is why the cell
    /// counts below are masked with 0x7F rather than written plainly.
    /// </para>
    /// </remarks>
    public static byte[] BuildBitmapCacheRev2CapabilitySet()
    {
        var w = new ByteWriter(BitmapCacheRev2CapabilitySetLength);
        w.U16(CapSetBitmapCacheRev2);
        w.U16(BitmapCacheRev2CapabilitySetLength);
        w.U16(0);                              // CacheFlags
        w.U8(0);                               // Pad2
        w.U8(BitmapCacheCellCount);             // NumCellCaches

        for (int cache = 0; cache < 5; cache++)
        {
            if (cache < BitmapCacheCellCount)
            {
                w.U32(BuildCellCacheInfo(BitmapCacheEntries[cache], BitmapCacheMaxCellSize[cache]));
            }
            else
            {
                w.U32(0);
            }
        }

        // Pad3, twelve octets, which the variable-length writer leaves as zeros.
        for (int i = 0; i < 12; i++)
        {
            w.U8(0);
        }

        return w.ToArray();
    }

    /// <summary>
    /// Pack one <c>TS_BITMAPCACHE_CELL_CACHE_INFO</c> (2.2.7.1.4.2.1).
    /// </summary>
    private static uint BuildCellCacheInfo(ushort entries, int maximumCellSize)
    {
        // The size is expressed in units that double as the cell grows, so it is
        // stored as the logarithm: 16 KiB is 2^10, and the specification's table
        // starts at 240 which is 15 * 16.
        int sizeUnits = maximumCellSize <= 240
            ? maximumCellSize / 16
            : maximumCellSize >> 8;

        uint low = (uint)(entries & 0x7F);
        uint high = (uint)(sizeUnits & 0x0F) << 4;

        return low | high | ((uint)(sizeUnits >> 4) << 16);
    }

    /// <summary>
    /// Build the Font Capability Set (MS-RDPBCGR 2.2.7.2.5).
    /// </summary>
    /// <remarks>
    /// This client renders no text, so it advertises no fonts and no font
    /// smoothing. It is sent because the Font List PDU has already gone out and
    /// the server answers it with a Font Map regardless; announcing no fonts is
    /// what an empty <c>fontList</c> in that PDU means.
    /// </remarks>
    public static byte[] BuildFontCapabilitySet()
    {
        var w = new ByteWriter(FontCapabilitySetLength);
        w.U16(CapSetFont);
        w.U16(FontCapabilitySetLength);
        w.U16(0);          // fontSupportFlags
        w.U16(0);          // pad2Octets
        return w.ToArray();
    }

    public sealed record DemandActive(
        int ShareId,
        uint SessionId,
        IReadOnlyList<CapabilitySet> Capabilities,
        string Summary);

    /// <summary>
    /// Parse a Demand Active PDU (MS-RDPBCGR 2.2.1.13.1.1).
    /// </summary>
    /// <remarks>
    /// <c>lengthCombinedCapabilities</c> counts numberCapabilities, pad2Octets
    /// and the capability sets together, so it is the authority on where the
    /// sets end; the count field is cross-checked against what actually walks
    /// out, because the two are written separately and a server that gets one
    /// wrong is describing something that is not on the wire.
    /// </remarks>
    public static DemandActive ParseDemandActive(byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        var header = ParseShareControlHeader(payload);
        if (header.PduType != PduTypeDemandActive)
        {
            throw new InvalidDataException(
                $"expected a Demand Active PDU (type {PduTypeDemandActive}), got type {header.PduType}");
        }

        // The reader is over the whole buffer and seeks to the structure, so every
        // offset it reports is absolute. Slicing the buffer instead and passing
        // that relative offset back into ParseCapabilitySets reads the
        // lengthCombinedCapabilities field as a capability set header.
        var r = new ByteReader(payload);
        r.Seek(header.PayloadOffset);
        uint shareId = r.U32();
        int sourceDescriptorLength = r.U16();
        int combinedCapabilitiesLength = r.U16();

        if (sourceDescriptorLength < 0 || r.Remaining < sourceDescriptorLength)
        {
            throw new InvalidDataException(
                $"the Demand Active PDU declares a {sourceDescriptorLength}-octet source descriptor "
                + $"but only {r.Remaining} octets remain");
        }

        r.Skip(sourceDescriptorLength);

        if (r.Remaining < combinedCapabilitiesLength)
        {
            throw new InvalidDataException(
                $"the Demand Active PDU declares {combinedCapabilitiesLength} octets of capability "
                + $"data but only {r.Remaining} remain");
        }

        // numberCapabilities and pad2Octets sit inside lengthCombinedCapabilities.
        if (r.Remaining < 4)
        {
            throw new InvalidDataException(
                "the Demand Active PDU has no capability count");
        }

        int declaredSets = r.U16();
        r.U16();     // pad2Octets

        int setsLength = combinedCapabilitiesLength - 4;
        IReadOnlyList<CapabilitySet> sets = ParseCapabilitySets(payload, r.Offset, setsLength);

        // Step over the sets before the session id. ParseCapabilitySets returns
        // copies rather than moving this reader, and reading the session id from
        // where the first set's header is produced 0x0018xxxx for any General
        // set instead of the session the server chose.
        r.Skip(setsLength);

        if (sets.Count != declaredSets)
        {
            throw new InvalidDataException(
                $"the Demand Active PDU declares {declaredSets} capability sets but {sets.Count} "
                + "are present");
        }

        if (r.Remaining < 4)
        {
            throw new InvalidDataException("the Demand Active PDU carries no session id");
        }

        uint sessionId = r.U32();

        return new DemandActive(
            (int)shareId, sessionId, sets, DescribeCapabilitySets(sets));
    }

    /// <summary>Name the capability sets in a form a log line can carry.</summary>
    public static string DescribeCapabilitySets(IReadOnlyList<CapabilitySet> sets)
    {
        ArgumentNullException.ThrowIfNull(sets);

        string[] names = new string[sets.Count];
        for (int i = 0; i < sets.Count; i++)
        {
            names[i] = $"{CapabilityName(sets[i].Type)}(0x{sets[i].Type:x4}, {sets[i].Length})";
        }

        return sets.Count == 0 ? "none" : string.Join(", ", names);
    }

    private static string CapabilityName(ushort type) => type switch
    {
        Rdp.CapSetGeneral => "General",
        Rdp.CapSetBitmap => "Bitmap",
        Rdp.CapSetOrder => "Order",
        Rdp.CapSetBmpCache => "BmpCache",
        Rdp.CapSetControl => "Control",
        Rdp.CapSetActivate => "Activate",
        Rdp.CapSetPointer => "Pointer",
        Rdp.CapSetShare => "Share",
        Rdp.CapSetSound => "Sound",
        Rdp.CapSetInput => "Input",
        Rdp.CapSetFont => "Font",
        Rdp.CapSetBrush => "Brush",
        Rdp.CapSetGlyphCache => "GlyphCache",
        Rdp.CapSetOffscreenCache => "OffscreenCache",
        Rdp.CapSetBmpCacheRev2 => "BmpCacheRev2",
        Rdp.CapSetBmpCacheHostSupport => "BmpCacheHostSupport",
        Rdp.CapSetVirtualChannel => "VirtualChannel",
        Rdp.CapSetDrawNineGridCache => "DrawNineGridCache",
        Rdp.CapSetDrawGdiPlus => "DrawGdiPlus",
        Rdp.CapSetRail => "Rail",
        Rdp.CapSetWindow => "Window",
        Rdp.CapSetCompDesk => "CompDesk",
        Rdp.CapSetMultitransport => "Multitransport",
        Rdp.CapSetLargePointer => "LargePointer",
        Rdp.CapSetSurfaceCommands => "SurfaceCommands",
        Rdp.CapSetBitmapCodecs => "BitmapCodecs",
        Rdp.CapSetFrameAcknowledge => "FrameAcknowledge",
        _ => "Unknown",
    };

    /// <summary>
    /// Build the Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2.1).
    /// </summary>
    /// <remarks>
    /// The originator ID is fixed at the server channel id 0x03EA (1002) by the
    /// specification, which is a different channel from either the user channel
    /// this client joins or the global channel it sends on: 1002 is the channel
    /// the server owns. The set body carries the T.128 source descriptor
    /// "RDP\0", the same four octets xrdp writes in its own Demand Active.
    /// </remarks>
    /// <param name="shareId">Copied from the Demand Active PDU.</param>
    /// <param name="capabilities">
    /// The sets to advertise, each already carrying its own type and length.
    /// </param>
    public static byte[] BuildConfirmActivePdu(int shareId, IReadOnlyList<byte[]> capabilities)
    {
        ArgumentNullException.ThrowIfNull(capabilities);

        int setsLength = capabilities.Sum(c => c.Length);
        if (setsLength > ushort.MaxValue)
        {
            throw new ArgumentException(
                "the combined capability sets exceed the 16-bit length field", nameof(capabilities));
        }

        int totalLength = ShareControlHeaderSize       // shareControlHeader
            + 4                                          // shareID
            + 2                                          // originatorID
            + 2                                          // lengthSourceDescriptor
            + 2                                          // lengthCombinedCapabilities
            + SourceDescriptorLength                     // sourceDescriptor, "RDP\0"
            + 4                                          // numberCapabilities, pad2Octets
            + setsLength;

        var w = new ByteWriter(totalLength);
        w.Bytes(BuildShareControlHeader(PduTypeConfirmActive, totalLength));
        w.U32(shareId);
        w.U16(Rdp.McsServerChannel);                    // originatorID, fixed at 1002
        w.U16(SourceDescriptorLength);                  // lengthSourceDescriptor
        w.U16(2 + 2 + setsLength);                      // lengthCombinedCapabilities
        w.U8((byte)'R');                                // sourceDescriptor: T.128 "RDP"
        w.U8((byte)'D');
        w.U8((byte)'P');
        w.U8(0);
        w.U16(capabilities.Count);                      // numberCapabilities
        w.U16(0);                                       // pad2Octets

        foreach (byte[] set in capabilities)
        {
            w.Bytes(set);
        }

        return w.ToArray();
    }
}