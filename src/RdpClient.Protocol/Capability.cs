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
    // Share Control Header pduType2 values (MS-RDPBCGR 2.2.8.1.1.1.1).
    public const int PduTypeDemandActive = 1;
    public const int PduTypeConfirmActive = 3;

    /// <summary>TS_PROTOCOL_VERSION, the low twelve bits of pduType2.</summary>
    public const int ProtocolVersion = 0x1;

    /// <summary>The Share Control Header is totalLength, pduType2, pduType1.</summary>
    public const int ShareControlHeaderSize = 6;

    /// <summary>CAPSTYPE_GENERAL, from MS-RDPBCGR 2.2.7.1.1.</summary>
    public const ushort CapSetGeneral = Rdp.CapSetGeneral;

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
    /// pduType2 packs the PDU type in its top two bits and the protocol version
    /// in the rest, which is why a Demand Active header is 0x1 and a Confirm
    /// Active is 0x3 rather than the raw type number: the layout is
    /// <c>(pduType &lt;&lt; 12) | (flags &lt;&lt; 10) | pduVersion</c>.
    /// </remarks>
    /// <param name="pduType">One of the <c>PduType*</c> values.</param>
    /// <param name="flags">The two action bits, normally zero.</param>
    /// <param name="totalLength">Length of the whole PDU, header included.</param>
    public static byte[] BuildShareControlHeader(int pduType, int flags, int totalLength)
    {
        if (totalLength > ushort.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(totalLength), totalLength,
                "a slow-path PDU length is a 16-bit field");
        }

        var w = new ByteWriter(ShareControlHeaderSize);
        w.U16(totalLength);
        w.U16((pduType << 12) | ((flags & 0x03) << 10) | (ProtocolVersion & 0x03FF));
        w.U16(0);     // pduType1, reserved
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
        r.U16();     // pduType1, reserved

        return new ShareControlHeader(
            totalLength,
            pduType2 >> 12,
            pduType2 & 0x03FF,
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
        Rdp.CapSetVirtualChannel => "VirtualChannel",
        Rdp.CapSetDrawableGdi => "DrawableGdi",
        Rdp.CapSetPduOrder => "PduOrder",
        Rdp.CapSetTextInput => "TextInput",
        Rdp.CapSetWindow => "Window",
        Rdp.CapSetMultitransport => "Multitransport",
        _ => "Unknown",
    };

    /// <summary>
    /// Build the Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2.1).
    /// </summary>
    /// <remarks>
    /// The originator ID is fixed at the server channel id 0x03EA (1002) by the
    /// specification, which is a different channel from either the user channel
    /// this client joins or the global channel it sends on: 1002 is the channel
    /// the server owns.
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
            + 0                                          // sourceDescriptor, empty
            + 4                                          // numberCapabilities, pad2Octets
            + setsLength;

        var w = new ByteWriter(totalLength);
        w.Bytes(BuildShareControlHeader(PduTypeConfirmActive, 0, totalLength));
        w.U32(shareId);
        w.U16(Rdp.McsServerChannel);                    // originatorID, fixed at 1002
        w.U16(0);                                       // lengthSourceDescriptor
        w.U16(4 + setsLength);                          // lengthCombinedCapabilities
        w.U16(capabilities.Count);                      // numberCapabilities
        w.U16(0);                                       // pad2Octets

        foreach (byte[] set in capabilities)
        {
            w.Bytes(set);
        }

        return w.ToArray();
    }
}