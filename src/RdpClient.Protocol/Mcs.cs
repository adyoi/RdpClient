namespace RdpClient.Protocol;

/// <summary>
/// MCS connection and channel primitives (MS-RDPBCGR 2.2.1.3.1 - 2.2.1.3.6).
/// </summary>
/// <remarks>
/// MCS is the T.125 presentation layer that carries GCC and the rest of the
/// connection. After Connect Initial/Response the client must erect the server
/// domain, attach itself as a user, and join the MCS global channel before any
/// application data can flow.
/// </remarks>
public static class Mcs
{
    /// <summary>
    /// Build the GCC Conference Create Request (MS-RDPBCGR 2.2.1.3.2).
    /// </summary>
    /// <remarks>
    /// The conference name length is expressed in UTF-16 code units, not bytes,
    /// which is the detail most reimplementations get wrong.
    /// </remarks>
    public static byte[] BuildConferenceCreateRequest(string conferenceName = Rdp.GccConferenceName)
    {
        var w = new ByteWriter(64);
        w.U8(0x01); // t124 Identifier
        w.U16(conferenceName.Length);
        w.Utf16(conferenceName);
        w.U16(Rdp.GccConferenceLabel);
        return w.ToArray();
    }

    public sealed record ConnectInitialOptions
    {
        public uint Cookie { get; init; } = 0xa0a0;
        public byte ProtocolVersion { get; init; } = 3;
        public ushort RSTransactionId { get; init; }
        public ushort ClientNodeId { get; init; } = Rdp.McsUserChannelBase;

        /// <summary>TS_UD_CS_CORE, TS_UD_CS_SECURITY, TS_UD_CS_NET and friends, concatenated.</summary>
        public required byte[] ClientInfo { get; init; }

        public string ConferenceName { get; init; } = Rdp.GccConferenceName;
    }

    /// <summary>
    /// Build the MCS Connect Initial PDU carrying the GCC conference and client data.
    /// </summary>
    /// <remarks>
    /// Each variable-length region is prefixed with a 2-byte byte count, and the
    /// whole thing is wrapped in TPKT/X.224 by <see cref="Negotiation.Tpkt"/>.
    /// </remarks>
    public static byte[] BuildConnectInitial(ConnectInitialOptions options)
    {
        byte[] conference = BuildConferenceCreateRequest(options.ConferenceName);

        var mcs = new ByteWriter(256);
        mcs.U8(options.ProtocolVersion);
        mcs.U16(options.RSTransactionId);
        mcs.U16((int)options.Cookie);

        // Connect Data: length-prefixed GCC Conference Create Request.
        mcs.U16(conference.Length).Bytes(conference);

        // Client Node ID: length-prefixed.
        mcs.U16(2).U16(options.ClientNodeId);

        // Client Info: length-prefixed block of TS_UD_CS_* structures.
        mcs.U16(options.ClientInfo.Length).Bytes(options.ClientInfo);
        return mcs.ToArray();
    }

    /// <summary>
    /// Wrap a Connect Initial in the X.224 Connection Request envelope (2.2.1.3).
    /// </summary>
    /// <remarks>
    /// After negotiation the MCS Connect Initial travels in the same class 0
    /// X.224 request envelope as the negotiation PDU, with no routing token.
    /// </remarks>
    public static byte[] BuildConnectInitialPdu(ConnectInitialOptions options)
    {
        byte[] mcs = BuildConnectInitial(options);
        var x224 = new ByteWriter(mcs.Length + 6);
        x224.U8(0);                        // length indicator
        x224.U8(Rdp.X224ConnectionRequest);
        x224.U16(0x0000);                  // destination reference
        x224.U16(0x0000);                  // source reference
        x224.U8(0x00);                     // class option
        return Negotiation.Tpkt(x224.Bytes(mcs).ToArray());
    }

    public sealed record ConnectResponse(
        bool Success,
        byte Result,
        byte? ConferenceResult,
        ushort? UserId,
        ushort? Token,
        ushort? ServerNodeId,
        ushort? ServerNonce,
        ushort? LabelId,
        string Summary,
        byte[] Raw);

    /// <summary>
    /// Parse an MCS Connect Response (MS-RDPBCGR 2.2.1.3.5).
    /// </summary>
    public static ConnectResponse ParseConnectResponse(byte[] buffer)
    {
        var r = new ByteReader(buffer);

        // Tolerate an X.224 wrapper: a leading 0xF0 data TPDU followed by a
        // 2-byte length indicator.
        int offset = 0;
        if (r.Remaining > 2 && r.PeekRest()[0] == Rdp.X224Data)
        {
            r.Skip(1);
            int li = r.U8();
            r.Skip(li); // li counts itself plus the EOFI/consumed bytes
            offset = r.Offset;
        }

        r.Seek(offset);
        byte result = r.U8();

        if (result != 0)
        {
            return new ConnectResponse(
                false, result, null, null, null, null, null, null,
                $"MCS Connect Response result {result}: connection refused", buffer);
        }

        if (r.Remaining < 2)
        {
            return new ConnectResponse(
                true, result, null, null, null, null, null, null,
                "MCS Connect Response accepted but carried no Connect Data", buffer);
        }

        int connectDataLength = r.U16();
        r.Seek(r.Offset + connectDataLength);
        if (r.Remaining < 1)
        {
            return new ConnectResponse(
                true, result, null, null, null, null, null, null,
                "MCS Connect Response accepted; Connect Data empty", buffer);
        }

        byte t124 = r.U8();
        int t124Length = r.U8();
        r.Skip(2); // t124 identifier padding
        if (r.Remaining < 6)
        {
            return new ConnectResponse(
                true, result, null, null, null, null, null, null,
                $"MCS accepted; T.124 identifier {t124}, Connect Data too short", buffer);
        }

        byte conferenceResult = r.U8();
        ushort userId = r.U16();
        ushort token = r.U16();

        ushort? serverNodeId = null;
        ushort? serverNonce = null;
        ushort? labelId = null;

        // The trailing three variable fields are present on a successful
        // conference create; a failed one stops after the fixed header.
        if (conferenceResult == 0 && r.Remaining >= 2)
        {
            int len = r.U16();
            if (len == 2 && r.Remaining >= 2) { serverNodeId = r.U16(); }
        }

        if (conferenceResult == 0 && r.Remaining >= 2)
        {
            int len = r.U16();
            if (len == 2 && r.Remaining >= 2) { serverNonce = r.U16(); }
        }

        if (conferenceResult == 0 && r.Remaining >= 2)
        {
            int len = r.U16();
            if (len == 2 && r.Remaining >= 2) { labelId = r.U16(); }
        }

        string summary =
            $"MCS accepted (conference {conferenceResult}), UserID {userId}, token 0x{token:x4}";
        if (serverNodeId is not null) summary += $", ServerNodeID {serverNodeId}";
        if (serverNonce is not null) summary += $", ServerNonce {serverNonce}";
        if (labelId is not null) summary += $", LabelID {labelId}";

        return new ConnectResponse(
            conferenceResult == 0, result, conferenceResult, userId, token,
            serverNodeId, serverNonce, labelId, summary, buffer);
    }

    /// <summary>Build an MCS Erect Domain Request (MS-RDPBCGR 2.2.1.3.6.1).</summary>
    public static byte[] BuildErectDomainRequest(ushort initiator, params ushort[] domainIds)
    {
        var w = new ByteWriter(16 + domainIds.Length * 2);
        w.U8(Rdp.McsErectDomainRequestPdu);
        w.U8(0); // initiator is declared but always sent as zero
        w.U16(initiator);
        w.U16((ushort)domainIds.Length);
        foreach (ushort id in domainIds)
        {
            w.U16(id);
        }

        return w.ToArray();
    }

    /// <summary>Build an MCS Attach User Request (MS-RDPBCGR 2.2.1.3.7).</summary>
    public static byte[] BuildAttachUserRequest(ushort initiator, ushort userId)
    {
        var w = new ByteWriter(8);
        w.U8(Rdp.McsAttachUserRequestPdu);
        w.U8(0);
        w.U16(initiator);
        w.U16(userId);
        return w.ToArray();
    }

    /// <summary>Build an MCS Channel Join Request (MS-RDPBCGR 2.2.1.3.8).</summary>
    public static byte[] BuildChannelJoinRequest(ushort initiator, ushort channelId, ushort userId)
    {
        var w = new ByteWriter(10);
        w.U8(Rdp.McsChannelJoinRequestPdu);
        w.U8(0);
        w.U16(initiator);
        w.U16(channelId);
        w.U16(userId);
        return w.ToArray();
    }

    /// <summary>
    /// Wrap a server data PDU in an MCS Send Data Indication.
    /// </summary>
    /// <remarks>
    /// The frame is sent in 1600-byte chunks, each carrying up to 1598 bytes of
    /// payload after the 2-byte fragmentation length.
    /// </remarks>
    public static IReadOnlyList<byte[]> BuildSendDataRequest(
        ushort initiator, ushort channelId, byte[] payload, int chunkSize = 1598)
    {
        if (payload.Length == 0)
        {
            throw new ArgumentException("payload must not be empty", nameof(payload));
        }

        var frames = new List<byte[]>();
        for (int offset = 0; offset < payload.Length; offset += chunkSize)
        {
            int length = Math.Min(chunkSize, payload.Length - offset);
            var w = new ByteWriter(length + 12);
            w.U8(Rdp.McsSendDataRequestPdu);
            w.U8(0);
            w.U16(initiator);
            w.U16(channelId);
            w.U16((ushort)(length + 2));
            w.Bytes(payload.AsSpan(offset, length));
            frames.Add(w.ToArray());
        }

        return frames;
    }
}