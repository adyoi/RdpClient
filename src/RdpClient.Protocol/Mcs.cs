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
    public static byte[] BuildConferenceCreateRequest(
        byte[] clientData,
        string conferenceName = Rdp.McsConferenceName)
    {
        ArgumentNullException.ThrowIfNull(clientData);
        ArgumentNullException.ThrowIfNull(conferenceName);

        var w = new ByteWriter(clientData.Length + 32);

        // From Key: select the OBJECT_IDENTIFIER alternative.
        w.U8(0x00);

        // ITU-T T.124 (02/98): five octets, the first two combined as 0*40+0.
        w.U8(0x05);
        w.U8(0x00);
        w.U8(0x14);
        w.U8(0x7C);
        w.U8(0x00);
        w.U8(0x01);

        // connectPDU length: everything after this field, which is the client
        // data plus fourteen octets of framing.
        const int ConnectPduOverhead = 14;
        Asn1.WritePerLength(w, clientData.Length + ConnectPduOverhead);

        // ConnectGCCPDU: conferenceCreateRequest, then its optional userData.
        w.U8(0x00);
        w.U8(0x08);

        // The name is a numeric string here: digit pairs packed one per octet,
        // so "1" is 0x10 rather than 0x01.
        Asn1.WritePerNumericString(w, conferenceName, minimum: 1);
        w.U8(0x00);            // padding to the next octet boundary
        w.U8(0x01);            // one set of user data follows

        // UserData: value present, h221NonStandard selected. The Duca key marks
        // the block as the client-to-server H.221 extension; a server that does
        // not know it ignores the block instead of refusing the connection.
        w.U8(0xC0);
        Asn1.WritePerOctetString(w, "Duca"u8.ToArray(), minimum: 4);

        Asn1.WritePerOctetString(w, clientData, minimum: 0);
        return w.ToArray();
    }

    public sealed record ConnectInitialOptions
    {
        /// <summary>TS_UD_CS_CORE, TS_UD_CS_SECURITY, TS_UD_CS_NET and friends, concatenated.</summary>
        public required byte[] ClientInfo { get; init; }

        public string ConferenceName { get; init; } = "1";

        public McsDomainParameters TargetParameters { get; init; } = McsDomainParameters.Target;
        public McsDomainParameters MinimumParameters { get; init; } = McsDomainParameters.Minimum;
        public McsDomainParameters MaximumParameters { get; init; } = McsDomainParameters.Maximum;
    }

    /// <summary>
    /// Build the T.125 Connect-Initial (MS-RDPBCGR 2.2.1.3.4.1).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is an ASN.1 structure, not the flat TLV it is often described as:
    /// <c>Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE</c> holding two
    /// domain selectors, an upward flag, three sets of domain parameters, and the
    /// user data. The tag goes out as <c>7f 65</c>, because 101 does not fit the
    /// five tag bits in one octet.
    /// </para>
    /// <para>
    /// Getting this wrong is silent in one direction and loud in the other: a
    /// server that names the structure it expected makes the mistake obvious,
    /// which is why the identifier is worth matching exactly.
    /// </para>
    /// </remarks>
    public static byte[] BuildConnectInitial(ConnectInitialOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        byte[] gcc = BuildConferenceCreateRequest(options.ClientInfo, options.ConferenceName);

        var body = new ByteWriter(gcc.Length + 96);

        // Both selectors are the single octet 0x01: the T.125 "domain" this
        // client belongs to.
        body.Bytes(Asn1.BerOctetString([0x01]));
        body.Bytes(Asn1.BerOctetString([0x01]));

        // upwardFlag TRUE: the client is joining, not creating a domain.
        body.Bytes(Asn1.BerBoolean(true));

        body.Bytes(BerDomainParameters(options.TargetParameters));
        body.Bytes(BerDomainParameters(options.MinimumParameters));
        body.Bytes(BerDomainParameters(options.MaximumParameters));

        // userData: the GCC Conference Create Request carrying the TS_UD_CS_*
        // client blocks.
        body.Bytes(Asn1.BerOctetString(gcc));

        return Asn1.WrapApplication(Asn1.ConnectInitialTag, body.ToArray());
    }

    private static byte[] BerDomainParameters(McsDomainParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        var body = new ByteWriter(64);
        body.Bytes(Asn1.BerInteger(parameters.MaxChannelIds));
        body.Bytes(Asn1.BerInteger(parameters.MaxUserIds));
        body.Bytes(Asn1.BerInteger(parameters.MaxTokenIds));
        body.Bytes(Asn1.BerInteger(parameters.NumPriorities));
        body.Bytes(Asn1.BerInteger(parameters.MinThroughput));
        body.Bytes(Asn1.BerInteger(parameters.MaxHeight));
        body.Bytes(Asn1.BerInteger(parameters.MaxMcsPduSize));
        body.Bytes(Asn1.BerInteger(parameters.ProtocolVersion));

        return Asn1.BerSequence(body.ToArray());
    }

    /// <summary>
    /// Wrap a Connect Initial in the X.224 Data TPDU envelope (2.2.1.3.1).
    /// </summary>
    /// <remarks>
    /// Only the negotiation request is a Connection Request TPDU. Everything
    /// after it - the Connect Initial, the Erect Domain, the Attach User, the
    /// channel join - travels in a Data TPDU, which is a different shape:
    /// LI, DT code, EOT, then the user data. A DT has no destination or source
    /// reference, so reusing the CR envelope writes five octets the server reads
    /// as payload. xrdp says so plainly:
    /// <c>xrdp_iso_recv only supports processing [ITU-T X.224] DT-TPDU (Data)
    /// headers. Received TPDU header: length indicator 0, TDPU code 0xe0</c>
    /// </remarks>
    public static byte[] BuildConnectInitialPdu(ConnectInitialOptions options)
    {
        byte[] mcs = BuildConnectInitial(options);
        return BuildDataPdu(mcs);
    }

    /// <summary>Wrap MCS application data in TPKT + X.224 Data TPDU.</summary>
    private static byte[] BuildDataPdu(byte[] payload)
    {
        var x224 = new ByteWriter(payload.Length + 3);
        x224.U8(2);                        // length indicator: LI octet and code
        x224.U8(Rdp.X224Data);
        x224.U8(0x80);                     // EOT (end of TSDU mark), TPDU-NR 0
        return Negotiation.Tpkt(x224.Bytes(payload).ToArray());
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

        // The reader is handed the whole TPKT datagram. Starting at offset 0
        // reads the TPKT version as if it were the MCS result, which is how a
        // 0x03 here became "connection refused" from a server that had
        // accepted the connection.
        r.Skip(4);

        // Then the X.224 Data TPDU, which is length indicator, DT code, EOT.
        // The code is the second octet; the first is the length indicator and
        // comparing that against the DT code never matches.
        ReadOnlySpan<byte> framed = r.PeekRest();
        if (framed.Length >= 3 && framed[1] == Rdp.X224Data)
        {
            r.Skip(3);
        }

        ReadOnlySpan<byte> payload = r.PeekRest();

        // Connect-Response ::= [APPLICATION 102] IMPLICIT SEQUENCE, so the
        // identifier is 7f 66. Reading the first payload octet as the result
        // instead reads the tag, and reports a refusal the server never made.
        if (!Asn1.TryReadHeader(payload, out byte tag, out int length, out int headerSize)
            || tag != Asn1.ConnectResponseTag)
        {
            // Naming the octets the response actually began with is what makes
            // this diagnosable; the identifier alone rarely is.
            int shown = Math.Min(payload.Length, 12);
            string seen = Convert.ToHexString(payload[..shown]).ToLowerInvariant();

            return new ConnectResponse(
                false, 0, null, null, null, null, null, null,
                $"not a Connect-Response structure: identifier {tag:x4}, wanted "
                + $"{Asn1.ConnectResponseTag:x4}; the PDU begins {seen}",
                buffer);
        }

        ReadOnlySpan<byte> body = payload.Slice(headerSize, length);

        // result ENUMERATED, then calledConnectId, domainParameters, userData.
        if (!Asn1.TryReadHeader(body, out byte resultTag, out int resultLength, out int resultHeader)
            || resultTag != Asn1.Enumerated || resultLength < 1)
        {
            return new ConnectResponse(
                false, 0, null, null, null, null, null, null,
                "the Connect-Response carries no result", buffer);
        }

        byte result = body[resultHeader];

        if (result != 0)
        {
            return new ConnectResponse(
                false, result, null, null, null, null, null, null,
                $"MCS Connect Response result {result}: connection refused", buffer);
        }

        // The user id the client attaches itself with lives in the conference
        // response inside userData, not in the calledConnectId. The two
        // fields between them are skipped by walking their BER headers.
        ReadOnlySpan<byte> rest = body[(resultHeader + resultLength)..];
        if (!TryReachUserData(rest, out ReadOnlySpan<byte> userData, out string walkProblem))
        {
            return new ConnectResponse(
                true, result, 0, null, null, null, null, null,
                $"MCS accepted but its fields were unreadable: {walkProblem}", buffer);
        }

        if (!TryParseConferenceResponse(userData, out ushort userId, out ushort? nodeId, out string problem))
        {
            return new ConnectResponse(
                true, result, 0, null, null, null, null, null,
                $"MCS accepted but the conference response was unreadable: {problem}", buffer);
        }

        string summary = $"MCS accepted (conference 0), UserID {userId}";
        if (nodeId is not null)
        {
            summary += $", ServerNodeID {nodeId}";
        }

        return new ConnectResponse(
            true, result, 0, userId, userId, nodeId, null, userId, summary, buffer);
    }

    /// <summary>
    /// Step over calledConnectId and domainParameters to reach userData.
    /// </summary>
    /// <remarks>
    /// The order is fixed by T.125, so walking two BER headers is enough; the
    /// payload of each is skipped whole, which is what makes this independent
    /// of how many domain parameters a server chooses to send.
    /// </remarks>
    private static bool TryReachUserData(
        ReadOnlySpan<byte> data,
        out ReadOnlySpan<byte> userData,
        out string problem)
    {
        userData = default;
        problem = string.Empty;

        ReadOnlySpan<byte> rest = data;
        foreach (byte expected in new[] { Asn1.Integer, Asn1.Sequence, Asn1.OctetString })
        {
            if (!Asn1.TryReadHeader(rest, out byte tag, out int length, out int headerSize)
                || tag != expected)
            {
                problem = $"expected tag {expected:x2}, found {(tag):x2}";
                return false;
            }

            if (expected == Asn1.OctetString)
            {
                userData = rest.Slice(headerSize, length);
                return true;
            }

            rest = rest[(headerSize + length)..];
        }

        problem = "userData did not appear";
        return false;
    }

    /// <summary>
    /// Read the GCC Conference Create Response inside the Connect-Response's
    /// user data (MS-RDPBCGR 2.2.1.3.3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The body is PER-encoded. One field is deliberately not trusted: the
    /// connectPDU length, which MS-RDPBCGR says the client must ignore, because
    /// servers do not agree on what it counts. Stepping over it as a
    /// variable-width field rather than a length is what makes the rest line
    /// up.
    /// </para>
    /// <para>
    /// The user id is a PER integer relative to the lowest id in use, so it
    /// arrives big-endian with no length prefix and 1001 has to be added back.
    /// </para>
    /// </remarks>
    private static bool TryParseConferenceResponse(
        ReadOnlySpan<byte> data,
        out ushort userId,
        out ushort? nodeId,
        out string problem)
    {
        userId = 0;
        nodeId = null;
        problem = string.Empty;

        ReadOnlySpan<byte> g = data;

        // From Key choice (1), then the T.124 object identifier (a one-octet
        // length followed by five octets, so six in total), then the connectPDU
        // length that must be ignored. Counting the identifier as five octets
        // leaves the cursor one short and reads the user id from the wrong
        // place.
        int cursor = 1 + 6;
        if (g.Length < cursor + 1)
        {
            problem = "truncated before the connectPDU length";
            return false;
        }

        cursor++;                                          // the ignored length
        if (g.Length < cursor + 1)
        {
            problem = "truncated before the ConnectGCCPDU choice";
            return false;
        }

        cursor++;                                          // ConnectGCCPDU choice

        if (g.Length < cursor + 2)
        {
            problem = "truncated before the user id";
            return false;
        }

        userId = (ushort)(((g[cursor] << 8) | g[cursor + 1]) + Rdp.McsUserChannelBase);
        nodeId = userId;
        cursor += 2;

        return true;
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