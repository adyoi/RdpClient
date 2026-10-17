namespace RdpClient.Protocol;

/// <summary>
/// MCS connection and channel primitives (MS-RDPBCGR 2.2.1.3 - 2.2.1.9).
/// </summary>
/// <remarks>
/// MCS is the T.125 presentation layer that carries GCC and the rest of the
/// connection. After Connect Initial/Response the client must erect the server
/// domain, attach itself as a user, and join its channels before any
/// application data can flow.
/// <para>
/// The section numbers matter and were wrong here for a long time. 2.2.1.3 is
/// the Connect Initial and its 2.2.1.3.x subsections are the client data blocks
/// inside it; the MCS domain PDUs are 2.2.1.5 (Erect Domain Request), 2.2.1.6
/// and 2.2.1.7 (Attach User Request and Confirm) and 2.2.1.8 and 2.2.1.9
/// (Channel Join Request and Confirm).
/// </para>
/// </remarks>
public static class Mcs
{
    /// <summary>
    /// Build the GCC Conference Create Request (MS-RDPBCGR 2.2.1.3).
    /// </summary>
    /// <remarks>
    /// The byte layout was confirmed against <c>mstscax.dll</c>, the COM control
    /// that holds the RDP client logic, where this structure is assembled as
    /// immediates rather than as a data table: <c>00 05 00 14 7c 00 01</c>, the
    /// PER length, <c>00 08 00 10 00 01 c0 00 44 75 63 61</c>, the PER length of
    /// the client data, then the blocks copied verbatim.
    /// </remarks>
    public static byte[] BuildConferenceCreateRequest(
        byte[] clientData,
        string conferenceName = Rdp.McsConferenceName)
    {
        ArgumentNullException.ThrowIfNull(clientData);
        ArgumentNullException.ThrowIfNull(conferenceName);

        // Twelve octets of fixed framing follow the connectPDU length before
        // the client-data length field: the ConnectGCCPDU choice, the optional
        // selection, the conference name length and name, the padding, the set
        // count, the UserData choice, and the H.221 key length and key.
        const int ConnectPduFixedOverhead = 12;

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
        // data, twelve octets of fixed framing, and the client-data length
        // field itself.
        //
        // A fixed fourteen is wrong below 0x80, because the length of the
        // client data is part of what is being counted and takes one octet
        // there rather than two. Measured in mstscax.dll, which builds this as
        //
        //     uVar1 = (0xe - (uint)(uVar3 < 0x80)) + uVar3;
        //
        // - that is, +14 for a total at or above 0x80 and +13 below it. The
        // two agree everywhere, including where the total crosses 0x80 while
        // the client data does not, so this states it as the width of the
        // field actually being added.
        int connectPduLength = clientData.Length
            + ConnectPduFixedOverhead
            + Asn1.PerLengthOctets(clientData.Length);

        Asn1.WritePerLength(w, connectPduLength);

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
    /// Build the T.125 Connect-Initial (MS-RDPBCGR 2.2.1.3).
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
    /// Wrap a Connect Initial in the X.224 Data TPDU envelope (MS-RDPBCGR 2.2.1.3).
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
    /// Parse an MCS Connect Response (MS-RDPBCGR 2.2.1.4).
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
    /// user data (MS-RDPBCGR 2.2.1.4).
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
        // length followed by five octets, so six in total). Counting the
        // identifier as five octets leaves the cursor one short and reads the
        // user id from the wrong place.
        int cursor = 1 + 6;
        if (g.Length < cursor + 1)
        {
            problem = "truncated before the connectPDU length";
            return false;
        }

        // The connectPDU length is ignored, but it still occupies one or two
        // octets. Stepping over a fixed single octet desynchronises the cursor
        // whenever a server writes the two-octet form, and every field after it
        // is then read from the wrong offset.
        if (!Asn1.TryReadPerLength(g[cursor..], out _, out int ignoredSize) || ignoredSize == 0)
        {
            problem = "truncated before the ConnectGCCPDU choice";
            return false;
        }

        cursor += ignoredSize;
        if (g.Length < cursor + 1)
        {
            problem = "truncated before the ConnectGCCPDU choice";
            return false;
        }

        cursor++;                                          // ConnectGCCPDU choice
        if (g.Length < cursor + 2)
        {
            problem = "truncated before the node id";
            return false;
        }

        // nodeID, a PER integer relative to the base channel id.
        userId = (ushort)(((g[cursor] << 8) | g[cursor + 1]) + Rdp.McsUserChannelBase);
        nodeId = userId;

        return true;
    }

    /// <summary>Build an MCS Erect Domain Request (MS-RDPBCGR 2.2.1.5).</summary>
    /// <remarks>
    /// <para>
    /// Wrapped in TPKT and an X.224 Data TPDU. Every MCS domain PDU the client
    /// sends after the Connect Initial travels in that envelope; only the
    /// Connect Initial itself is framed differently, because it is an
    /// [APPLICATION 101] structure rather than a DomainMCSPDU choice.
    /// </para>
    /// <para>
    /// The two trailing fields are subHeight and subInterval, both PER-encoded
    /// INTEGERs. A PER integer carries its own length determinant, so a zero is
    /// the two octets <c>01 00</c> and not a bare <c>00</c> - writing the value
    /// alone leaves the reader one octet short.
    /// </para>
    /// </remarks>
    public static byte[] BuildErectDomainRequest() =>
        BuildDomainPdu(
            Rdp.McsOpcode(Rdp.McsChoiceErectDomainRequest),
            [0x01, 0x00,   // subHeight = 0, as a PER length plus its value
             0x01, 0x00]); // subInterval = 0

    /// <summary>Build an MCS Attach User Request (MS-RDPBCGR 2.2.1.6).</summary>
    /// <remarks>
    /// The PDU has no fields of its own: T.125 puts the assigned user id in the
    /// server's Attach User Confirm, not in the request. The only octets are
    /// the DomainMCSPDU choice.
    /// </remarks>
    public static byte[] BuildAttachUserRequest() =>
        BuildDomainPdu(Rdp.McsOpcode(Rdp.McsChoiceAttachUserRequest), []);

    /// <summary>Build an MCS Channel Join Request (MS-RDPBCGR 2.2.1.8).</summary>
    /// <remarks>
    /// A client sends one of these per static virtual channel it offered, plus one
    /// for the MCS user channel and one for the global channel. xrdp counts
    /// exactly that: <c>channel_list-&gt;count + 2</c>.
    /// </remarks>
    /// <param name="userId">
    /// The user id the server assigned in its Attach User Confirm. It is a PER
    /// INTEGER relative to the MCS base channel id of 1001, so 1001 itself is
    /// written as <c>00 00</c>. A conventional 1001 is not a substitute: the
    /// server rejects a join request whose initiator is not the user it
    /// attached.
    /// </param>
    /// <param name="channelId">The channel to join.</param>
    public static byte[] BuildChannelJoinRequest(ushort userId, ushort channelId)
    {
        if (userId < Rdp.McsUserChannelBase)
        {
            throw new ArgumentOutOfRangeException(
                nameof(userId), userId,
                $"a dynamic channel id must be at least {Rdp.McsUserChannelBase}");
        }

        var payload = new ByteWriter(6);
        payload.U16BigEndian(userId - Rdp.McsUserChannelBase);   // initiator, PER-relative
        payload.U16BigEndian(channelId);
        return BuildDomainPdu(Rdp.McsOpcode(Rdp.McsChoiceChannelJoinRequest), payload.ToArray());
    }

    /// <summary>
    /// Frame a DomainMCSPDU: TPKT header, X.224 Data TPDU, then the opcode.
    /// </summary>
    /// <param name="opcode">
    /// The choice octet, from <see cref="Rdp.McsOpcode"/>. The top six bits are
    /// the DomainMCSPDU choice and the low two are the option bits.
    /// </param>
    /// <param name="payload">The fields that follow the opcode.</param>
    private static byte[] BuildDomainPdu(byte opcode, byte[] payload)
    {
        // TPKT(4) + X.224 Data TPDU(3) + opcode(1) + payload
        var x224 = new ByteWriter(payload.Length + 4);
        x224.U8(2);                       // length indicator: the LI octet and the DT code
        x224.U8(Rdp.X224Data);
        x224.U8(0x80);                    // EOT, TPDU-NR 0
        x224.U8(opcode);
        x224.Bytes(payload);
        return Negotiation.Tpkt(x224.ToArray());
    }

    public sealed record DomainPdu(byte Opcode, int Choice, byte[] Payload, byte[] Raw);

    /// <summary>
    /// Read one DomainMCSPDU: TPKT header, X.224 Data TPDU, then the opcode.
    /// </summary>
    /// <remarks>
    /// The choice index is the opcode's top six bits. Reading the opcode as the
    /// choice without the shift is why the whole DomainMCSPDU set was once
    /// misidentified.
    /// </remarks>
    public static DomainPdu ParseDomainPdu(byte[] buffer)
    {
        ArgumentNullException.ThrowIfNull(buffer);

        var r = new ByteReader(buffer);
        int version = r.U8();
        r.Skip(1);                                   // TPKT reserved
        int length = r.U16BigEndian();

        if (version != Rdp.TpktVersion)
        {
            throw new InvalidDataException($"unexpected TPKT version {version}");
        }

        if (length != buffer.Length)
        {
            throw new InvalidDataException(
                $"TPKT length {length} disagrees with the {buffer.Length} bytes received");
        }

        r.Skip(3);                                   // length indicator, DT code, EOT
        byte opcode = r.U8();

        return new DomainPdu(opcode, opcode >> 2, r.PeekRest().ToArray(), buffer);
    }

    /// <summary>
    /// Parse an Attach User Confirm (MS-RDPBCGR 2.2.1.7).
    /// </summary>
    /// <remarks>
    /// Returns the assigned user id, which is the value the Channel Join Request
    /// must carry: a conventional 1001 is not a substitute, because the server
    /// rejects a join whose initiator is not the user it attached. It is null
    /// when the server refused.
    /// <para>
    /// The id arrives as a PER integer relative to the base channel id, so it is
    /// read as big-endian with 1001 added back.
    /// </para>
    /// </remarks>
    /// <param name="buffer">One TPKT-framed DomainMCSPDU.</param>
    /// <param name="expectedResult">The MCS result that means success, normally 0.</param>
    public static (bool Success, ushort? UserId, string Summary) ParseAttachUserConfirm(
        byte[] buffer, int expectedResult = 0)
    {
        var pdu = ParseDomainPdu(buffer);
        if (pdu.Choice != Rdp.McsChoiceAttachUserConfirm)
        {
            return (false, null,
                $"expected an Attach User Confirm (choice {Rdp.McsChoiceAttachUserConfirm}), "
                + $"got choice {pdu.Choice}");
        }

        var r = new ByteReader(pdu.Payload);
        byte result = r.U8();
        if (result != expectedResult)
        {
            return (false, null, $"MCS refused the attach: result {result}");
        }

        // T.125 declares the initiator OPTIONAL and the opcode's low bit is what
        // says whether it is present. A server that omits it attached nobody by
        // name, and there is then no id to join a channel with.
        if ((pdu.Opcode & 0x02) == 0 || r.Remaining < 2)
        {
            return (false, null, "the Attach User Confirm carried no user id");
        }

        ushort assigned = (ushort)(r.U16BigEndian() + Rdp.McsUserChannelBase);
        return (true, assigned, $"attached as MCS user {assigned}");
    }

    /// <summary>
    /// Parse a Channel Join Confirm (MS-RDPBCGR 2.2.1.9).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The result alone is not enough to call this a success. The Confirm also
    /// names the channel the server actually joined, and if that is not the
    /// channel the client asked for then the join this code is about to report
    /// did not happen - which is the same "reported success it never verified"
    /// failure the rest of this connection sequence was rewritten to avoid.
    /// </para>
    /// <para>
    /// What the two opcode option bits mean is per-PDU, and they are not
    /// interchangeable between the Confirms. In the Attach User Confirm 0x02
    /// says the initiator is present; in the Channel Join Confirm xrdp writes
    /// the same bit for <c>channelId</c> and says so in its own comment, having
    /// written initiator and requested unconditionally alongside it. So
    /// initiator and requested are stepped over here unconditionally, and
    /// channelId is only read when 0x02 is set.
    /// </para>
    /// </remarks>
    /// <param name="buffer">One TPKT-framed DomainMCSPDU.</param>
    /// <param name="expectedChannel">
    /// The channel the client asked to join, or null to accept whatever the
    /// server names.
    /// </param>
    /// <param name="expectedResult">The MCS result that means success, normally 0.</param>
    public static (bool Success, ushort? ChannelId, string Summary) ParseChannelJoinConfirm(
        byte[] buffer, ushort? expectedChannel = null, int expectedResult = 0)
    {
        var pdu = ParseDomainPdu(buffer);
        if (pdu.Choice != Rdp.McsChoiceChannelJoinConfirm)
        {
            return (false, null,
                $"expected a Channel Join Confirm (choice {Rdp.McsChoiceChannelJoinConfirm}), "
                + $"got choice {pdu.Choice}");
        }

        var r = new ByteReader(pdu.Payload);
        byte result = r.U8();
        if (result != expectedResult)
        {
            return (false, null, $"MCS refused the channel join: result {result}");
        }

        r.Skip(2);                                   // initiator
        r.Skip(2);                                   // requested

        // 0x02 marks the optional channelId field as present. Reading past the
        // payload when it is absent produced a channel id out of thin air.
        if ((pdu.Opcode & 0x02) == 0)
        {
            return (false, null,
                "the Channel Join Confirm carries no channel id, so there is "
                + "nothing to show that the requested channel was joined");
        }

        if (r.Remaining < 2)
        {
            return (false, null, "the Channel Join Confirm ended before its channel id");
        }

        ushort channel = r.U16BigEndian();
        if (expectedChannel is { } wanted && channel != wanted)
        {
            return (false, channel,
                $"the server joined MCS channel {channel} but {wanted} was requested");
        }

        return (true, channel, $"joined MCS channel {channel}");
    }

    /// <summary>
    /// One MCS Send Data Indication: a fragment of application data the server
    /// sent on a channel.
    /// </summary>
    /// <remarks>
    /// This is how every server-to-client PDU after the channel joins arrives.
    /// It carries a fragmentation field, so a Demand Active PDU larger than one
    /// fragment arrives as several of these and has to be reassembled before it
    /// can be parsed.
    /// </remarks>
    public sealed record SendDataIndication(
        ushort ChannelId, byte Segmentation, int FragmentLength, byte[] Payload);

    /// <summary>Segmentation value marking the final fragment of a multi-fragment PDU.</summary>
    public const byte SegmentationLast = 0x03;

    /// <summary>Segmentation value for a PDU that fits in one fragment.</summary>
    public const byte SegmentationSingle = 0x00;

    /// <summary>
    /// Upper bound on the fragments reassembled into one PDU.
    /// </summary>
    /// <remarks>
    /// A slow-path PDU is capped well below the MCS maximum, so anything past
    /// this is a PDU that is not being reassembled correctly. Without a bound a
    /// wrong segmentation value is indistinguishable from a slow server, and the
    /// read simply never finishes.
    /// </remarks>
    public const int MaxSendDataFragments = 256;

    /// <summary>
    /// Parse an MCS Send Data Indication (MS-RDPBCGR 2.2.1.10.1, T.125 8.4.2).
    /// </summary>
    public static SendDataIndication ParseSendDataIndication(byte[] buffer)
    {
        var pdu = ParseDomainPdu(buffer);
        if (pdu.Choice != Rdp.McsChoiceSendDataIndication)
        {
            throw new InvalidDataException(
                $"expected a Send Data Indication (choice {Rdp.McsChoiceSendDataIndication}), "
                + $"got choice {pdu.Choice}");
        }

        var r = new ByteReader(pdu.Payload);
        r.Skip(2);                                   // initiator
        ushort channel = r.U16BigEndian();
        byte dataPriority = r.U8();

        // priority(1 bit) | segmentation(2 bits) | then reserved. Only the
        // segmentation field decides whether more fragments follow.
        byte segmentation = (byte)((dataPriority >> 5) & 0x03);

        int fragmentLength = r.U16();
        if (fragmentLength < 2)
        {
            throw new InvalidDataException(
                $"a Send Data Indication fragment length must cover its own field, got {fragmentLength}");
        }

        int dataLength = fragmentLength - 2;
        if (r.Remaining < dataLength)
        {
            throw new InvalidDataException(
                $"the Send Data Indication declares a {dataLength}-octet fragment but only "
                + $"{r.Remaining} octets remain");
        }

        return new SendDataIndication(channel, segmentation, dataLength, r.Bytes(dataLength));
    }

    /// <summary>
    /// Wrap a server data PDU in an MCS Send Data Request, chunked.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Send Data Request is a DomainMCSPDU like the three above, so it carries
    /// the same TPKT and X.224 Data TPDU envelope and the same choice-shifted
    /// opcode. A frame without that framing is not an MCS PDU at all.
    /// </para>
    /// <para>
    /// The frame is chunked at 1598 bytes of payload, which is what leaves the
    /// resulting PDU inside the 1600-byte maximum an MCS domain declares.
    /// </para>
    /// </remarks>
    /// <param name="userId">The initiator, as a dynamic channel id (>= 1001).</param>
    /// <param name="channelId">The channel to send on.</param>
    /// <param name="payload">The bytes to send. Must not be empty.</param>
    /// <param name="chunkSize">Payload bytes per frame, 1598 by default.</param>
    public static IReadOnlyList<byte[]> BuildSendDataRequest(
        ushort userId, ushort channelId, byte[] payload, int chunkSize = 1598)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if (payload.Length == 0)
        {
            throw new ArgumentException("payload must not be empty", nameof(payload));
        }

        if (userId < Rdp.McsUserChannelBase)
        {
            throw new ArgumentOutOfRangeException(
                nameof(userId), userId,
                $"a dynamic channel id must be at least {Rdp.McsUserChannelBase}");
        }

        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize), chunkSize, "chunk size must be positive");
        }

        var frames = new List<byte[]>();
        for (int offset = 0; offset < payload.Length; offset += chunkSize)
        {
            int length = Math.Min(chunkSize, payload.Length - offset);

            var w = new ByteWriter(length + 12);
            w.U16BigEndian(userId - Rdp.McsUserChannelBase);   // initiator, PER-relative
            w.U16BigEndian(channelId);
            w.U8(0x70);                                        // dataPriority low, no segmentation
            w.U16((ushort)(length + 2));                       // lengthPerFragment, including itself
            w.Bytes(payload.AsSpan(offset, length));
            frames.Add(BuildDomainPdu(Rdp.McsOpcode(Rdp.McsChoiceSendDataRequest), w.ToArray()));
        }

        return frames;
    }
}