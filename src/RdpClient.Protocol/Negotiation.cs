using System.Buffers.Binary;

namespace RdpClient.Protocol;

/// <summary>
/// X.224/T.125 connection sequence and the RDP Negotiation exchange.
/// </summary>
/// <remarks>
/// MS-RDPBCGR 2.2.1.1 folds the T.125 Connection Request and the RDP_NEG_REQ
/// into one PDU. Everything before MCS happens here, so this type also owns
/// TPKT framing.
/// </remarks>
public static class Negotiation
{
    /// <summary>Size of the TPKT header: version, reserved, 16-bit length.</summary>
    private const int TpktHeaderLength = 4;

    /// <summary>
    /// Declared size of RDP_CORRELATION_INFO (MS-RDPBCGR 2.2.1.1.2).
    /// </summary>
    /// <remarks>
    /// The structure's own length field is 36, which is larger than the sum of
    /// the fields it lists, so a conforming sender has to pad. See the comment
    /// at the write site for the evidence.
    /// </remarks>
    public const int CorrelationInfoLength = 36;

    /// <summary>
    /// Wrap a payload in a TPKT version 3 header.
    /// </summary>
    /// <remarks>
    /// TPKT (RFC 1006, cited as [T123] section 8) is
    /// <c>version(1) | reserved(1) | length(2)</c>. The length counts the whole
    /// datagram including this header, and is the <em>only</em> big-endian field
    /// in the RDP connection sequence — everything inside TPKT is
    /// little-endian. MS-RDPBCGR 3.3.5.3.1 requires the server to verify the
    /// embedded length fields agree with the data, and it drops the connection
    /// when they do not, so getting this wrong looks like an instant reset.
    /// </remarks>
    public static byte[] Tpkt(ReadOnlySpan<byte> payload)
    {
        int total = payload.Length + TpktHeaderLength;
        if (total > Rdp.TpktMaxLength)
        {
            throw new ArgumentException(
                $"X.224 payload of {payload.Length} bytes exceeds the 7-bit length octet", nameof(payload));
        }

        var w = new ByteWriter(total);
        w.U8(Rdp.TpktVersion);
        w.U8(0x00);            // reserved
        w.U16BigEndian(total);
        return w.Bytes(payload).ToArray();
    }

    /// <summary>
    /// Build the class 0 X.224 Connection Request TPDU (X.224 section 3.3).
    /// </summary>
    /// <remarks>
    /// X.224 puts the length indicator <em>before</em> the TPDU code, unlike TPKT
    /// where the length is last. <paramref name="lengthIndicator"/> counts the
    /// LI octet itself plus the fixed header and user data that follow.
    /// </remarks>
    private static byte[] X224ConnectionRequest(int lengthIndicator, ReadOnlySpan<byte> payload)
    {
        var x224 = new ByteWriter(payload.Length + 6);
        x224.U8(lengthIndicator);
        x224.U8(Rdp.X224ConnectionRequest);
        x224.U16(0x0000);    // destination reference
        x224.U16(0x0000);    // source reference
        x224.U8(0x00);       // class option: class 0
        return Tpkt(x224.Bytes(payload).ToArray());
    }

    /// <summary>
    /// Build the X.224 Connection Request carrying an RDP_NEG_REQ.
    /// </summary>
    /// <param name="requestedProtocols">
    /// SelectedProtocol candidate bitmask. <see cref="Rdp.ProtocolSsl"/> is sent
    /// alongside <see cref="Rdp.ProtocolHybrid"/> so the server may pick either.
    /// </param>
    /// <param name="correlationId">
    /// Optional 16-byte vector. When supplied the server echoes it back, which
    /// lets the client confirm it reached a real RDP endpoint rather than a
    /// port redirector that answers 3389 with something else. Supplying it also
    /// raises the CORRELATION_INFO_PRESENT flag, which MS-RDPBCGR 2.2.1.1.1
    /// requires whenever the block is appended.
    /// </param>
    public static byte[] BuildConnectionRequest(uint requestedProtocols, byte[]? correlationId = null)
    {
        // MS-RDPBCGR 2.2.1.1.1: the CORRELATION_INFO_PRESENT flag must be set
        // whenever the optional correlation block follows the base request.
        byte flags = correlationId is not null
            ? (byte)Rdp.NegRspFlags.CorrelationInfoPresent
            : (byte)0;

        var neg = new ByteWriter(64);
        neg.U8(Rdp.NegReqTypeRdpConnectionReq);
        neg.U8(flags);
        neg.U16(8);
        neg.U32(requestedProtocols);

        if (correlationId is not null)
        {
            // MS-RDPBCGR 2.2.1.1.1: RDP_CORRELATION_INFO follows the base request.
            if (correlationId.Length != 16)
            {
                throw new ArgumentException("correlationId must be 16 bytes", nameof(correlationId));
            }

            int start = neg.Length;
            neg.U8(Rdp.NegReqTypeCorrelationInfo);
            neg.U8(0x00);
            neg.U16(CorrelationInfoLength);
            neg.Bytes(correlationId);
            neg.U16(0x0001); // RPC_CORRELATION_VECTOR_INFO1
            neg.U16(0x0000); // Reserved

            // The fields above occupy 24 octets but the structure declares 36,
            // so the bytes present must cover the length the client itself
            // writes. xrdp walks 35 octets after the type and aborts the
            // connection when they are not there:
            //
            //   Parsing [MS-RDPBCGR] RDP_NEG_CORRELATION_INFO Not enough bytes
            //   in the stream: expected 35, remaining 23
            //
            // Windows tolerates the short form, which is why this survived: a
            // capture of mstsc.exe shows it never sends the block at all, so
            // there is no Windows-side evidence to contradict xrdp.
            while (neg.Length - start < CorrelationInfoLength)
            {
                neg.U8(0x00);
            }
        }

        byte[] negBytes = neg.ToArray();

        // LI counts itself, the TPDU code, the two references and the class
        // option, plus everything the client appends (MS-RDPBCGR 2.2.1.1).
        int lengthIndicator = 6 + negBytes.Length;
        return X224ConnectionRequest(lengthIndicator, negBytes);
    }

    /// <summary>Build a T.125 Disconnect Request to close a connection politely.</summary>
    public static byte[] BuildDisconnectRequest()
    {
        var x224 = new ByteWriter(5);
        x224.U8(0x06);    // length indicator
        x224.U8(Rdp.X224DisconnectRequest);
        x224.U16(0x0000); // destination reference
        x224.U16(0x0000); // source reference
        x224.U8(0x80);    // reason: not specified
        return Tpkt(x224.ToArray());
    }

    public sealed record ConnectionConfirm(
        bool Failed,
        byte? Type,
        byte? Flags,
        uint? NegotiatedVersion,
        uint? SelectedProtocol,
        byte[]? CorrelationId,
        byte? CorrelationType,
        uint? FailureCode,
        string Summary,
        byte[] Raw);

    /// <summary>
    /// Parse an X.224 Connection Confirm and the RDP_NEG_RSP it carries.
    /// </summary>
    /// <remarks>
    /// A server that refuses negotiation answers with a T.125 Negotiate Failure
    /// and no RDP_NEG_RSP. That is a normal protocol outcome, so it is reported
    /// as <c>Failed</c> rather than thrown.
    /// </remarks>
    public static ConnectionConfirm ParseConnectionConfirm(byte[] buffer)
    {
        var r = new ByteReader(buffer);

        if (r.Remaining < 7)
        {
            throw new InvalidDataException($"connection confirm too short: {r.Remaining} bytes");
        }

        int version = r.U8();
        r.Skip(1);                  // reserved
        int length = r.U16BigEndian();
        // X.224 puts the length indicator before the TPDU code, unlike TPKT where the
        // length is last.
        byte li = r.U8();
        byte x224Type = r.U8();

        if (version != Rdp.TpktVersion)
        {
            throw new InvalidDataException($"unexpected TPKT version {version}");
        }

        if (length != buffer.Length)
        {
            throw new InvalidDataException(
                $"TPKT length {length} disagrees with the {buffer.Length} bytes received");
        }

        if (x224Type != Rdp.X224ConnectionConfirm)
        {
            return new ConnectionConfirm(
                Failed: true, Type: null, Flags: null, NegotiatedVersion: null,
                SelectedProtocol: null, CorrelationId: null, CorrelationType: null,
                FailureCode: null, Summary: $"X.224 type 0x{x224Type:x2} is not a Connection Confirm",
                Raw: buffer);
        }

        // Having already consumed the TPDU code, five bytes remain of the fixed X.224
        // header: destination reference (2), source reference (2), class
        // option (1). Skip those rather than trusting li: RDP servers send
        // li = 0x0E regardless of what actually follows, so an li-driven skip
        // overshoots the RDP_NEG_RSP entirely.
        _ = li;
        r.Skip(5);

        if (r.Remaining == 0)
        {
            return new ConnectionConfirm(
                Failed: true, Type: null, Flags: null, NegotiatedVersion: null,
                SelectedProtocol: null, CorrelationId: null, CorrelationType: null,
                FailureCode: null, Summary: "T.125 Connection Confirm with no RDP_NEG_RSP: negotiation refused",
                Raw: buffer);
        }

        return ParseNegotiationResponse(r, buffer);
    }

    private static ConnectionConfirm ParseNegotiationResponse(ByteReader r, byte[] buffer)
    {
        byte type = r.U8();
        if (type is not (Rdp.NegRspTypeRdpConnectionResp or Rdp.NegRspTypeRdpConnectionFailure))
        {
            return new ConnectionConfirm(
                Failed: true, Type: type, Flags: null, NegotiatedVersion: null,
                SelectedProtocol: null, CorrelationId: null, CorrelationType: null,
                FailureCode: null, Summary: $"unexpected RDP_NEG_RSP type 0x{type:x2}",
                Raw: buffer);
        }

        byte flags = r.U8();
        int rspLength = r.U16();
        if (rspLength < 8)
        {
            throw new InvalidDataException($"RDP_NEG_RSP length {rspLength} is below the 8-byte minimum");
        }

        if (type == Rdp.NegRspTypeRdpConnectionFailure)
        {
            uint failureCode = r.U32();
            return new ConnectionConfirm(
                Failed: true, Type: type, Flags: flags, NegotiatedVersion: null,
                SelectedProtocol: null, CorrelationId: null, CorrelationType: null,
                FailureCode: failureCode, Summary: $"RDP_NEG_RSP failure, code {failureCode}",
                Raw: buffer);
        }

        uint selected = r.U32();
        string summary = $"negotiated version 0x{selected:x8}, SelectedProtocol 0x{selected:x8}";

        byte[]? correlation = null;
        byte? correlationType = null;
        if (rspLength >= 36)
        {
            correlationType = r.U8();
            r.Skip(3); // reserved
            correlation = r.Bytes(16);
            summary += ", correlation echoed";
        }

        return new ConnectionConfirm(
            Failed: false, Type: type, Flags: flags, NegotiatedVersion: selected,
            SelectedProtocol: selected, CorrelationId: correlation,
            CorrelationType: correlationType, FailureCode: null, Summary: summary, Raw: buffer);
    }

    /// <summary>Render a SelectedProtocol bitmask as readable names.</summary>
    public static string DescribeSelectedProtocol(uint mask) => mask switch
    {
        Rdp.ProtocolSsl => "SSL",
        Rdp.ProtocolHybrid => "HYBRID (CredSSP/NLA)",
        Rdp.ProtocolHybridEx => "HYBRID_EX",
        Rdp.ProtocolRdsaad => "RDSAAD",
        _ => DescribeBits(mask),
    };

    private static string DescribeBits(uint mask)
    {
        var parts = new List<string>();
        if ((mask & Rdp.ProtocolSsl) != 0) parts.Add("SSL");
        if ((mask & Rdp.ProtocolHybrid) != 0) parts.Add("HYBRID/NLA");
        if ((mask & Rdp.ProtocolRdstls) != 0) parts.Add("RDSTLS");
        if ((mask & Rdp.ProtocolHybridEx) != 0) parts.Add("HYBRID_EX");
        if ((mask & Rdp.ProtocolRdsaad) != 0) parts.Add("RDSAAD");
        return parts.Count > 0 ? string.Join(" | ", parts) : $"0x{mask:x8} (no recognised bit)";
    }
}