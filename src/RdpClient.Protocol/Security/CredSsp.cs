namespace RdpClient.Protocol.Security;

/// <summary>
/// The CredSSP envelope: the <c>TSRequest</c> ASN.1 structure that carries every
/// message inside the TLS channel once <c>PROTOCOL_HYBRID</c> is selected.
/// </summary>
/// <remarks>
/// <para>
/// MS-CSSP 2.2.1 defines the wire form as
/// <code>
/// TSRequest ::= SEQUENCE {
///   version     [0] INTEGER,
///   negoTokens  [1] NegoData OPTIONAL,
///   authInfo    [2] OCTET STRING OPTIONAL,
///   pubKeyAuth  [3] OCTET STRING OPTIONAL,
///   errorCode   [4] INTEGER OPTIONAL,
///   clientNonce [5] OCTET STRING OPTIONAL }
///
/// NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
/// </code>
/// </para>
/// <para>
/// The envelope is not optional decoration. A CredSSP server reads the first
/// bytes after the TLS handshake as a <c>TSRequest</c>; handing it a bare SPNEGO
/// or NTLM message makes the DER parse fail and the host closes the connection
/// with no diagnostic. Nothing before this layer can be diagnosed until the
/// framing is right.
/// </para>
/// <para>
/// CredSSP also does not use SPNEGO when the negotiated package is NTLM. MS-CSSP
/// 2.2.1.1 puts "one or more SPNEGO tokens <i>and all</i> Kerberos or NTLM
/// messages" in <c>negoToken</c>; the Windows implementation, confirmed by
/// decompiling <c>credssp.dll</c>, hands the output buffer of
/// <c>InitializeSecurityContextW</c> on the underlying package straight to the
/// serializer, so an NTLM message travels bare. Kerberos is the case that needs
/// a SPNEGO wrapper; NTLM is not.
/// </para>
/// </remarks>
public static class CredSsp
{
    /// <summary>
    /// The CredSSP version this client advertises.
    /// </summary>
    /// <remarks>
    /// MS-CSSP 2.2.1 permits 2 through 6. Version 5 and above bind the TLS
    /// channel with a SHA-256 hash over a client nonce (section 3.1.5 step 3)
    /// rather than encrypting the server public key, which is what the Windows
    /// RDP server negotiates today.
    /// </remarks>
    public const int ProtocolVersion = 6;

    private const byte TagInteger = 0x02;
    private const byte TagOctetString = 0x04;
    private const byte TagSequence = 0x30;

    /// <summary>
    /// Build a <c>TSRequest</c> for transmission.
    /// </summary>
    /// <param name="negoTokens">
    /// NTLM messages, in order, to place in <c>negoTokens</c>. Each becomes one
    /// <c>NegoData</c> element. Pass none for a request that carries only a
    /// public key or error.
    /// </param>
    /// <param name="authInfo">Delegated credentials, if any. Omitted during authentication.</param>
    /// <param name="pubKeyAuth">Encrypted or hashed server public key. Omitted until the last token.</param>
    /// <param name="clientNonce">
    /// 32 random bytes for version 5 and above. Omitted for older versions.
    /// </param>
    public static byte[] BuildRequest(
        IReadOnlyList<byte[]>? negoTokens = null,
        byte[]? authInfo = null,
        byte[]? pubKeyAuth = null,
        byte[]? clientNonce = null)
    {
        var fields = new List<byte[]>();

        // version [0] INTEGER, always present.
        fields.Add(Context(0, EncodeInteger(ProtocolVersion)));

        // negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        if (negoTokens is { Count: > 0 })
        {
            var items = new List<byte[]>(negoTokens.Count);
            foreach (byte[] token in negoTokens)
            {
                items.Add(Sequence([Context(0, OctetString(token))]));
            }

            fields.Add(Context(1, Sequence(items)));
        }

        // authInfo [2] OCTET STRING
        if (authInfo is not null)
        {
            fields.Add(Context(2, OctetString(authInfo)));
        }

        // pubKeyAuth [3] OCTET STRING
        if (pubKeyAuth is not null)
        {
            fields.Add(Context(3, OctetString(pubKeyAuth)));
        }

        // clientNonce [5] OCTET STRING. Tag [4] is errorCode, which only a server
        // populates, so the nonce follows the gap in the numbering.
        if (clientNonce is not null)
        {
            fields.Add(Context(5, OctetString(clientNonce)));
        }

        return Sequence(fields);
    }

    /// <summary>
    /// Build the <c>TSRequest</c> the server sends back to report a failure.
    /// </summary>
    /// <remarks>
    /// MS-CSSP 3.1.5 step 2 requires the server to answer a failed SPNEGO
    /// handshake with a <c>TSRequest</c> carrying <c>errorCode</c>, and requires
    /// the client to fail immediately with that status. This is only used by the
    /// tests; a client never originates an error request.
    /// </remarks>
    public static byte[] BuildErrorRequest(int errorCode) =>
        Sequence([Context(0, EncodeInteger(ProtocolVersion)), Context(4, EncodeInteger(errorCode))]);

    /// <summary>A parsed <c>TSRequest</c>.</summary>
    /// <param name="Version">The peer's CredSSP version.</param>
    /// <param name="NegoTokens">Every <c>negoToken</c>, in the order received.</param>
    /// <param name="AuthInfo">Delegated credentials, or null.</param>
    /// <param name="PubKeyAuth">The peer's public key proof, or null.</param>
    /// <param name="ErrorCode">
    /// The failure status, or null when the request succeeded. Its presence is
    /// itself the error signal; the value may legitimately be zero.
    /// </param>
    /// <param name="ClientNonce">The peer's nonce, or null.</param>
    public sealed record Request(
        int Version,
        IReadOnlyList<byte[]> NegoTokens,
        byte[]? AuthInfo,
        byte[]? PubKeyAuth,
        int? ErrorCode,
        byte[]? ClientNonce);

    /// <summary>
    /// Read a <c>TSRequest</c> from the server.
    /// </summary>
    /// <remarks>
    /// The server speaks the same structure as the client. MS-CSSP never defines
    /// a separate reply type: the server answers with a <c>TSRequest</c> too, so
    /// one parser covers both directions.
    /// </remarks>
    public static Request ParseRequest(byte[] der)
    {
        ArgumentNullException.ThrowIfNull(der);

        var request = new Request(
            Version: 0,
            NegoTokens: [],
            AuthInfo: null,
            PubKeyAuth: null,
            ErrorCode: null,
            ClientNonce: null);

        var negoTokens = new List<byte[]>();

        // The request is itself a SEQUENCE, so the fields are its contents.
        // Walking the top-level tags directly reads only the SEQUENCE header,
        // finds no context tags, and silently yields an empty request - which
        // reads as a server that authenticated us when it sent nothing at all.
        WalkElements(der, (outerTag, content) =>
        {
            if (outerTag != TagSequence)
            {
                throw new InvalidDataException(
                    $"CredSSP request is not a SEQUENCE (tag 0x{outerTag:x2})");
            }

            WalkElements(content, (tag, value) =>
            {
                switch (ContextTag(tag))
                {
                case 0:
                    request = request with { Version = DecodeInteger(value) };
                    break;

                case 1:
                    // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
                    // Three descents: the SEQUENCE OF yields one NegoDataItem
                    // each, whose own contents hold the [0] field.
                    WalkElements(value, (_, item) =>
                    {
                        WalkElements(item, (_, itemContent) =>
                        {
                            WalkElements(itemContent, (fieldTag, fieldValue) =>
                            {
                                if (ContextTag(fieldTag) == 0)
                                {
                                    negoTokens.Add(InnerOctets(fieldValue));
                                }
                            });
                        });
                    });
                    break;

                case 2:
                    request = request with { AuthInfo = InnerOctets(value) };
                    break;

                case 3:
                    request = request with { PubKeyAuth = InnerOctets(value) };
                    break;

                case 4:
                    request = request with { ErrorCode = DecodeInteger(value) };
                    break;

                case 5:
                    request = request with { ClientNonce = InnerOctets(value) };
                    break;
                }
            });
        });

        return request with { NegoTokens = negoTokens };
    }

    /// <summary>
    /// Human-readable summary for logs; never includes token contents.
    /// </summary>
    public static string Describe(Request request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var parts = new List<string> { $"version {request.Version}" };

        if (request.NegoTokens.Count > 0)
        {
            parts.Add($"{request.NegoTokens.Count} negoToken(s) "
                + $"[{string.Join(", ", request.NegoTokens.Select(Ntlm.DescribeType))}]");
        }

        if (request.PubKeyAuth is not null)
        {
            parts.Add($"pubKeyAuth {request.PubKeyAuth.Length} bytes");
        }

        if (request.AuthInfo is not null)
        {
            parts.Add($"authInfo {request.AuthInfo.Length} bytes");
        }

        if (request.ClientNonce is not null)
        {
            parts.Add($"clientNonce {request.ClientNonce.Length} bytes");
        }

        if (request.ErrorCode is not null)
        {
            parts.Add($"errorCode 0x{unchecked((uint)request.ErrorCode.Value):x8}");
        }

        return string.Join(", ", parts);
    }

    /// <summary>
    /// Wrap a fatal CredSSP failure in the exception the connection layer reports.
    /// </summary>
    /// <remarks>
    /// MS-CSSP 3.1.5 step 2 is unconditional: when <c>errorCode</c> is present
    /// the client must fail with that status and stop. Reporting it as any other
    /// error would hide the only diagnostic the server offers.
    /// </remarks>
    public static bool TryThrowServerError(Request request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.ErrorCode is not int status)
        {
            return false;
        }

        throw new NtlmAuthenticationException(
            $"the server rejected the CredSSP exchange with NTSTATUS 0x{unchecked((uint)status):x8} "
            + $"(0x{status:x8})");
    }

    // --- BER primitives --------------------------------------------------------

    private static byte[] Context(int tag, byte[] content) => Tlv((byte)(0xA0 | tag), content);

    private static byte[] Sequence(IReadOnlyList<byte[]> items)
    {
        int total = 0;
        foreach (byte[] item in items)
        {
            total += item.Length;
        }

        var content = new byte[total];
        int offset = 0;
        foreach (byte[] item in items)
        {
            item.CopyTo(content.AsSpan(offset));
            offset += item.Length;
        }

        return Tlv(TagSequence, content);
    }

    private static byte[] OctetString(byte[] content) => Tlv(TagOctetString, content);

    /// <summary>
    /// Wrap content in a tag and length, using the long form above 127 bytes.
    /// </summary>
    private static byte[] Tlv(byte tag, byte[] content)
    {
        byte[] length = EncodeLength(content.Length);
        var result = new byte[1 + length.Length + content.Length];
        result[0] = tag;
        length.CopyTo(result, 1);
        content.CopyTo(result.AsSpan(1 + length.Length));
        return result;
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80)
        {
            return [(byte)length];
        }

        var bytes = new List<byte>();
        int value = length;
        while (value > 0)
        {
            bytes.Insert(0, (byte)(value & 0xFF));
            value >>= 8;
        }

        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return [.. bytes];
    }

    /// <summary>
    /// Encode a non-negative integer as a DER INTEGER content octet string.
    /// </summary>
    /// <remarks>
    /// A leading zero is required when the top bit of the first octet is set, or
    /// the value reads as negative. Encoding 6 as <c>06</c> is correct because
    /// the top bit is clear.
    /// </remarks>
    private static byte[] EncodeInteger(int value)
    {
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value), value, "only non-negative CredSSP fields are encoded here");
        }

        if (value == 0)
        {
            return [0x00];
        }

        var bytes = new List<byte>();
        int remaining = value;
        while (remaining > 0)
        {
            bytes.Insert(0, (byte)(remaining & 0xFF));
            remaining >>= 8;
        }

        if ((bytes[0] & 0x80) != 0)
        {
            bytes.Insert(0, 0x00);
        }

        return [.. bytes];
    }

    private static void WalkElements(byte[] data, Action<byte, byte[]> visit)
    {
        int position = 0;
        while (position < data.Length)
        {
            byte tag = data[position++];
            int length = ReadLength(data, ref position);
            if (position + length > data.Length)
            {
                throw new InvalidDataException(
                    $"CredSSP element claims {length} bytes but only "
                    + $"{data.Length - position} remain");
            }

            visit(tag, data.AsSpan(position, length).ToArray());
            position += length;
        }
    }

    private static int ReadLength(byte[] data, ref int position)
    {
        if (position >= data.Length)
        {
            throw new InvalidDataException("CredSSP data ended before a length");
        }

        int first = data[position++];
        if (first < 0x80)
        {
            return first;
        }

        int count = first & 0x7F;
        if (count is 0 or > 4)
        {
            throw new InvalidDataException($"unsupported CredSSP length form 0x{first:x2}");
        }

        int length = 0;
        for (int i = 0; i < count; i++)
        {
            if (position >= data.Length)
            {
                throw new InvalidDataException("CredSSP length octets are truncated");
            }

            length = (length << 8) | data[position++];
        }

        return length;
    }

    /// <summary>The context tag number, or -1 when the tag is not context-class.</summary>
    private static int ContextTag(byte tag) =>
        (tag & 0xC0) == 0x80 ? (tag & 0x1F) : -1;

    /// <summary>
    /// Unwrap the single OCTET STRING a context-tagged field holds.
    /// </summary>
    /// <remarks>
    /// The tag is consumed by the caller's walk, so what remains is the
    /// primitive. A peer that sends the value untagged is tolerated rather than
    /// rejected: being lenient here costs nothing and avoids turning a working
    /// exchange into a connection reset.
    /// </remarks>
    private static byte[] InnerOctets(byte[] content)
    {
        if (content.Length == 0)
        {
            return [];
        }

        if (content[0] != TagOctetString)
        {
            return content;
        }

        var copy = (byte[])content.Clone();
        int position = 1;
        int length = ReadLength(copy, ref position);
        if (position + length > copy.Length)
        {
            throw new InvalidDataException("CredSSP OCTET STRING is truncated");
        }

        return copy.AsSpan(position, length).ToArray();
    }

    private static int DecodeInteger(byte[] content)
    {
        if (content.Length == 0)
        {
            throw new InvalidDataException("CredSSP INTEGER is empty");
        }

        // != binds tighter than &, so the sign test must be parenthesised.
        int result = (content[0] & 0x80) != 0 ? -1 : 0;
        foreach (byte b in content)
        {
            result = (result << 8) | b;
        }

        return result;
    }
}