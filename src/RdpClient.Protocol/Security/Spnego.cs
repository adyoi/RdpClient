using System.Text;

namespace RdpClient.Protocol.Security;

/// <summary>
/// Minimal BER encoder/decoder for the SPNEGO tokens CredSSP exchanges with NTLM.
/// </summary>
/// <remarks>
/// CredSSP wraps NTLM in SPNEGO inside a GSS-API initial-context token:
/// <code>
/// GSSAPI      ::= SEQUENCE { thisMech [0] MechType, innerContextToken [1] OCTET STRING OPTIONAL }
/// NegTokenInit::= SEQUENCE { mechTypes [0] SEQUENCE OF MechType, mechToken [1] OCTET STRING OPTIONAL }
/// NegTokenTarg::= SEQUENCE { negResult [0] ENUMERATED, supportedMech [1] MechType OPTIONAL,
///                            responseToken [2] OCTET STRING OPTIONAL }
/// </code>
/// Only the fields this client actually uses are handled; unknown context tags
/// are skipped so an extended server token still parses.
/// </remarks>
public static class Spnego
{
    /// <summary>
    /// Content octets of OID 1.3.6.1.5.5.2, the NTLM security mechanism.
    /// </summary>
    /// <remarks>
    /// Stored without a tag or length because <see cref="Tlv"/> adds them. The
    /// first two arcs combine as 40*1+3, leaving six content octets; declaring
    /// five makes a server reject the whole token as malformed.
    /// </remarks>
    private static readonly byte[] NtlmMechanismOidContent = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];

    private const byte TagSequence = 0x30;
    private const byte TagOctetString = 0x04;
    private const byte TagEnumerated = 0x0A;
    private const byte TagObjectIdentifier = 0x06;
    private const byte TagContext0 = 0xA0;
    private const byte TagContext1 = 0xA1;
    private const byte TagContext2 = 0xA2;

    /// <summary>
    /// APPLICATION-class constructed tag 0.
    /// </summary>
    /// <remarks>
    /// Inside the GSS-API initial-context token, Windows and the major open
    /// source clients tag <c>thisMech</c> with the APPLICATION class rather than
    /// CONTEXT-specific. Sending <c>0xA0</c> there is accepted by no host: the
    /// token parses as malformed and the server answers with a TLS alert.
    /// CONTEXT-specific tagging is still correct inside <c>NegTokenInit</c>.
    /// </remarks>
    private const byte TagApplication0 = 0x60;

    /// <summary>
    /// Build the initial token: a GSS-API wrapper carrying a NegTokenInit that
    /// advertises NTLM and embeds the NEGOTIATE message.
    /// </summary>
    public static byte[] BuildNegotiateToken(byte[] ntlmNegotiate)
    {
        // NegTokenInit { mechTypes [0] { OID }, mechToken [1] OCTET STRING }
        var mechTypes = Tlv(TagContext0, [.. Tlv(TagObjectIdentifier, NtlmMechanismOidContent)]);
        var mechToken = Tlv(TagContext1, Tlv(TagOctetString, ntlmNegotiate));
        var negTokenInit = Tlv(TagSequence, [.. mechTypes, .. mechToken]);

        return WrapInGssApi(negTokenInit);
    }

    /// <summary>
    /// Build the token carrying the AUTHENTICATE message.
    /// </summary>
    /// <remarks>
    /// MS-NLMP 3.1.5.1.2 wraps it in a NegTokenInit whose mechToken holds the
    /// response. mechTypes is omitted: the mechanism was already selected.
    /// </remarks>
    public static byte[] BuildAuthenticateToken(byte[] ntlmAuthenticate)
    {
        var mechToken = Tlv(TagContext1, Tlv(TagOctetString, ntlmAuthenticate));
        var negTokenInit = Tlv(TagSequence, mechToken);
        return WrapInGssApi(negTokenInit);
    }

    private static byte[] WrapInGssApi(byte[] innerContextToken)
    {
        var thisMech = Tlv(TagApplication0, Tlv(TagObjectIdentifier, NtlmMechanismOidContent));
        var inner = Tlv(TagContext1, Tlv(TagOctetString, innerContextToken));
        return Tlv(TagSequence, [.. thisMech, .. inner]);
    }

    public sealed record ServerToken(
        int NegResult,
        byte[]? SupportedMechanism,
        byte[]? ResponseToken,
        byte[]? ErrorMessage);

    /// <summary>
    /// Read a token the server sent and extract the inner SPNEGO result.
    /// </summary>
    public static ServerToken ParseServerToken(byte[] token)
    {
        ArgumentNullException.ThrowIfNull(token);

        var reader = new BerReader(token);
        ReadSequence(reader, content =>
        {
            // GSS-API wrapper: thisMech [0] then innerContextToken [1].
            byte[]? inner = null;
            ReadSequenceContent(content, (tag, value) =>
            {
                // thisMech is APPLICATION-tagged on the wire; accept either class.
                if (tag == TagApplication0 || tag == TagContext0)
                {
                    return;
                }

                if (tag == TagContext1)
                {
                    inner = ReadSingleOctetString(value);
                }
            });

            if (inner is null)
            {
                throw new InvalidDataException("SPNEGO token has no innerContextToken");
            }

            return ParseNegTokenTarg(inner);
        });

        throw new InvalidDataException("SPNEGO token is not a SEQUENCE");
    }

    private static ServerToken ParseNegTokenTarg(byte[] der)
    {
        var result = new ServerToken(
            NegResult: -1, SupportedMechanism: null, ResponseToken: null, ErrorMessage: null);

        var reader = new BerReader(der);
        ReadSequence(reader, content =>
        {
            ReadSequenceContent(content, (tag, value) =>
            {
                switch (tag)
                {
                    case TagContext0:
                        // negResult is an ENUMERATED, which BER may encode in one
                        // or more octets.
                        if (value.Length == 0)
                        {
                            throw new InvalidDataException("negResult is empty");
                        }

                        result = result with { NegResult = value[0] };
                        break;

                    case TagContext1:
                        result = result with
                        {
                            SupportedMechanism = FirstElement(value, TagObjectIdentifier),
                        };
                        break;

                    case TagContext2:
                        result = result with
                        {
                            ResponseToken = ReadSingleOctetString(value),
                            ErrorMessage = ReadSingleOctetString(value),
                        };
                        break;
                }
            });

            return result;
        });

        return result;
    }

    private static byte[]? FirstElement(byte[] der, byte tag)
    {
        var reader = new BerReader(der);
        byte[]? found = null;
        try
        {
            ReadTlv(reader, (actualTag, value) =>
            {
                if (actualTag == tag && found is null)
                {
                    found = value;
                }
            });
        }
        catch (InvalidDataException)
        {
            // A server that omits supportedMech is tolerated; the caller decides
            // whether that matters.
        }

        return found;
    }

    private static byte[] ReadSingleOctetString(byte[] der)
    {
        var reader = new BerReader(der);
        byte[]? value = null;
        ReadTlv(reader, (_, content) => value = content);
        return value ?? [];
    }

    // --- primitive BER helpers -------------------------------------------------

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

    private static void ReadSequence(BerReader reader, Func<BerReader, object> body)
    {
        bool matched = false;
        ReadTlv(reader, (tag, content) =>
        {
            if (tag != TagSequence)
            {
                return;
            }

            matched = true;
            var inner = new BerReader(content);
            body(inner);
        });

        if (!matched)
        {
            throw new InvalidDataException("expected a BER SEQUENCE");
        }
    }

    private static void ReadSequenceContent(BerReader content, Action<byte, byte[]> visit)
    {
        while (content.Remaining > 0)
        {
            ReadTlv(content, visit);
        }
    }

    private static void ReadTlv(BerReader reader, Action<byte, byte[]> visit)
    {
        byte tag = reader.ReadByte();
        int length = reader.ReadLength();

        // Primitive forms shorter than 128 bytes carry the length inline.
        if ((tag & 0x20) == 0 && tag != TagEnumerated)
        {
            // Still read as a value so the cursor advances correctly.
            visit(tag, reader.ReadBytes(length));
            return;
        }

        visit(tag, reader.ReadBytes(length));
    }

    /// <summary>Cursor over BER-encoded bytes.</summary>
    private sealed class BerReader(byte[] data)
    {
        private int _position;

        public int Remaining => data.Length - _position;

        public byte ReadByte()
        {
            if (_position >= data.Length)
            {
                throw new InvalidDataException("BER data ended unexpectedly");
            }

            return data[_position++];
        }

        public int ReadLength()
        {
            int first = ReadByte();
            if (first < 0x80)
            {
                return first;
            }

            int count = first & 0x7F;
            if (count is 0 or > 4)
            {
                throw new InvalidDataException($"unsupported BER length form: 0x{first:x2}");
            }

            int length = 0;
            for (int i = 0; i < count; i++)
            {
                length = (length << 8) | ReadByte();
            }

            return length;
        }

        public byte[] ReadBytes(int count)
        {
            if (count < 0 || _position + count > data.Length)
            {
                throw new InvalidDataException(
                    $"BER element claims {count} bytes but only {Remaining} remain");
            }

            var slice = data.AsSpan(_position, count).ToArray();
            _position += count;
            return slice;
        }
    }

    /// <summary>
    /// Read an SPNEGO error carried in a <c>responseToken</c>.
    /// </summary>
    /// <remarks>
    /// On failure the server reuses the responseToken slot for
    /// <c>SPNEGO_ERROR ::= SEQUENCE { errorCode [0] INTEGER, errorString [1] OCTET STRING OPTIONAL }</c>.
    /// An error code of zero, or a field that does not parse, means the token
    /// was a real NTLM message rather than an error.
    /// </remarks>
    public static bool TryReadError(byte[] responseToken, out string message)
    {
        message = string.Empty;
        if (responseToken.Length == 0)
        {
            return false;
        }

        try
        {
            int errorCode = 0;
            string errorString = string.Empty;

            var reader = new BerReader(responseToken);
            ReadSequence(reader, content =>
            {
                ReadSequenceContent(content, (tag, value) =>
                {
                    switch (tag)
                    {
                        case TagContext0:
                            if (value.Length > 0)
                            {
                                errorCode = DecodeUnsigned(value);
                            }

                            break;
                        case TagContext1:
                            errorString = Encoding.UTF8.GetString(value);
                            break;
                    }
                });

                return 0;
            });

            if (errorCode == 0 && errorString.Length == 0)
            {
                return false;
            }

            message = string.IsNullOrEmpty(errorString)
                ? $"SPNEGO error code {errorCode}"
                : $"{errorString} (code {errorCode})";
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static int DecodeUnsigned(byte[] value)
    {
        int result = 0;
        foreach (byte b in value)
        {
            result = (result << 8) | b;
        }

        return result;
    }

    /// <summary>Hex helper used when logging a token that fails to parse.</summary>
    public static string Describe(byte[] data) =>
        data.Length == 0 ? "<empty>" : $"0x{Convert.ToHexString(data).ToLowerInvariant()}";

    internal static string Ascii(byte[] data) => Encoding.ASCII.GetString(data);
}