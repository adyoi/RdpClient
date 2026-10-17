using System.Numerics;
using System.Text;

namespace RdpClient.Protocol;
/// <summary>
/// The MCS domain limits carried in a T.125 Connect-Initial.
/// </summary>
/// <remarks>
/// <para>
/// The structure is named in T.125 and repeated in MS-RDPBCGR 2.2.1.3.4.1. Each
/// field is an independent upper or lower bound: the server merges the target,
/// minimum and maximum sets and answers with a single set it can honour.
/// </para>
/// <para>
/// These are the values a real Windows client offers. The target set is the
/// client's own capability, the minimum set is the floor it will accept, and
/// the maximum set is deliberately generous so the server is not boxed in. The
/// user id floor of 1 is not cosmetic: the client attaches itself as a user
/// right after the connect, so a floor of 0 leaves the server with nowhere to
/// put it.
/// </para>
/// </remarks>
public sealed record McsDomainParameters
{
    /// <summary>Highest channel id the domain may allocate.</summary>
    public uint MaxChannelIds { get; init; }

    /// <summary>Highest user id the domain may allocate.</summary>
    public uint MaxUserIds { get; init; }

    /// <summary>Highest token id the domain may allocate.</summary>
    public uint MaxTokenIds { get; init; }

    public uint NumPriorities { get; init; } = 1;
    public uint MinThroughput { get; init; }
    public uint MaxHeight { get; init; } = 1;

    /// <summary>Upper bound on an MCS PDU, excluding its own header.</summary>
    public uint MaxMcsPduSize { get; init; }

    /// <summary>MCS protocol version this peer implements.</summary>
    public uint ProtocolVersion { get; init; } = 2;

    /// <summary>What the client asks for.</summary>
    public static McsDomainParameters Target { get; } = new()
    {
        MaxChannelIds = 34,
        MaxUserIds = 2,
        MaxTokenIds = 0,
        MaxMcsPduSize = 0xFFFF,
    };

    /// <summary>The lowest the client will settle for.</summary>
    public static McsDomainParameters Minimum { get; } = new()
    {
        MaxChannelIds = 1,
        MaxUserIds = 1,
        MaxTokenIds = 1,
        MaxMcsPduSize = 0x0420,
    };

    /// <summary>No ceiling on the server's side of the negotiation.</summary>
    public static McsDomainParameters Maximum { get; } = new()
    {
        MaxChannelIds = 0xFFFF,
        MaxUserIds = 0xFC17,
        MaxTokenIds = 0xFFFF,
        MaxMcsPduSize = 0xFFFF,
    };
}

/// <summary>
/// The BER (X.690) and PER (X.691) primitives the T.125 Connect-Initial needs.
/// </summary>
/// <remarks>
/// <para>
/// This is not the DER used by CredSSP. Two differences matter and both have
/// bitten this client before:
/// </para>
/// <list type="bullet">
/// <item>BER integers are <em>big-endian</em>, and RDP is little-endian
/// everywhere else.</item>
/// <item>PER length fields are not the same shape as BER ones. A PER length
/// above 127 sets the high bit and keeps the whole 16-bit value, rather than
/// counting following octets the way BER does.</item>
/// </list>
/// </remarks>
internal static class Asn1
{
    /// <summary>Universal tag: BOOLEAN.</summary>
    public const byte Boolean = 0x01;

    /// <summary>Universal tag: INTEGER.</summary>
    public const byte Integer = 0x02;

    /// <summary>Universal tag: OCTET STRING, primitive.</summary>
    public const byte OctetString = 0x04;

    /// <summary>Universal tag: SEQUENCE, constructed.</summary>
    public const byte Sequence = 0x30;

    /// <summary>Universal tag: ENUMERATED.</summary>
    public const byte Enumerated = 0x0A;

    /// <summary>Application class, constructed, tag number above 30.</summary>
    private const byte ApplicationConstructedMask = 0x7F;

    /// <summary>Connect-Initial is <c>[APPLICATION 101]</c>.</summary>
    public const int ConnectInitialTag = 101;

    /// <summary>Connect-Response is <c>[APPLICATION 102]</c>.</summary>
    public const int ConnectResponseTag = 102;

    /// <summary>
    /// Read one BER header: the identifier, the length, and how far the header
    /// reaches.
    /// </summary>
    /// <remarks>
    /// The length comes from the peer, so it is checked against what is
    /// actually in the buffer rather than trusted: a structure claiming more
    /// than was received is a truncated read, not a field to skip past.
    /// </remarks>
    public static bool TryReadHeader(
        ReadOnlySpan<byte> data,
        out byte tag,
        out int length,
        out int headerSize)
    {
        tag = 0;
        length = 0;
        headerSize = 0;

        if (data.Length < 2)
        {
            return false;
        }

        int cursor = 0;
        int first = data[cursor++];

        // A tag above 30 is split: the first octet is all ones and the tag
        // number follows in the next octet.
        if ((first & 0x1F) == 0x1F)
        {
            if (data.Length < cursor + 1)
            {
                return false;
            }

            tag = (byte)((0x1F << 8) | data[cursor++]);
        }
        else
        {
            tag = (byte)first;
        }

        if (cursor >= data.Length)
        {
            return false;
        }

        int size = data[cursor++];
        if ((size & 0x80) != 0)
        {
            int count = size & 0x7F;
            if (count is 0 or > 4 || cursor + count > data.Length)
            {
                return false;
            }

            length = 0;
            for (int i = 0; i < count; i++)
            {
                length = (length << 8) | data[cursor++];
            }
        }
        else
        {
            length = size;
        }

        if (length < 0 || cursor + length > data.Length)
        {
            return false;
        }

        headerSize = cursor;
        return true;
    }

    /// <summary>
    /// Read a PER length field: one octet, or two with the high bit set.
    /// </summary>
    /// <remarks>
    /// This is the shape T.125's ALIGNED variant uses, and it is not a BER
    /// length. Above 127 the high bit marks a two-octet value rather than a
    /// count of octets, so the two disagree on purpose for the same input.
    /// </remarks>
    public static bool TryReadPerLength(ReadOnlySpan<byte> data, out int value, out int size)
    {
        value = 0;
        size = 0;

        if (data.Length < 1)
        {
            return false;
        }

        int first = data[0];
        if ((first & 0x80) != 0)
        {
            if (data.Length < 2)
            {
                return false;
            }

            value = ((first & 0x7F) << 8) | data[1];
            size = 2;
        }
        else
        {
            value = first;
            size = 1;
        }

        return true;
    }

    /// <summary>Wrap content in a BER tag and length.</summary>
    public static byte[] Tlv(byte tag, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);

        byte[] length = BerLength(content.Length);

        var framed = new byte[1 + length.Length + content.Length];
        framed[0] = tag;
        length.CopyTo(framed, 1);
        content.CopyTo(framed, 1 + length.Length);
        return framed;
    }

    /// <summary>
    /// A BER length: short form up to 127, otherwise a count of following
    /// octets.
    /// </summary>
    private static byte[] BerLength(int length)
    {
        if (length < 0x80)
        {
            return [(byte)length];
        }

        var octets = new List<byte>(4);
        int value = length;
        while (value > 0)
        {
            octets.Insert(0, (byte)(value & 0xFF));
            value >>= 8;
        }

        octets.Insert(0, (byte)(0x80 | octets.Count));
        return [.. octets];
    }

    /// <summary>
    /// Build the outer <c>7f 65 &lt;length&gt;</c> wrapper for a Connect-Initial.
    /// </summary>
    /// <remarks>
    /// A tag number above 30 does not fit the five bits of the first tag octet,
    /// so it is split: the first octet becomes all ones and the number follows.
    /// Connect-Initial is tag 101, so it goes out as <c>7f 65</c>, which is
    /// exactly the identifier a server names when it reports which one it
    /// expected.
    /// </remarks>
    public static byte[] WrapApplication(int tag, byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);

        if (tag is <= 0 or > 0xFF)
        {
            throw new ArgumentOutOfRangeException(nameof(tag), tag,
                "an application tag must fit the octet that carries it");
        }

        byte[] length = BerLength(content.Length);

        var framed = new byte[2 + length.Length + content.Length];
        framed[0] = ApplicationConstructedMask;
        framed[1] = (byte)tag;
        length.CopyTo(framed, 2);
        content.CopyTo(framed, 2 + length.Length);
        return framed;
    }

    /// <summary>A BER INTEGER, minimal and big-endian.</summary>
    public static byte[] BerInteger(uint value)
    {
        if (value == 0)
        {
            return Tlv(Integer, [0x00]);
        }

        // How many bits the value actually needs, which is what makes the
        // encoding minimal: 34 needs one octet, 0xFFFF needs three.
        int significant = 32 - BitOperations.LeadingZeroCount(value);

        // A BER INTEGER is signed, so a value whose top bit is set needs one
        // more octet than its own width to keep it from reading as negative.
        // 0xFFFF therefore becomes 00 FF FF, not FF FF.
        int width = significant / 8 + 1;

        var content = new byte[width];
        for (int i = width - 1; i >= 0; i--)
        {
            content[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return Tlv(Integer, content);
    }

    /// <summary>A BER BOOLEAN.</summary>
    public static byte[] BerBoolean(bool value) => Tlv(Boolean, [value ? (byte)0xFF : (byte)0x00]);

    /// <summary>A BER OCTET STRING.</summary>
    public static byte[] BerOctetString(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Tlv(OctetString, content);
    }

    /// <summary>A BER SEQUENCE.</summary>
    public static byte[] BerSequence(byte[] content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return Tlv(Sequence, content);
    }

    /// <summary>
    /// A PER length field: one octet, or two with the high bit set.
    /// </summary>
    /// <remarks>
    /// This is the shape T.125's ALIGNED variant uses, and it is not a BER
    /// length. Above 127 the high bit marks a two-octet value rather than a
    /// count of octets, so <c>per_write_length</c> and <c>BerLength</c> disagree
    /// on purpose for the same input.
    /// </remarks>
    public static void WritePerLength(ByteWriter writer, int length)
    {
        ArgumentNullException.ThrowIfNull(writer);

        if (length > 0x7F)
        {
            writer.U8((byte)((length >> 8) | 0x80));
            writer.U8((byte)length);
        }
        else
        {
            writer.U8((byte)length);
        }
    }

    /// <summary>How many octets <see cref="WritePerLength"/> emits for a value.</summary>
    /// <remarks>
    /// A PER length is one octet up to 127 and two above that, where the high
    /// bit is set and the whole value is kept. Anything that has to account for
    /// the width of a length field it is itself writing - the GCC connectPDU
    /// length counts the field that holds it - needs this to stay
    /// self-consistent rather than assuming a fixed width.
    /// </remarks>
    public static int PerLengthOctets(int length) => length > 0x7F ? 2 : 1;

    /// <summary>
    /// A PER numeric string: a length, then each digit pair packed into one
    /// octet, high nibble first.
    /// </summary>
    /// <remarks>
    /// T.125 asks for a conference name as a numeric string. The digits are
    /// packed two per octet as <c>(d1 &lt;&lt; 4) | d2</c> with an implied
    /// trailing <c>0</c> when the string has an odd length, which is why the
    /// name "1" becomes the single octet <c>0x10</c> and not <c>0x01</c>.
    /// </remarks>
    public static void WritePerNumericString(ByteWriter writer, string value, int minimum)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        WritePerLength(writer, Math.Max(value.Length - minimum, 0));

        byte[] digits = Encoding.ASCII.GetBytes(value);
        for (int i = 0; i < digits.Length; i += 2)
        {
            byte high = digits[i];
            byte low = i + 1 < digits.Length ? digits[i + 1] : (byte)'0';

            if (high < '0' || high > '9' || low < '0' || low > '9')
            {
                throw new ArgumentException(
                    $"a numeric string cannot contain '{value}': digits only", nameof(value));
            }

            writer.U8((byte)(((high - '0') << 4) | (low - '0')));
        }
    }

    /// <summary>A PER OCTET STRING with an explicit minimum length.</summary>
    public static void WritePerOctetString(ByteWriter writer, byte[] value, int minimum)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(value);

        WritePerLength(writer, Math.Max(value.Length - minimum, 0));
        writer.Bytes(value);
    }
}
