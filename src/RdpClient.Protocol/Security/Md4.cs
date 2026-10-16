using System.Security.Cryptography;
using System.Text;

namespace RdpClient.Protocol.Security;

/// <summary>MD4, which .NET does not ship but NTLM needs for the NT hash.</summary>
/// <remarks>
/// RFC 1320. MD4 is not collision resistant and is used here only because NTLM
/// specifies it; it is never used for anything else in this project.
/// </remarks>
public sealed class Md4 : IDisposable
{
    private readonly uint[] _state = new uint[4];
    private readonly byte[] _buffer = new byte[64];
    private readonly uint[] _x = new uint[16];
    private long _length;
    private int _bufferIndex;

    public Md4()
    {
        Reset();
    }

    public void Reset()
    {
        _state[0] = 0x67452301;
        _state[1] = 0xefcdab89;
        _state[2] = 0x98badcfe;
        _state[3] = 0x10325476;
        _length = 0;
        _bufferIndex = 0;
    }

    public void Update(ReadOnlySpan<byte> input)
    {
        _length += input.Length;

        while (input.Length > 0)
        {
            int take = Math.Min(64 - _bufferIndex, input.Length);
            input[..take].CopyTo(_buffer.AsSpan(_bufferIndex));
            _bufferIndex += take;
            input = input[take..];

            if (_bufferIndex == 64)
            {
                ProcessBlock(_buffer);
                _bufferIndex = 0;
            }
        }
    }

    public byte[] Finish()
    {
        long bitLength = _length * 8;

        // Padding: 0x80 then zeros to 56 mod 64, then the 64-bit length.
        Update([0x80]);
        while (_bufferIndex != 56)
        {
            Update([0x00]);
        }

        Span<byte> lengthBytes = stackalloc byte[8];
        BinaryPrimitivesCompat.WriteUInt64LittleEndian(lengthBytes, (ulong)bitLength);
        Update(lengthBytes);

        var result = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            BinaryPrimitivesCompat.WriteUInt32LittleEndian(result.AsSpan(i * 4), _state[i]);
        }

        return result;
    }

    public byte[] ComputeHash(ReadOnlySpan<byte> data)
    {
        Reset();
        Update(data);
        return Finish();
    }

    private void ProcessBlock(ReadOnlySpan<byte> block)
    {
        for (int i = 0; i < 16; i++)
        {
            _x[i] = BinaryPrimitivesCompat.ReadUInt32LittleEndian(block.Slice(i * 4, 4));
        }

        uint a = _state[0], b = _state[1], c = _state[2], d = _state[3];

        // RFC 1320 section 3.2: three rounds of sixteen operations. Each round
        // has its own mixing function, its own additive constant and its own
        // walk over the message words, so all three are tabulated from the RFC
        // rather than derived. Getting this wrong still yields a
        // plausible-looking 128-bit digest; only a known-answer test catches
        // it, which is why MD4 carries RFC 1320 Appendix A.5 vectors.
        //
        // The four registers rotate after each operation so the one to update
        // is always first: v becomes [v3, v0, v1, v2]. That turns the RFC's
        // ABCD/DABC/CDAB/BCDA ordering into a straight loop.
        foreach ((Func<uint, uint, uint, uint> mix, uint constant, byte[] order, byte[] rotations)
                 in Rounds)
        {
            for (int i = 0; i < 16; i++)
            {
                uint next = RotateLeft(a + mix(b, c, d) + _x[order[i]] + constant, rotations[i & 3]);
                (a, b, c, d) = (d, next, b, c);
            }
        }

        _state[0] += a;
        _state[1] += b;
        _state[2] += c;
        _state[3] += d;
    }

    private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);

    private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

    private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

    /// <summary>
    /// RFC 1320 section 3.2, transcribed: mixing function, additive constant,
    /// the order the message words are visited in, and the rotation amounts.
    /// </summary>
    private static readonly (Func<uint, uint, uint, uint> Mix, uint Constant, byte[] Order, byte[] Rotations)[]
        Rounds =
        [
            (F, 0x00000000, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [3, 7, 11, 19]),
            (G, 0x5A827999, [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15], [3, 5, 9, 13]),
            (H, 0x6ED9EBA1, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15], [3, 9, 11, 15]),
        ];

    private static uint RotateLeft(uint value, int count) =>
        (value << count) | (value >> (32 - count));

    public void Dispose() => Reset();
}

/// <summary>Little-endian helpers kept separate so the primitive types stay obvious.</summary>
internal static class BinaryPrimitivesCompat
{
    public static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> data)
    {
        uint value = 0;
        for (int i = 3; i >= 0; i--)
        {
            value = (value << 8) | data[i];
        }

        return value;
    }

    public static void WriteUInt32LittleEndian(Span<byte> destination, uint value)
    {
        for (int i = 0; i < 4; i++)
        {
            destination[i] = (byte)(value >> (8 * i));
        }
    }

    public static ushort ReadUInt16LittleEndian(ReadOnlySpan<byte> data) =>
        (ushort)(data[0] | (data[1] << 8));

    public static void WriteUInt16LittleEndian(Span<byte> destination, ushort value)
    {
        destination[0] = (byte)value;
        destination[1] = (byte)(value >> 8);
    }

    public static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> data)
    {
        ulong value = 0;
        for (int i = 7; i >= 0; i--)
        {
            value = (value << 8) | data[i];
        }

        return value;
    }

    public static void WriteUInt64LittleEndian(Span<byte> destination, ulong value)
    {
        for (int i = 0; i < 8; i++)
        {
            destination[i] = (byte)(value >> (8 * i));
        }
    }
}