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

        Round(ref a, ref b, ref c, ref d, 0, 3, 1);
        Round(ref d, ref a, ref b, ref c, 1, 7, 2);
        Round(ref c, ref d, ref a, ref b, 2, 11, 3);
        Round(ref b, ref c, ref d, ref a, 3, 19, 4);

        Round(ref a, ref b, ref c, ref d, 4, 3, 5);
        Round(ref d, ref a, ref b, ref c, 5, 7, 6);
        Round(ref c, ref d, ref a, ref b, 6, 11, 7);
        Round(ref b, ref c, ref d, ref a, 7, 19, 8);

        Round(ref a, ref b, ref c, ref d, 8, 3, 9);
        Round(ref d, ref a, ref b, ref c, 9, 7, 10);
        Round(ref c, ref d, ref a, ref b, 10, 11, 11);
        Round(ref b, ref c, ref d, ref a, 11, 19, 12);

        Round(ref a, ref b, ref c, ref d, 12, 3, 13);
        Round(ref d, ref a, ref b, ref c, 13, 7, 14);
        Round(ref c, ref d, ref a, ref b, 14, 11, 15);
        Round(ref b, ref c, ref d, ref a, 15, 19, 16);

        _state[0] += a;
        _state[1] += b;
        _state[2] += c;
        _state[3] += d;
    }

    private void Round(ref uint a, ref uint b, ref uint c, ref uint d, int k, int s, int round)
    {
        uint f;
        int g;

        switch (round)
        {
            case 1:
            case 2:
                f = (b & c) | (~b & d);
                g = k;
                break;
            case 3:
                f = (b & c) | (b & d) | (c & d);
                g = (5 * k + 1) % 16;
                break;
            default:
                f = b ^ c ^ d;
                g = (3 * k + 5) % 16;
                break;
        }

        uint temp = a + f + _x[g];
        a = d;
        d = c;
        c = b;
        b = RotateLeft(temp, s);
    }

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