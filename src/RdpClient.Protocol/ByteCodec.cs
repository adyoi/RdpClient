using System.Buffers.Binary;

namespace RdpClient.Protocol;

/// <summary>
/// Little-endian writer with the alignment rules RDP uses.
/// </summary>
/// <remarks>
/// RDP mixes 1-byte and 2-byte aligned structures and several distinct integer
/// encodings. Length fields in TSFC blocks alternate between 2 and 4 bytes,
/// while MCS carries its own variable-byte integers. Centralising the
/// primitives keeps field ordering in one place so a mis-sized length shows up
/// as a diff against the spec rather than as an unexplained server disconnect.
/// </remarks>
public sealed class ByteWriter
{
    private byte[] _buffer;
    private int _length;

    public ByteWriter(int initialCapacity = 512)
    {
        _buffer = new byte[Math.Max(initialCapacity, 16)];
    }

    public int Length => _length;

    private Span<byte> Reserve(int count)
    {
        if (_length + count > _buffer.Length)
        {
            int next = Math.Max(_buffer.Length * 2, _length + count);
            Array.Resize(ref _buffer, next);
        }

        var span = _buffer.AsSpan(_length, count);
        _length += count;
        return span;
    }

    public ByteWriter U8(int value)
    {
        Reserve(1)[0] = (byte)value;
        return this;
    }

    public ByteWriter U16(int value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(Reserve(2), (ushort)value);
        return this;
    }

    /// <summary>
    /// Big-endian 16-bit write. RDP is little-endian throughout except the TPKT
    /// length, which RFC 1006 defines in network byte order.
    /// </summary>
    public ByteWriter U16BigEndian(int value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(Reserve(2), (ushort)value);
        return this;
    }

    public ByteWriter U32(long value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(Reserve(4), unchecked((uint)value));
        return this;
    }

    public ByteWriter I32(int value)
    {
        BinaryPrimitives.WriteInt32LittleEndian(Reserve(4), value);
        return this;
    }

    public ByteWriter Bytes(ReadOnlySpan<byte> data)
    {
        data.CopyTo(Reserve(data.Length));
        return this;
    }

    /// <summary>UTF-16LE text with no terminator; .rdp strings are length-prefixed.</summary>
    public ByteWriter Utf16(string value) => Bytes(System.Text.Encoding.Unicode.GetBytes(value));

    /// <summary>
    /// MCS variable-byte integer (T.125 PerEncoding as carried by MCS).
    /// </summary>
    /// <remarks>
    /// RDP carries MCS lengths as plain fixed-width integers, not T.125
    /// PerEncoding: the GCC Conference Create Request writes the character count
    /// as a bare 16-bit value. The writer therefore emits the narrowest
    /// representation, and the reader must be told which width to expect because
    /// there is no selector to infer it from.
    /// </remarks>
    public ByteWriter McsVariableByte(int value)
    {
        if (value is >= 0 and <= 0xFF)
        {
            return U8(value);
        }

        if (value is >= 0 and <= 0xFFFF)
        {
            return U16(value);
        }

        return I32(value);
    }

    /// <summary>2-byte length in <em>characters</em> followed by UTF-16LE text.</summary>
    public ByteWriter McsUnicodeString(string value)
    {
        U16(value.Length);
        return Utf16(value);
    }

    /// <summary>Pad with NULs to an even offset. RDP TLV lengths count bytes, not words.</summary>
    public ByteWriter Align(int alignment = 2)
    {
        while (_length % alignment != 0)
        {
            U8(0);
        }

        return this;
    }

    /// <summary>Write text into a fixed-width field, NUL-padded to <paramref name="byteLength"/>.</summary>
    public ByteWriter FixedUtf16(string value, int byteLength)
    {
        int maxChars = byteLength / 2;
        string clipped = value.Length <= maxChars ? value : value[..maxChars];
        byte[] raw = System.Text.Encoding.Unicode.GetBytes(clipped);
        int take = Math.Min(raw.Length, byteLength);
        Bytes(raw.AsSpan(0, take));
        for (int i = take; i < byteLength; i++)
        {
            U8(0);
        }

        return this;
    }

    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();
}

/// <summary>Counterpart to <see cref="ByteWriter"/>; reads little-endian.</summary>
public sealed class ByteReader
{
    private readonly ReadOnlyMemory<byte> _buffer;
    private int _position;

    public ByteReader(ReadOnlyMemory<byte> buffer) => _buffer = buffer;

    public int Offset => _position;

    public int Remaining => _buffer.Length - _position;

    public void Seek(int position)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(position);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(position, _buffer.Length);
        _position = position;
    }

    public void Skip(int count) => Seek(_position + count);

    public byte U8()
    {
        ReadOnlySpan<byte> span = _buffer.Span;
        byte value = span[_position];
        _position += 1;
        return value;
    }

    public ushort U16()
    {
        ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_buffer.Span[_position..]);
        _position += 2;
        return value;
    }

    /// <summary>Big-endian 16-bit read; see <see cref="ByteWriter.U16BigEndian"/>.</summary>
    public ushort U16BigEndian()
    {
        ushort value = BinaryPrimitives.ReadUInt16BigEndian(_buffer.Span[_position..]);
        _position += 2;
        return value;
    }

    public uint U32()
    {
        uint value = BinaryPrimitives.ReadUInt32LittleEndian(_buffer.Span[_position..]);
        _position += 4;
        return value;
    }

    public int I32()
    {
        int value = BinaryPrimitives.ReadInt32LittleEndian(_buffer.Span[_position..]);
        _position += 4;
        return value;
    }

    public byte[] Bytes(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, Remaining);
        var span = _buffer.Span.Slice(_position, count);
        _position += count;
        return span.ToArray();
    }

    /// <summary>
    /// Reads an MCS integer of a caller-declared width.
    /// </summary>
    /// <remarks>
    /// The width cannot be inferred from the bytes, so the caller states it.
    /// See <see cref="ByteWriter.McsVariableByte"/> for why there is no selector.
    /// </remarks>
    public int McsVariableByte(int byteWidth) => byteWidth switch
    {
        1 => U8(),
        2 => U16(),
        4 => I32(),
        _ => throw new ArgumentOutOfRangeException(nameof(byteWidth), byteWidth, "width must be 1, 2 or 4"),
    };

    public string McsUnicodeString()
    {
        int chars = U16();
        return System.Text.Encoding.Unicode.GetString(Bytes(chars * 2));
    }

    public ReadOnlySpan<byte> PeekRest() => _buffer.Span[_position..];
}