using System.IO.Compression;

namespace RdpClient.Protocol;

/// <summary>
/// RDP bulk decompression for compressed Share Data PDUs (MS-RDPBCGR 3.1.8.3,
/// 3.1.8.4.2).
/// </summary>
/// <remarks>
/// <para>
/// A slow-path PDU over about fifty octets is normally deflated by the server,
/// so a client that refuses compressed PDUs receives the desktop's first
/// rectangle and nothing after it - which is why the connection has to inflate.
/// </para>
/// <para>
/// <c>PACKET_COMPR_TYPE_64K</c> is DEFLATE (RFC 1951) over a persistent 64 KiB
/// history buffer, not a self-contained stream: a match may refer back into data
/// the server sent in an earlier PDU. This implementation keeps one buffer per
/// connection for that reason, because handing a self-contained inflater each
/// PDU would fail on exactly the PDUs that benefit from compression.
/// </para>
/// <para>
/// The two flags that move the write position are <c>PACKET_FLUSHED</c>
/// (0x80), which resets the history to zero and makes all of it valid, and
/// <c>PACKET_AT_FRONT</c> (0x40), which rewinds the write offset without
/// clearing. <c>PACKET_FLUSHED</c> must be processed first; doing them in the
/// other order produces an image that is subtly wrong rather than obviously
/// broken.
/// </para>
/// </remarks>
public sealed class BulkDecompressor
{
    private const int HistorySize = 64 * 1024;

    /// <summary>CompressionTypeMask: the package used for compression.</summary>
    public const byte CompressionTypeMask = 0x0F;

    /// <summary>PACKET_COMPRESSED: the payload is compressed.</summary>
    public const byte PacketCompressed = 0x20;

    /// <summary>PACKET_AT_FRONT: place the decompressed data at the start of the history.</summary>
    public const byte PacketAtFront = 0x40;

    /// <summary>PACKET_FLUSHED: reset the history buffer to zeros first.</summary>
    public const byte PacketFlushed = 0x80;

    /// <summary>PACKET_COMPR_TYPE_8K, the RDP 4.0 scheme, which is not implemented.</summary>
    public const byte PacketComprType8K = 0x0;

    /// <summary>PACKET_COMPR_TYPE_64K: DEFLATE over a 64 KiB history.</summary>
    public const byte PacketComprType64K = 0x1;

    private readonly byte[] _history = new byte[HistorySize];
    private int _offset;

    /// <summary>How many decompressed octets this instance has produced.</summary>
    public long TotalDecompressed { get; private set; }

    /// <summary>
    /// Decompress one compressed payload into the history buffer and return it.
    /// </summary>
    /// <param name="flags">The Share Data Header's <c>compressedType</c>.</param>
    /// <param name="payload">The compressed octets.</param>
    /// <param name="uncompressedLength">
    /// The Share Data Header's <c>uncompressedLength</c>, which is the authority
    /// on how much the payload inflates to.
    /// </param>
    public byte[] Decompress(byte flags, ReadOnlySpan<byte> payload, int uncompressedLength)
    {
        if ((flags & PacketCompressed) == 0)
        {
            throw new ArgumentException(
                "the payload is not flagged as compressed", nameof(flags));
        }

        // PACKET_FLUSHED must be handled before PACKET_AT_FRONT, so the
        // reinitialised buffer is not immediately overwritten by a rewind.
        if ((flags & PacketFlushed) != 0)
        {
            Array.Clear(_history);
            _offset = 0;
        }

        int writeStart = (flags & PacketAtFront) != 0 ? 0 : _offset;

        int compressionType = flags & CompressionTypeMask;
        if (compressionType != PacketComprType64K)
        {
            throw new NotSupportedException(
                compressionType == PacketComprType8K
                    ? "RDP 4.0 bulk compression is not implemented"
                    : $"bulk compression type {compressionType} is not implemented");
        }

        if (uncompressedLength <= 0 || uncompressedLength > HistorySize)
        {
            throw new InvalidDataException(
                $"a compressed PDU declares {uncompressedLength} octets, outside the "
                + $"{HistorySize}-octet history buffer");
        }

        int produced = Inflate(payload, _history.AsSpan(writeStart, uncompressedLength));

        if (produced != uncompressedLength)
        {
            throw new InvalidDataException(
                $"the compressed payload inflated to {produced} octets but the PDU "
                + $"declares {uncompressedLength}");
        }

        TotalDecompressed += produced;
        _offset = writeStart + produced;
        return _history.AsSpan(writeStart, produced).ToArray();
    }

    /// <summary>
    /// Inflate a raw DEFLATE stream straight into a slice of the history buffer,
    /// so the decompressed octets are where the next match will look for them.
    /// </summary>
    private static int Inflate(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        // A negative window size selects raw DEFLATE, which is what
        // PACKET_COMPR_TYPE_64K uses: no zlib wrapper, no trailing checksum.
        using var input = new MemoryStream(payload.ToArray(), writable: false);

        // The negative window size selects raw DEFLATE, which is what
        // PACKET_COMPR_TYPE_64K uses: no zlib wrapper, no trailing checksum.
        using var deflate = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: false);

        int read = 0;
        while (read < destination.Length)
        {
            int n = deflate.Read(destination[read..]);
            if (n == 0)
            {
                break;
            }

            read += n;
        }

        return read;
    }
}