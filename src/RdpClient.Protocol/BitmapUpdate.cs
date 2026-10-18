namespace RdpClient.Protocol;

/// <summary>
/// Bitmap Update PDUs (MS-RDPBCGR 2.2.9.1.1.3.1.2): parsing
/// <c>TS_UPDATE_BITMAP_DATA</c> and decoding <c>TS_BITMAP_DATA</c>, both
/// uncompressed and Interleaved RLE.
/// </summary>
/// <remarks>
/// <para>
/// This is the slow-path graphics path: rectangular clippings of the server's
/// frame buffer. It is not the only way a server can send output - a client that
/// advertises the Order capability set receives drawing orders from
/// [MS-RDPEGDI] instead, and one that negotiates EGFX over the <c>rdpgfx</c>
/// virtual channel receives surfaces. Only the bitmap path is implemented here,
/// and it is the one a client gets when it advertises the Bitmap capability set
/// without the Order capability set.
/// </para>
/// <para>
/// Uncompressed data is bottom-up and left-to-right with each row padded to a
/// multiple of four bytes. That padding is the detail that makes a naive
/// "copy height * width * bytesPerPixel" decoder read garbage: it is in the
/// stream but not in the image, and dropping it shears every row.
/// </para>
/// </remarks>
public static class BitmapUpdate
{
    /// <summary>PDUTYPE2_UPDATE, the pduType2 of a Graphics Update PDU (2.2.8.1.1.1.2).</summary>
    public const byte PduType2Update = 0x02;

    /// <summary>UPDATETYPE_ORDERS.</summary>
    public const ushort UpdateTypeOrders = 0x0000;

    /// <summary>UPDATETYPE_BITMAP (2.2.9.1.1.3.1.2.1).</summary>
    public const ushort UpdateTypeBitmap = 0x0001;

    /// <summary>UPDATETYPE_PALETTE.</summary>
    public const ushort UpdateTypePalette = 0x0002;

    /// <summary>UPDATETYPE_SYNCHRONIZE.</summary>
    public const ushort UpdateTypeSynchronize = 0x0003;

    /// <summary>BITMAP_COMPRESSION: the data carries an RLE stream (2.2.9.1.1.3.1.2.2).</summary>
    public const ushort FlagBitmapCompression = 0x0001;

    /// <summary>NO_BITMAP_COMPRESSION_HDR: the eight-octet TS_CD_HEADER is absent.</summary>
    public const ushort FlagNoBitmapCompressionHdr = 0x0400;

    /// <summary>One rectangle of decoded pixels, top-down, 32 bpp BGRA.</summary>
    /// <param name="DestinationLeft">Left bound on the desktop.</param>
    /// <param name="DestinationTop">Top bound on the desktop.</param>
    /// <param name="Width">Width in pixels.</param>
    /// <param name="Height">Height in pixels.</param>
    /// <param name="Pixels">
    /// Width * Height pixels as 32-bit BGRA, top-down: the first pixel is the
    /// top-left one. That order is chosen deliberately, because the wire order
    /// is bottom-up and every caller wants top-down.
    /// </param>
    public sealed record BitmapRectangle(
        int DestinationLeft,
        int DestinationTop,
        int Width,
        int Height,
        byte[] Pixels);

    /// <summary>
    /// Parse a Graphics Update PDU body (everything after the Share Data
    /// Header) and return its decoded bitmap rectangles.
    /// </summary>
    /// <param name="body">
    /// The PDU body: the update type, its count, then the update structure.
    /// </param>
    /// <param name="requestedDepth">
    /// The colour depth the client advertised, which selects the pixel format
    /// the server is expected to use.
    /// </param>
    /// <exception cref="NotSupportedException">
    /// The update is a type this client does not render, which is a reportable
    /// limitation rather than a parse failure.
    /// </exception>
    public static IReadOnlyList<BitmapRectangle> ParseUpdate(
        byte[] body, int requestedDepth)
    {
        ArgumentNullException.ThrowIfNull(body);

        if (body.Length < 4)
        {
            throw new InvalidDataException(
                $"a graphics update needs an updateType and a count, got {body.Length} bytes");
        }

        var r = new ByteReader(body);
        int updateType = r.U16();
        int numberRectangles = r.U16();

        switch (updateType)
        {
            case UpdateTypeBitmap:
                return ParseBitmapUpdate(body, r.Offset, numberRectangles, requestedDepth);

            case UpdateTypeOrders:
                // xrdp sends orders regardless of what the client advertised:
                // its gdi/xrdp layer picks orders by server policy, not by the
                // client's capability set. That is a fact about xrdp, not a
                // misconfiguration to correct on the client, so the message
                // says so rather than telling the caller to change the set.
                throw new NotSupportedException(
                    "the server sent GDI drawing orders (MS-RDPEGDI), which this client does "
                    + "not implement; only bitmap updates are decoded");

            case UpdateTypePalette:
                throw new NotSupportedException(
                    "the server sent a palette update, which only matters for 8 bpp output");

            case UpdateTypeSynchronize:
                // A synchronize update is a single 2-octet syncFlag, and it
                // ends a batch of graphics; nothing to paint.
                return [];

            default:
                throw new NotSupportedException(
                    $"graphics update type {updateType} is not implemented");
        }
    }

    /// <summary>Parse <c>TS_UPDATE_BITMAP_DATA</c>: a count, then that many rectangles.</summary>
    public static IReadOnlyList<BitmapRectangle> ParseBitmapUpdate(
        byte[] body, int offset, int numberRectangles, int requestedDepth)
    {
        ArgumentNullException.ThrowIfNull(body);

        var rectangles = new List<BitmapRectangle>(numberRectangles);
        int cursor = offset;

        for (int i = 0; i < numberRectangles; i++)
        {
            // destLeft(2) destTop(2) destRight(2) destBottom(2) width(2)
            // height(2) bitsPerPixel(2) flags(2) bitmapLength(2) = 18 octets
            const int FixedFields = 18;
            if (cursor + FixedFields > body.Length)
            {
                throw new InvalidDataException(
                    $"bitmap rectangle {i} of {numberRectangles} needs {FixedFields} octets of "
                    + $"fields but only {body.Length - cursor} remain");
            }

            int destinationLeft = ReadU16(body, cursor);
            int destinationTop = ReadU16(body, cursor + 2);

            // destRight and destBottom are inclusive, so they are bounds rather
            // than dimensions. The server states width and height separately and
            // the stated dimensions are what the pixel data is actually sized
            // for, so those win; the bounds are only checked for agreement.
            int destinationRight = ReadU16(body, cursor + 4);
            int destinationBottom = ReadU16(body, cursor + 6);
            int width = ReadU16(body, cursor + 8);
            int height = ReadU16(body, cursor + 10);
            int bitsPerPixel = ReadU16(body, cursor + 12);
            int flags = ReadU16(body, cursor + 14);
            int bitmapLength = ReadU16(body, cursor + 16);
            cursor += FixedFields;

            // A rectangle whose stated width disagrees with its inclusive
            // bounds is a malformed rectangle, not something to guess at.
            if (destinationRight - destinationLeft + 1 != width
                || destinationBottom - destinationTop + 1 != height)
            {
                throw new InvalidDataException(
                    $"bitmap rectangle {i} is {width}x{height} but its inclusive bounds "
                    + $"({destinationLeft},{destinationTop})-({destinationRight},{destinationBottom}) "
                    + $"imply {destinationRight - destinationLeft + 1}x{destinationBottom - destinationTop + 1}");
            }

            if (width <= 0 || height <= 0)
            {
                throw new InvalidDataException(
                    $"bitmap rectangle {i} declares {width}x{height}");
            }

            bool compressed = (flags & FlagBitmapCompression) != 0;
            bool hasHeader = compressed && (flags & FlagNoBitmapCompressionHdr) == 0;

            // bitmapLength counts the compressed data header when present, not
            // just the pixel stream, so stepping over the right number of octets
            // depends on the flag rather than on a constant.
            int streamOffset = cursor;
            if (hasHeader)
            {
                const int CompressedDataHeaderSize = 8;
                if (streamOffset + CompressedDataHeaderSize > body.Length)
                {
                    throw new InvalidDataException(
                        $"bitmap rectangle {i} needs an {CompressedDataHeaderSize}-octet "
                        + "compressed data header that the PDU does not contain");
                }

                streamOffset += CompressedDataHeaderSize;
            }

            int streamLength = bitmapLength - (hasHeader ? 8 : 0);
            if (streamLength < 0 || streamOffset + streamLength > body.Length)
            {
                throw new InvalidDataException(
                    $"bitmap rectangle {i} declares {bitmapLength} octets of bitmap data "
                    + $"but only {body.Length - streamOffset} remain");
            }

            rectangles.Add(new BitmapRectangle(
                destinationLeft,
                destinationTop,
                width,
                height,
                compressed
                    ? RleBitmap.Decode(
                        body.AsSpan(streamOffset, streamLength), width, height, bitsPerPixel)
                    : UncompressedBitmap.Decode(
                        body.AsSpan(streamOffset, streamLength), width, height, bitsPerPixel)));

            cursor = streamOffset + streamLength;
        }

        return rectangles;
    }

    private static int ReadU16(byte[] data, int offset) =>
        data[offset] | (data[offset + 1] << 8);
}