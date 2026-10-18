namespace RdpClient.Protocol;

/// <summary>
/// Decodes an uncompressed <c>bitmapDataStream</c> (MS-RDPBCGR
/// 2.2.9.1.1.3.1.2.2) into 32-bit BGRA, top-down.
/// </summary>
/// <remarks>
/// The two properties of this format that a decoder gets wrong are the row
/// order and the row padding. Data is bottom-up, and each row is padded to a
/// multiple of four bytes - so a row of 16-bit pixels at an odd width carries
/// two bytes of padding that are in the stream and not in the image. Reading
/// <c>height * width * bytesPerPixel</c> bytes in one block without honouring
/// the stride produces an image that shears progressively down the screen.
/// </remarks>
internal static class UncompressedBitmap
{
    internal static byte[] Decode(
        ReadOnlySpan<byte> stream, int width, int height, int bitsPerPixel)
    {
        int bytesPerPixel = PixelBytesPerPixel(bitsPerPixel);
        int stride = RowStride(width, bytesPerPixel);

        // The stream holds one pad byte per row on top of the pixels, so the
        // expected length is the stride times the height.
        int required = stride * height;
        if (stream.Length < required)
        {
            throw new InvalidDataException(
                $"an uncompressed {width}x{height} {bitsPerPixel} bpp bitmap needs "
                + $"{required} octets at a stride of {stride}, got {stream.Length}");
        }

        var pixels = new byte[width * height * 4];

        for (int y = 0; y < height; y++)
        {
            // The wire is bottom-up; the output is top-down, so source row
            // height-1-y is output row y.
            int sourceRow = height - 1 - y;
            int sourceStart = sourceRow * stride;

            for (int x = 0; x < width; x++)
            {
                int source = sourceStart + (x * bytesPerPixel);
                int destination = ((y * width) + x) * 4;
                WritePixel(stream, source, pixels.AsSpan(destination), bytesPerPixel, bitsPerPixel);
            }
        }

        return pixels;
    }

    /// <summary>
    /// The row stride in bytes: the pixel row padded out to a four-octet
    /// boundary (2.2.9.1.1.3.1.2.2).
    /// </summary>
    internal static int RowStride(int width, int bytesPerPixel) =>
        ((width * bytesPerPixel) + 3) & ~3;

    internal static int PixelBytesPerPixel(int bitsPerPixel) => bitsPerPixel switch
    {
        1 => 1,
        4 or 8 => 1,
        15 or 16 => 2,
        24 => 3,
        32 => 4,
        _ => throw new NotSupportedException(
            $"{bitsPerPixel} bpp bitmap data is not implemented"),
    };

    /// <summary>
    /// Write one pixel into the 32-bit BGRA output.
    /// </summary>
    /// <remarks>
    /// The output is BGRA rather than RGBA because that is what a WinUI
    /// <c>SoftwareBitmap</c> of BGRA8 wants, and converting once here is
    /// cheaper than converting per blit on the UI side.
    /// </remarks>
    private static void WritePixel(
        ReadOnlySpan<byte> source, int offset, Span<byte> destination, int bytesPerPixel, int bitsPerPixel)
    {
        switch (bitsPerPixel)
        {
            case 32:
                // A 32 bpp pixel is B, G, R, X in wire order, which is already
                // BGRA, so it is copied rather than reordered.
                destination[0] = source[offset];
                destination[1] = source[offset + 1];
                destination[2] = source[offset + 2];
                destination[3] = 0xFF;
                break;

            case 24:
                // Three octets per pixel, B G R.
                destination[0] = source[offset];
                destination[1] = source[offset + 1];
                destination[2] = source[offset + 2];
                destination[3] = 0xFF;
                break;

            case 16:
                // R5G6B5, little-endian.
                {
                    int value = source[offset] | (source[offset + 1] << 8);
                    destination[0] = (byte)((((value >> 0) & 0x1F) << 3) | (((value >> 0) & 0x1F) >> 2));
                    destination[1] = (byte)((((value >> 5) & 0x3F) << 2) | (((value >> 5) & 0x3F) >> 4));
                    destination[2] = (byte)((((value >> 11) & 0x1F) << 3) | (((value >> 11) & 0x1F) >> 2));
                    destination[3] = 0xFF;
                    break;
                }

            // 8 bpp is palettised: its colours live in a Palette Update
            // (2.2.9.1.1.3.1.1), which is not implemented, and 1 and 4 bpp are
            // monochrome modes no server this client talks to produces.
            // Rendering any of them as grey would produce a plausible-looking
            // image that is simply wrong, so they are refused instead.
            case 8:
                throw new NotSupportedException(
                    "8 bpp bitmap data is palettised and the palette update is not implemented");

            case 4:
            case 1:
                throw new NotSupportedException($"{bitsPerPixel} bpp bitmap data is not implemented");

            default:
                throw new NotSupportedException($"{bitsPerPixel} bpp is not implemented");
        }
    }
}