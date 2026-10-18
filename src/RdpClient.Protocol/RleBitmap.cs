namespace RdpClient.Protocol;

/// <summary>
/// Interleaved RLE decompressor for compressed bitmap data (MS-RDPBCGR
/// 2.2.9.1.1.3.1.2.4, RLE_BITMAP_STREAM).
/// </summary>
/// <remarks>
/// <para>
/// The format is scanline-relative: a background run copies the pixel above, a
/// foreground run copies the pixel above XOR'd with the current foreground
/// colour, and the first scanline has no pixel above, so "black" stands in for
/// it. A decoder that treats it as a flat stream produces an image that looks
/// almost right and is wrong everywhere a run referred upwards.
/// </para>
/// <para>
/// Three run-length forms share one code identifier space, and conflating them
/// is the most common way to get this wrong:
/// </para>
/// <list type="bullet">
/// <item><description>regular: 3-bit code, 5-bit length, a zero length meaning
/// "+32 from the following octet";</description></item>
/// <item><description>lite: 4-bit code, 4-bit length, a zero length meaning
/// "+16 from the following octet";</description></item>
/// <item><description>MEGA_MEGA: 8-bit code, length in the two following
/// octets, little-endian, with no offset.</description></item>
/// </list>
/// <para>
/// Two further details are easy to miss: a regular FGBG image order's length is
/// a count of <em>bitmask octets</em> and must be multiplied by eight, while
/// every other regular order's length counts pixels; and back-to-back background
/// runs need a one-pixel foreground run written between them so the second one
/// does not copy what the first just wrote.
/// </para>
/// </remarks>
internal static class RleBitmap
{
    private const int Regular = 0;
    private const int RegularFgRun = 1;
    private const int RegularFgbgImage = 2;
    private const int RegularColorRun = 3;
    private const int RegularColorImage = 4;

    private const int LiteSetFgFgRun = 0x0C;
    private const int LiteSetFgFgbgImage = 0x0D;
    private const int LiteDitheredRun = 0x0E;

    private const int MegaMegaBgRun = 0xF0;
    private const int MegaMegaFgRun = 0xF1;
    private const int MegaMegaFgbgImage = 0xF2;
    private const int MegaMegaColorRun = 0xF3;
    private const int MegaMegaColorImage = 0xF4;
    private const int MegaMegaSetFgRun = 0xF6;
    private const int MegaMegaSetFgFgbgImage = 0xF7;
    private const int MegaMegaDitheredRun = 0xF8;

    private const int SpecialFgbg1 = 0xF9;
    private const int SpecialFgbg2 = 0xFA;
    private const int White = 0xFD;
    private const int Black = 0xFE;

    internal static byte[] Decode(ReadOnlySpan<byte> stream, int width, int height, int bitsPerPixel)
    {
        int bytesPerPixel = UncompressedBitmap.PixelBytesPerPixel(bitsPerPixel);

        if (bytesPerPixel != 2)
        {
            // RLE is specified for the sub-32 bpp depths; a 32 bpp stream uses
            // the RDP 6.0 compressed form in [MS-RDPEGDI] 2.2.2.5.1 instead.
            throw new NotSupportedException(
                $"Interleaved RLE is not defined for {bitsPerPixel} bpp; a 32 bpp stream "
                + "uses the RDP 6.0 compressed form, which is not implemented");
        }

        int stride = width * bytesPerPixel;
        var destination = new byte[stride * height];

        // The output is top-down while the wire is bottom-up, so the decoder
        // fills a bottom-up buffer and flips it at the end rather than
        // translating coordinates on every write.
        int x = 0;
        int y = 0;
        int cursor = 0;
        int fgColor = 0xFFFF;
        bool secondRunOnFirstLine = false;

        while (cursor < stream.Length && y < height)
        {
            byte header = stream[cursor++];
            int code = header & 0xF0;
            int length = header & 0x0F;

            switch (code)
            {
                case Regular:
                    length = header & 0x1F;
                    if (length == 0)
                    {
                        length = 32 + ReadOctet(stream, ref cursor);
                    }
                    break;

                case LiteSetFgFgRun:
                case LiteSetFgFgbgImage:
                case LiteDitheredRun:
                    // A lite form packs the run length into four bits, so its
                    // extended run starts at 16 rather than the regular form's 32.
                    if (length == 0)
                    {
                        length = 16 + ReadOctet(stream, ref cursor);
                    }
                    break;

                case MegaMegaBgRun:
                case MegaMegaFgRun:
                case MegaMegaFgbgImage:
                case MegaMegaColorRun:
                case MegaMegaColorImage:
                case MegaMegaSetFgRun:
                case MegaMegaSetFgFgbgImage:
                case MegaMegaDitheredRun:
                    length = ReadU16(stream, ref cursor);
                    break;
            }

            switch (header)
            {
                case Regular or MegaMegaBgRun:
                    {
                        // Back-to-back background runs need a one-pixel
                        // foreground run between them, or the second copies what
                        // the first just wrote.
                        if (x == 0 && y > 0 && secondRunOnFirstLine)
                        {
                            WriteForeground(destination, stride, bytesPerPixel, x, y, 1, fgColor, stream, ref cursor);
                            x++;
                        }

                        secondRunOnFirstLine = y == 0 || y == 1;
                        WriteBackground(destination, stride, bytesPerPixel, x, y, length);
                        x += length;
                        break;
                    }

                case RegularFgRun or LiteSetFgFgRun or MegaMegaFgRun or MegaMegaSetFgRun:
                    {
                        if (header is MegaMegaSetFgRun or LiteSetFgFgRun)
                        {
                            fgColor = ReadU16(stream, ref cursor);
                        }

                        secondRunOnFirstLine = false;
                        WriteForeground(destination, stride, bytesPerPixel, x, y, length, fgColor, stream, ref cursor);
                        x += length;
                        break;
                    }

                case RegularFgbgImage or MegaMegaFgbgImage or LiteSetFgFgbgImage or MegaMegaSetFgFgbgImage:
                    {
                        if (header is MegaMegaSetFgFgbgImage or LiteSetFgFgbgImage)
                        {
                            fgColor = ReadU16(stream, ref cursor);
                        }

                        // A regular FGBG image's length counts bitmask octets,
                        // not pixels, so it is multiplied by eight here and
                        // nowhere else.
                        int pixels = header is RegularFgbgImage
                            ? length * 8
                            : header is LiteSetFgFgbgImage
                                ? (length == 0 ? 8 : length)
                                : length;

                        secondRunOnFirstLine = false;
                        WriteForegroundBackgroundImage(
                            destination, stride, bytesPerPixel, x, y, pixels, fgColor, stream, ref cursor);
                        x += pixels;
                        break;
                    }

                case RegularColorRun or MegaMegaColorRun:
                    {
                        int color = ReadU16(stream, ref cursor);
                        secondRunOnFirstLine = false;
                        WriteColor(destination, stride, bytesPerPixel, x, y, length, color);
                        x += length;
                        break;
                    }

                case RegularColorImage or MegaMegaColorImage:
                    {
                        secondRunOnFirstLine = false;
                        WriteColorImage(
                            destination, stride, bytesPerPixel, x, y, length, stream, ref cursor);
                        x += length;
                        break;
                    }

                case LiteDitheredRun or MegaMegaDitheredRun:
                    {
                        // A dithered run's length counts pixel pairs.
                        int foreground = ReadU16(stream, ref cursor);
                        int background = ReadU16(stream, ref cursor);
                        secondRunOnFirstLine = false;

                        for (int i = 0; i < length; i++)
                        {
                            WriteColor(destination, stride, bytesPerPixel, x, y, 1, foreground);
                            x++;
                            WriteColor(destination, stride, bytesPerPixel, x, y, 1, background);
                            x++;
                        }

                        break;
                    }

                case SpecialFgbg1:
                case SpecialFgbg2:
                    {
                        // These carry an 8-bit bitmask, so they are always eight
                        // pixels regardless of any length field.
                        secondRunOnFirstLine = false;
                        WriteForegroundBackgroundImage(
                            destination, stride, bytesPerPixel, x, y, 8, fgColor, stream, ref cursor);
                        x += 8;
                        break;
                    }

                case White:
                    secondRunOnFirstLine = false;
                    WriteColor(destination, stride, bytesPerPixel, x, y, 1, 0xFFFF);
                    x++;
                    break;

                case Black:
                    secondRunOnFirstLine = false;
                    WriteColor(destination, stride, bytesPerPixel, x, y, 1, 0x0000);
                    x++;
                    break;

                default:
                    throw new InvalidDataException(
                        $"RLE compression order 0x{header:x2} at offset {cursor - 1} is not "
                        + "defined by MS-RDPBCGR 2.2.9.1.1.3.1.2.4");
            }

            if (x >= width)
            {
                x = 0;
                y++;
            }
        }

        return FlipVertically(destination, stride, height);
    }

    /// <summary>Write a run that repeats the pixel above, or black on the first scanline.</summary>
    private static void WriteBackground(
        byte[] destination, int stride, int bytesPerPixel, int x, int y, int length)
    {
        for (int i = 0; i < length; i++)
        {
            int column = x + i;
            if (column >= stride / bytesPerPixel)
            {
                break;
            }

            int offset = (y * stride) + (column * bytesPerPixel);

            if (y == 0)
            {
                // No scanline above, so "the pixel above" is black.
                destination[offset] = 0;
                destination[offset + 1] = 0;
            }
            else
            {
                int above = offset - stride;
                destination[offset] = destination[above];
                destination[offset + 1] = destination[above + 1];
            }
        }
    }

    /// <summary>
    /// Write a run of the current foreground colour: the pixel above XOR'd with
    /// it, or the colour itself on the first scanline.
    /// </summary>
    private static void WriteForeground(
        byte[] destination, int stride, int bytesPerPixel,
        int x, int y, int length, int foreground, ReadOnlySpan<byte> stream, ref int cursor)
    {
        _ = stream;
        _ = cursor;

        for (int i = 0; i < length; i++)
        {
            int column = x + i;
            if (column >= stride / bytesPerPixel)
            {
                break;
            }

            int offset = (y * stride) + (column * bytesPerPixel);
            int value;

            if (y == 0)
            {
                value = foreground;
            }
            else
            {
                int above = offset - stride;
                int previous = destination[above] | (destination[above + 1] << 8);
                value = previous ^ foreground;
            }

            destination[offset] = (byte)(value & 0xFF);
            destination[offset + 1] = (byte)(value >> 8);
        }
    }

    /// <summary>
    /// Write a binary image: each bit selects the foreground run or the
    /// background run for one pixel, bits from the low end of each octet.
    /// </summary>
    private static void WriteForegroundBackgroundImage(
        byte[] destination, int stride, int bytesPerPixel,
        int x, int y, int pixels, int foreground, ReadOnlySpan<byte> stream, ref int cursor)
    {
        for (int i = 0; i < pixels; i++)
        {
            int bitIndex = i / 8;
            if (cursor + bitIndex >= stream.Length)
            {
                break;
            }

            int bit = (stream[cursor + bitIndex] >> (i % 8)) & 1;
            int column = x + i;
            if (column >= stride / bytesPerPixel)
            {
                break;
            }

            int offset = (y * stride) + (column * bytesPerPixel);

            if (bit == 1)
            {
                if (y == 0)
                {
                    destination[offset] = (byte)(foreground & 0xFF);
                    destination[offset + 1] = (byte)(foreground >> 8);
                }
                else
                {
                    int above = offset - stride;
                    int previous = destination[above] | (destination[above + 1] << 8);
                    int value = previous ^ foreground;
                    destination[offset] = (byte)(value & 0xFF);
                    destination[offset + 1] = (byte)(value >> 8);
                }
            }
            else
            {
                if (y == 0)
                {
                    destination[offset] = 0;
                    destination[offset + 1] = 0;
                }
                else
                {
                    int above = offset - stride;
                    destination[offset] = destination[above];
                    destination[offset + 1] = destination[above + 1];
                }
            }
        }

        cursor += (pixels + 7) / 8;
    }

    /// <summary>Write a run of one repeated colour.</summary>
    private static void WriteColor(
        byte[] destination, int stride, int bytesPerPixel, int x, int y, int length, int color)
    {
        for (int i = 0; i < length; i++)
        {
            int column = x + i;
            if (column >= stride / bytesPerPixel)
            {
                break;
            }

            int offset = (y * stride) + (column * bytesPerPixel);
            destination[offset] = (byte)(color & 0xFF);
            destination[offset + 1] = (byte)(color >> 8);
        }
    }

    /// <summary>Write a run of literal pixels copied straight from the stream.</summary>
    private static void WriteColorImage(
        byte[] destination, int stride, int bytesPerPixel,
        int x, int y, int length, ReadOnlySpan<byte> stream, ref int cursor)
    {
        int bytes = length * bytesPerPixel;

        if (cursor + bytes > stream.Length)
        {
            bytes = stream.Length - cursor;
        }

        if (bytes <= 0)
        {
            return;
        }

        int available = (stride / bytesPerPixel) - x;
        if (bytes > available * bytesPerPixel)
        {
            bytes = available * bytesPerPixel;
        }

        stream.Slice(cursor, bytes).CopyTo(destination.AsSpan((y * stride) + (x * bytesPerPixel)));
        cursor += bytes;
    }

    /// <summary>
    /// Turn the bottom-up decoder output into the top-down order callers want,
    /// expanding each R5G6B5 pixel to 32-bit BGRA.
    /// </summary>
    private static byte[] FlipVertically(byte[] bottomUp, int stride, int height)
    {
        int width = stride / 2;
        var pixels = new byte[width * height * 4];

        for (int y = 0; y < height; y++)
        {
            int sourceRow = height - 1 - y;

            for (int x = 0; x < width; x++)
            {
                int source = (sourceRow * stride) + (x * 2);
                int value = bottomUp[source] | (bottomUp[source + 1] << 8);
                int destination = ((y * width) + x) * 4;

                pixels[destination] = (byte)((((value >> 0) & 0x1F) << 3) | (((value >> 0) & 0x1F) >> 2));
                pixels[destination + 1] = (byte)((((value >> 5) & 0x3F) << 2) | (((value >> 5) & 0x3F) >> 4));
                pixels[destination + 2] = (byte)((((value >> 11) & 0x1F) << 3) | (((value >> 11) & 0x1F) >> 2));
                pixels[destination + 3] = 0xFF;
            }
        }

        return pixels;
    }

    private static byte ReadOctet(ReadOnlySpan<byte> stream, ref int cursor) =>
        cursor < stream.Length ? stream[cursor++] : (byte)0;

    private static int ReadU16(ReadOnlySpan<byte> stream, ref int cursor)
    {
        if (cursor + 1 >= stream.Length)
        {
            cursor = stream.Length;
            return 0;
        }

        int value = stream[cursor] | (stream[cursor + 1] << 8);
        cursor += 2;
        return value;
    }
}