namespace RdpClient.Protocol;

/// <summary>
/// A desktop-sized BGRA surface that bitmap updates are painted onto.
/// </summary>
/// <remarks>
/// The server sends rectangular clippings, not frames, so something has to
/// accumulate them into a whole screen. Keeping that here rather than in the
/// connection class is what lets the parser be tested without a socket: the
/// decoder produces rectangles and this composes them.
/// </remarks>
public sealed class ScreenSurface
{
    private readonly byte[] _pixels;

    public int Width { get; }

    public int Height { get; }

    public ScreenSurface(int width, int height)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(width);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(height);

        Width = width;
        Height = height;
        _pixels = new byte[width * height * 4];
    }

    /// <summary>The surface as top-down BGRA, which is the layout a WinUI image wants.</summary>
    public ReadOnlyMemory<byte> Pixels => _pixels;

    /// <summary>
    /// Paint one decoded rectangle, clipping it to the surface.
    /// </summary>
    /// <remarks>
    /// Clipping is not defensive padding: the server is free to send a rectangle
    /// that runs past the desktop it declared, and writing past the buffer
    /// would be a heap corruption rather than a visible glitch. A rectangle
    /// entirely outside the surface is dropped and reported as not painted.
    /// </remarks>
    /// <returns>The number of pixels actually painted.</returns>
    public int Paint(BitmapUpdate.BitmapRectangle rectangle)
    {
        ArgumentNullException.ThrowIfNull(rectangle);

        int painted = 0;

        for (int y = 0; y < rectangle.Height; y++)
        {
            int targetY = rectangle.DestinationTop + y;
            if (targetY < 0 || targetY >= Height)
            {
                continue;
            }

            for (int x = 0; x < rectangle.Width; x++)
            {
                int targetX = rectangle.DestinationLeft + x;
                if (targetX < 0 || targetX >= Width)
                {
                    continue;
                }

                int source = ((y * rectangle.Width) + x) * 4;
                int destination = ((targetY * Width) + targetX) * 4;

                _pixels[destination] = rectangle.Pixels[source];
                _pixels[destination + 1] = rectangle.Pixels[source + 1];
                _pixels[destination + 2] = rectangle.Pixels[source + 2];
                _pixels[destination + 3] = 0xFF;
                painted++;
            }
        }

        return painted;
    }

    /// <summary>Fill the whole surface with one colour, as a black desktop starts.</summary>
    public void Clear(byte r, byte g, byte b)
    {
        for (int i = 0; i < _pixels.Length; i += 4)
        {
            _pixels[i] = b;
            _pixels[i + 1] = g;
            _pixels[i + 2] = r;
            _pixels[i + 3] = 0xFF;
        }
    }

    /// <summary>
    /// Write the surface as a 32-bit uncompressed BMP, for verifying a decode
    /// outside the GUI.
    /// </summary>
    /// <remarks>
    /// A BMP is used rather than a PNG because it needs no encoder: the point is
    /// to be able to look at what the decoder produced, and a 54-octet header is
    /// cheaper than a deflate implementation.
    /// </remarks>
    public byte[] ToBmp()
    {
        const int HeaderSize = 54;
        int stride = ((Width * 3) + 3) & ~3;    // BMP rows are padded to four octets
        int pixelBytes = stride * Height;
        var bmp = new byte[HeaderSize + pixelBytes];

        // BITMAPFILEHEADER: "BM", the file size, zero reserved, the data offset.
        bmp[0] = (byte)'B';
        bmp[1] = (byte)'M';
        WriteI32(bmp, 2, HeaderSize + pixelBytes);
        WriteI32(bmp, 10, HeaderSize);

        // BITMAPINFOHEADER: 40 octets, a 24 bpp DIB, uncompressed.
        WriteI32(bmp, 14, 40);
        WriteI32(bmp, 18, Width);
        WriteI32(bmp, 22, Height);            // positive: bottom-up, matching the format
        WriteI16(bmp, 26, 1);
        WriteI16(bmp, 28, 24);
        WriteI32(bmp, 34, pixelBytes);

        for (int y = 0; y < Height; y++)
        {
            int sourceRow = Height - 1 - y;    // BMP is bottom-up
            int rowStart = HeaderSize + (y * stride);

            for (int x = 0; x < Width; x++)
            {
                int source = ((sourceRow * Width) + x) * 4;
                int destination = rowStart + (x * 3);

                // The surface is BGRA; a 24 bpp BMP row is BGR.
                bmp[destination] = _pixels[source];
                bmp[destination + 1] = _pixels[source + 1];
                bmp[destination + 2] = _pixels[source + 2];
            }
        }

        return bmp;
    }

    private static void WriteI32(byte[] buffer, int offset, int value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
        buffer[offset + 2] = (byte)((value >> 16) & 0xFF);
        buffer[offset + 3] = (byte)((value >> 24) & 0xFF);
    }

    private static void WriteI16(byte[] buffer, int offset, int value)
    {
        buffer[offset] = (byte)(value & 0xFF);
        buffer[offset + 1] = (byte)((value >> 8) & 0xFF);
    }
}