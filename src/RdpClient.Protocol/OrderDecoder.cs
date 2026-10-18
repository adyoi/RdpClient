namespace RdpClient.Protocol;

/// <summary>
/// Decodes GDI drawing orders (MS-RDPEGDI 2.2.2.2.1) and renders them onto a
/// <see cref="ScreenSurface"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the other half of Basic Output from the bitmap path. A server that
/// sends orders encodes the drawing operations rather than the pixels, which is
/// what makes it usable over a slow link; xrdp always sends orders, so without
/// this a client that negotiated with it gets a connection and no screen.
/// </para>
/// <para>
/// Primary orders carry almost no data. Every field is optional on the wire and
/// absent fields keep their previous value, and both the previous values and
/// the previous bounds are part of the session state rather than of any one
/// PDU. That is why the decoder is a stateful class rather than a function:
/// two identical orders mean different things depending on what preceded them,
/// and a decoder that treats an order as self-contained draws the wrong thing
/// without any error.
/// </para>
/// <para>
/// The initial values are fixed by the specification: every field is zero, the
/// order type is <c>TS_ENC_PATBLT_ORDER</c>, and the bounds are the zero
/// rectangle. They matter, because the first order a server sends is usually a
/// type change that omits coordinates on the assumption they are already zero.
/// </para>
/// </remarks>
public sealed class OrderDecoder
{
    // controlFlags (2.2.2.2.1.1).
    private const byte TsStandard = 0x01;
    private const byte TsSecondary = 0x02;
    private const byte TsBounds = 0x04;
    private const byte TsTypeChange = 0x08;
    private const byte TsDeltaCoordinates = 0x10;
    private const byte TsZeroBoundsDeltas = 0x20;

    // Bounds flags (2.2.2.2.1.1.3).
    private const byte BoundLeft = 0x01;
    private const byte BoundTop = 0x02;
    private const byte BoundRight = 0x04;
    private const byte BoundBottom = 0x08;
    private const byte BoundDeltaLeft = 0x10;
    private const byte BoundDeltaTop = 0x20;
    private const byte BoundDeltaRight = 0x40;
    private const byte BoundDeltaBottom = 0x80;

    // Primary order types (2.2.2.2.1.1.2).
    private const int OrderDstBlt = 0x00;
    private const int OrderPatBlt = 0x01;
    private const int OrderScrBlt = 0x02;
    private const int OrderLineTo = 0x09;
    private const int OrderOpaqueRect = 0x0A;
    private const int OrderMemBlt = 0x0D;
    private const int OrderFastIndex = 0x13;
    private const int OrderFastGlyph = 0x18;
    private const int OrderGlyphIndex = 0x1B;

    // Secondary order types (2.2.2.2.1.2.1.1).
    private const int SecondaryCacheBitmapUncompressed = 0x00;
    private const int SecondaryCacheColorTable = 0x01;
    private const int SecondaryCacheBitmapCompressed = 0x02;
    private const int SecondaryCacheGlyph = 0x03;
    private const int SecondaryCacheBitmapUncompressedRev2 = 0x04;
    private const int SecondaryCacheBitmapCompressedRev2 = 0x05;
    private const int SecondaryCacheBrush = 0x07;
    private const int SecondaryCacheBitmapCompressedRev3 = 0x08;

    /// <summary>The order type the specification fixes as the initial value.</summary>
    private const int InitialOrderType = OrderPatBlt;

    private readonly ScreenSurface _surface;
    private readonly int _desktopWidth;
    private readonly int _desktopHeight;

    // Per-order-type field state, which is what makes the orders incremental.
    private readonly Dictionary<int, int[]> _fields = [];

    private int _orderType = InitialOrderType;
    private int _left;
    private int _top;
    private int _right;
    private int _bottom;

    // Secondary-order caches, indexed by cache id.
    private readonly Dictionary<int, CachedBitmap> _bitmapCache = [];
    private readonly Dictionary<int, CachedBitmap> _brushCache = [];

    /// <summary>How many orders have been decoded since the connection began.</summary>
    public int OrdersDecoded { get; private set; }

    /// <summary>How many of those have been rendered onto the surface.</summary>
    public int OrdersRendered { get; private set; }

    /// <summary>The last order type seen, named for a log line.</summary>
    public string LastOrder { get; private set; } = "none";

    public OrderDecoder(ScreenSurface surface)
    {
        ArgumentNullException.ThrowIfNull(surface);

        _surface = surface;
        _desktopWidth = surface.Width;
        _desktopHeight = surface.Height;
    }

    /// <summary>
    /// Decode the orders in one Orders Update body: updateType(2), pad2OctetsA(2),
    /// numberOrders(2), pad2OctetsB(2), then the packed orders.
    /// </summary>
    /// <remarks>
    /// The two pad fields are genuinely arbitrary and are skipped by offset,
    /// not read: one of them sits between the update type and the count, which
    /// is the offset a decoder that assumes updateType then count gets wrong.
    /// </remarks>
    public void ExecuteOrdersUpdate(ReadOnlySpan<byte> body)
    {
        // MS-RDPEGDI 2.2.2.1: updateType(2), pad2OctetsA(2), numberOrders(2),
        // pad2OctetsB(2), then orderData. The count is the third field, not
        // the second: reading it at offset 2 reads pad2OctetsA, which is
        // arbitrary, and the orders then begin at the wrong offset.
        const int FixedFields = 8;
        if (body.Length < FixedFields)
        {
            throw new InvalidDataException(
                $"an Orders Update needs {FixedFields} octets of fields, got {body.Length}");
        }

        int numberOrders = ReadU16(body, 4);
        var reader = new SpanReader(body.Slice(FixedFields));

        for (int i = 0; i < numberOrders; i++)
        {
            if (!DecodeOne(ref reader))
            {
                break;
            }
        }
    }

    /// <summary>Decode one order from the reader, advancing it past the order.</summary>
    private bool DecodeOne(ref SpanReader reader)
    {
        byte controlFlags = reader.U8();
        bool isPrimary = (controlFlags & TsStandard) != 0;
        bool isSecondary = (controlFlags & TsSecondary) != 0;

        if (isPrimary)
        {
            DecodePrimary(ref reader, controlFlags);
            return true;
        }

        if (isSecondary)
        {
            // 2.2.2.2.1.2.1.1: orderLength(2) extraFlags(2) orderType(1), then
            // the body. orderLength is thirteen less than the real length, a
            // historical quirk, so the header is added back before anything is
            // stepped over.
            int declaredLength = reader.I16() + 13;
            int extraFlags = reader.U16();
            byte orderType = reader.U8();

            int available = reader.Remaining;
            int bodyLength = Math.Min(declaredLength - 6, available);

            if (bodyLength <= 0)
            {
                return false;
            }

            if (orderType == SecondaryCacheColorTable)
            {
                _surface.Clear(0, 0, 0);
            }
            else
            {
                CacheSecondary(orderType, extraFlags, reader.Slice(bodyLength));
            }

            reader.Skip(bodyLength);
            OrdersDecoded++;
            return true;
        }

        // An alternate secondary order's header is a single octet whose low six
        // bits are the order type (2.2.2.2.1.3.1.1). Unlike a secondary order it
        // carries no length, so each type's own layout has to give one; the
        // fixed-size types are handled here and the streamed ones are refused
        // rather than stepped over by a guess.
        int altType = controlFlags & 0x3F;
        int altLength = AlternateSecondaryLength(altType, reader);

        if (altLength < 0)
        {
            throw new NotSupportedException(
                $"alternate secondary drawing order type {altType:x2} has no fixed "
                + "length, so the next order's boundary cannot be found");
        }

        if (altLength > reader.Remaining)
        {
            return false;
        }

        OrdersDecoded++;
        reader.Skip(altLength);
        return true;
    }

    /// <summary>
    /// The length of an alternate secondary order, or -1 when its length is not
    /// derivable from the octets that follow.
    /// </summary>
    private static int AlternateSecondaryLength(int orderType, SpanReader reader)
    {
        // header(1) plus the order's own fields (2.2.2.2.1.3).
        return orderType switch
        {
            0x00 => 3,                       // Switch Surface: bitmapId(2)
            0x01 => OffscreenBitmapLength(reader),
            0x0B => 3,                       // Windowing: windowId(2)
            0x0C => 6,                       // Desktop Composition: 2 * uint32
            0x0D => 6,                       // Frame Marker: frameMarker(4) + frameAction(1)
            _ => -1,
        };
    }

    /// <summary>
    /// Create Offscreen Bitmap is header, flags(2), cx(2), cy(2), and then a
    /// delete list whose length depends on the flags' <c>d</c> bit and on the
    /// cache's own encoding, so it is only computed when the list is absent.
    /// </summary>
    private static int OffscreenBitmapLength(SpanReader reader)
    {
        if (reader.Remaining < 6)
        {
            return -1;
        }

        // flags(2) cx(2) cy(2); the d bit in flags says whether a delete
        // list follows, and this client advertises no offscreen cache, so an
        // order that carries one cannot be stepped over safely.
        int flags = reader.U16() | (reader.U16() << 16);
        int cx = reader.U16();
        int cy = reader.U16();

        _ = cx;
        _ = cy;

        return (flags & 0x0001) != 0 ? -1 : 7;
    }

    private void DecodePrimary(ref SpanReader reader, byte controlFlags)
    {
        bool deltaCoordinates = (controlFlags & TsDeltaCoordinates) != 0;

        if ((controlFlags & TsTypeChange) != 0)
        {
            _orderType = reader.U8();
        }

        int fieldCount = FieldCountFor(_orderType);

        // fieldFlags is ceil((fields + 1) / 8) octets, and the two zero-field
        // bits in controlFlags say how many of those octets are omitted from the
        // end of the set. Reading a fixed one octet only works for the orders
        // that have seven fields or fewer, which is where a decoder that does so
        // starts desynchronising on the very first PatBlt.
        int flagBytes = (fieldCount + 1 + 7) / 8;
        int zeroBytes = (controlFlags >> 6) & 0x03;
        int presentBytes = Math.Max(flagBytes - zeroBytes, 1);

        uint fieldFlags = 0;
        for (int i = 0; i < presentBytes; i++)
        {
            fieldFlags |= (uint)reader.U8() << (i * 8);
        }

        // Bounds come before the order's own fields.
        if ((controlFlags & TsBounds) != 0 && (controlFlags & TsZeroBoundsDeltas) == 0)
        {
            DecodeBounds(ref reader);
        }

        int[] state = FieldsFor(_orderType);
        bool delta = deltaCoordinates;

        switch (_orderType)
        {
            case OrderDstBlt:
                ReadRect(ref reader, state, fieldFlags, delta, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 4);
                RenderBitBlt(state[0], state[1], state[2], state[3], state[4]);
                break;

            case OrderScrBlt:
                ReadRect(ref reader, state, fieldFlags, delta, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 4);
                RenderBitBlt(state[0], state[1], state[2], state[3], state[4]);
                break;

            case OrderOpaqueRect:
                ReadRect(ref reader, state, fieldFlags, delta, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 5);
                ReadOptionalU8(ref reader, state, fieldFlags, 6);
                RenderSolidRect(state[0], state[1], state[2], state[3], state[4], state[5], state[6]);
                break;

            case OrderMemBlt:
                ReadRect(ref reader, state, fieldFlags, delta, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 4);
                ReadOptionalU8(ref reader, state, fieldFlags, 5);
                // Field 6 is nDeltaEntries followed by a CodedDeltaList, whose
                // extent is not derivable from a field count alone. MemBlt from
                // a cache this client does not maintain renders nothing, so the
                // fields are consumed and the list skipped rather than decoded.
                RenderMemBlt(state[0], state[1], state[2], state[3], state[5]);
                break;

            case OrderFastIndex:
            case OrderFastGlyph:
            case OrderGlyphIndex:
                ReadGlyphFields(ref reader, state, fieldFlags, delta);
                RenderGlyph(_orderType, state);
                break;

            case OrderPatBlt:
            case OrderLineTo:
            default:
                // The remaining order types either need a cache this client does
                // not build or are shapes. They are skipped rather than guessed,
                // and the count of them is reported so a blank screen is
                // distinguishable from a decode that never ran.
                SkipOrderFields(ref reader, fieldCount, fieldFlags, delta);
                break;
        }

        OrdersDecoded++;
        LastOrder = DescribeOrderType(_orderType);
    }

    /// <summary>
    /// Read a rectangle's four coordinates from the present fields, honouring
    /// the delta encoding.
    /// </summary>
    private void ReadRect(
        ref SpanReader reader, int[] state, uint fieldFlags, bool delta, int firstField)
    {
        for (int i = 0; i < 4; i++)
        {
            int field = firstField + i;

            if ((fieldFlags & (1u << field)) != 0)
            {
                state[field] = delta
                    ? state[field] + reader.I8()
                    : reader.I16();
            }
        }
    }

    private static void ReadOptionalU8(ref SpanReader reader, int[] state, uint fieldFlags, int field)
    {
        if ((fieldFlags & (1u << field)) != 0)
        {
            state[field] = reader.U8();
        }
    }

    private void DecodeBounds(ref SpanReader reader)
    {
        byte flags = reader.U8();

        _left = ReadBound(ref reader, flags, BoundLeft, BoundDeltaLeft, _left);
        _top = ReadBound(ref reader, flags, BoundTop, BoundDeltaTop, _top);
        _right = ReadBound(ref reader, flags, BoundRight, BoundDeltaRight, _right);
        _bottom = ReadBound(ref reader, flags, BoundBottom, BoundDeltaBottom, _bottom);
    }

    /// <summary>
    /// Read one bound. The non-delta flag wins when both are set, which the
    /// specification says explicitly rather than leaving it to the reader.
    /// </summary>
    private static int ReadBound(ref SpanReader reader, byte flags, byte absolute, byte delta, int previous)
    {
        if ((flags & absolute) != 0)
        {
            return reader.I16();
        }

        if ((flags & delta) != 0)
        {
            return previous + reader.I8();
        }

        return previous;
    }

    private void ReadGlyphFields(ref SpanReader reader, int[] state, uint fieldFlags, bool delta)
    {
        // A glyph order's fields differ per type and its trailing data is not
        // field-counted, so only the geometry is read; the cache entry and the
        // glyph data are left for a glyph cache this client does not maintain.
        ReadRect(ref reader, state, fieldFlags, delta, 0);
        ReadOptionalU8(ref reader, state, fieldFlags, 4);
        ReadOptionalU16(ref reader, state, fieldFlags, 5);
    }

    private static void ReadOptionalU16(ref SpanReader reader, int[] state, uint fieldFlags, int field)
    {
        if ((fieldFlags & (1u << field)) != 0)
        {
            state[field] = reader.U16();
        }
    }

    /// <summary>
    /// Step over an order's fields without interpreting them, which is what an
    /// unimplemented order needs: the next order starts at a byte boundary and
    /// this is where that boundary is.
    /// </summary>
    private static void SkipOrderFields(
        ref SpanReader reader, int fieldCount, uint fieldFlags, bool delta)
    {
        int size = delta ? 1 : 2;

        for (int field = 0; field < fieldCount && field < 16; field++)
        {
            if ((fieldFlags & (1u << field)) != 0)
            {
                reader.Skip(size);
            }
        }
    }

    // --- Rendering ---------------------------------------------------------

    private void RenderSolidRect(int left, int top, int width, int height, int red, int green, int blue)
    {
        _surface.FillRect(left, top, width, height, (byte)red, (byte)green, (byte)blue);
        OrdersRendered++;
    }

    /// <summary>
    /// A destination-only or screen-to-screen blit. With no source and a ROP3
    /// that depends only on the destination, the interesting case is the copy
    /// (0x00) and its many spellings; anything that samples a pattern the
    /// client does not hold leaves the destination alone.
    /// </summary>
    private void RenderBitBlt(int left, int top, int width, int height, int rop)
    {
        // ROP3 0x00CC is a straight copy. Its inverted spellings (0x00AA and
        // 0x0055) are the same shape, so the index is tested rather than the
        // whole byte: a server may send either.
        if ((rop & 0xF0) == 0x00 && ((rop & 0x0F) == 0x0C || (rop & 0x33) == 0x00))
        {
            _surface.CopyRect(left, top, left, top, width, height);
        }

        OrdersRendered++;
    }

    private void RenderMemBlt(int left, int top, int width, int height, int cacheId)
    {
        if (_bitmapCache.TryGetValue(cacheId, out CachedBitmap? cached))
        {
            _surface.BlitCachedBitmap(cached.Pixels, cached.Width, cached.Height, cached.RowBytes, left, top);
        }

        OrdersRendered++;
    }

    private void RenderGlyph(int orderType, int[] state)
    {
        // A glyph's pixels come from the glyph cache, which this client does not
        // maintain. The geometry is still parsed so the stream stays aligned.
        _ = orderType;
        _ = state;
        OrdersRendered++;
    }

    private void CacheSecondary(int orderType, int extraFlags, ReadOnlySpan<byte> body)
    {
        switch (orderType)
        {
            case SecondaryCacheBitmapUncompressed:
            case SecondaryCacheBitmapCompressed:
            case SecondaryCacheBitmapUncompressedRev2:
            case SecondaryCacheBitmapCompressedRev2:
            case SecondaryCacheBitmapCompressedRev3:
                {
                    // Revision 1 (2.2.2.2.1.2.2) and revision 2 (2.2.2.2.1.2.3)
                    // differ in the fields before the pixel data; revision 3
                    // (2.2.2.2.1.2.8) is a bitmap cache entry plus an RLE or
                    // RemoteFX stream. Only revision 1 uncompressed is decoded
                    // here, which is what xrdp sends for its own backing store.
                    if (orderType == SecondaryCacheBitmapUncompressed && body.Length >= 25)
                    {
                        int cacheId = body[0];
                        int width = ReadU16(body, 1);
                        int height = ReadU16(body, 3);

                        // 2.2.2.2.1.2.2: cacheId(1) flags(1) width(2) height(2)
                        // then six one-byte lengths, one per pad octet, then the
                        // bitmap. The pad lengths are the count of padding octets
                        // on each row, which a decoder that ignores them shears.
                        var padding = new int[6];
                        for (int i = 0; i < 6; i++)
                        {
                            padding[i] = body[5 + i];
                        }

                        int bitsPerPixel = 16;
                        int rowBytes = ((width * bitsPerPixel) + 7) / 8;

                        // The header is 25 octets in revision 1: the eleven above
                        // plus the fourteen-octet TS_BITMAP_DATA_EXISTING
                        // header that follows.
                        const int HeaderLength = 25;
                        if (width > 0 && height > 0 && body.Length >= HeaderLength + (rowBytes * height))
                        {
                            _bitmapCache[cacheId] = new CachedBitmap(
                                width, height, rowBytes,
                                body.Slice(HeaderLength, rowBytes * height).ToArray());
                        }
                    }

                    break;
                }

            case SecondaryCacheBrush:
                {
                    // 2.2.2.2.1.2.7: cacheId(1) style(1) width(2) height(2),
                    // then rows padded to the style's alignment.
                    if (body.Length >= 6)
                    {
                        int cacheId = body[0];
                        int style = body[1];
                        int width = ReadU16(body, 2);
                        int height = ReadU16(body, 4);

                        if (width > 0 && height > 0)
                        {
                            int rowBytes = style switch
                            {
                                0 => width * 2,
                                1 => ((width + 7) / 8) + 4,
                                _ => width,
                            };

                            if (body.Length >= 6 + (rowBytes * height))
                            {
                                _brushCache[cacheId] = new CachedBitmap(
                                    width, height, rowBytes, body.Slice(6, rowBytes * height).ToArray());
                            }
                        }
                    }

                    break;
                }

            case SecondaryCacheGlyph:
                // Glyph caches are not maintained; the order is stepped over so
                // the stream stays aligned.
                _ = extraFlags;
                break;
        }
    }

    // --- State -------------------------------------------------------------

    private int[] FieldsFor(int orderType)
    {
        if (!_fields.TryGetValue(orderType, out int[]? state))
        {
            state = new int[FieldCountFor(orderType)];
            _fields[orderType] = state;
        }

        return state;
    }

    /// <summary>The number of fields each order type has (MS-RDPEGDI 2.2.2.2.1.1.2).</summary>
    private static int FieldCountFor(int orderType) => orderType switch
    {
        OrderDstBlt => 5,           // left, top, width, height, rop
        OrderScrBlt => 5,
        OrderOpaqueRect => 7,       // ... plus red, green, blue
        OrderMemBlt => 7,           // ... plus rop, deltaEntries, deltaList
        OrderPatBlt => 8,
        OrderLineTo => 7,
        OrderFastIndex => 7,
        OrderFastGlyph => 9,
        OrderGlyphIndex => 10,
        _ => 5,
    };

    public static string DescribeOrderType(int orderType) => orderType switch
    {
        OrderDstBlt => "DstBlt",
        OrderPatBlt => "PatBlt",
        OrderScrBlt => "ScrBlt",
        OrderLineTo => "LineTo",
        OrderOpaqueRect => "OpaqueRect",
        OrderMemBlt => "MemBlt",
        OrderFastIndex => "FastIndex",
        OrderFastGlyph => "FastGlyph",
        OrderGlyphIndex => "GlyphIndex",
        _ => $"order {orderType}",
    };

    private sealed record CachedBitmap(int Width, int Height, int RowBytes, byte[] Pixels);

    private static int ReadU16(ReadOnlySpan<byte> data, int offset) =>
        data[offset] | (data[offset + 1] << 8);
}

/// <summary>
/// A forward-only reader over a drawing order stream.
/// </summary>
/// <remarks>
/// A ref struct so it can hold a <see cref="ReadOnlySpan{T}"/> field directly:
/// a byte array would mean copying every order out of the MCS buffer and back,
/// and the orders are the bulk of what the server sends.
/// </remarks>
internal ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _offset;

    internal SpanReader(ReadOnlySpan<byte> data) => _data = data;

    internal int Remaining => _data.Length - _offset;

    internal ReadOnlySpan<byte> Slice(int length) =>
        _data.Slice(_offset, Math.Min(length, Remaining));

    internal void Skip(int count) => _offset += Math.Min(count, Remaining);

    internal byte U8()
    {
        if (Remaining < 1)
        {
            throw new InvalidDataException(
                "a drawing order ended before its declared fields");
        }

        return _data[_offset++];
    }

    internal ushort U16()
    {
        if (Remaining < 2)
        {
            throw new InvalidDataException(
                "a drawing order ended before its declared fields");
        }

        ushort value = (ushort)(_data[_offset] | (_data[_offset + 1] << 8));
        _offset += 2;
        return value;
    }

    internal short I16() => unchecked((short)U16());

    internal sbyte I8() => unchecked((sbyte)U8());
}