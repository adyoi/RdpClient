using RdpClient.Protocol;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for the drawing order decoder (MS-RDPEGDI 2.2.2.2.1).
/// </summary>
/// <remarks>
/// Each case pins a defect that was found by tracing a live orders update from
/// xrdp rather than by reading the specification, which is the reason they are
/// phrased as byte counts rather than as rendered pixels: an order stream that
/// is one octet out of step still produces plausible-looking orders for as long
/// as the bytes ahead of it happen to decode, and the first symptom is an order
/// type the specification does not define. What actually settles each of these
/// is whether the decoder stops exactly at the end of the order data.
/// </remarks>
public class OrderDecoderTests
{
    /// <summary>
    /// A secondary order sets both TS_STANDARD and TS_SECONDARY, and must take
    /// the secondary path (MS-RDPEGDI 2.2.2.1.1).
    /// </summary>
    /// <remarks>
    /// Testing TS_STANDARD first sends every secondary order down the primary
    /// path. The stream then desynchronises at the first Cache Bitmap, and
    /// because the primary path never fails, it does so silently: it reads the
    /// order's own header bytes as field flags and walks onward.
    /// </remarks>
    [Fact]
    public void SecondaryOrder_SettingBothClassBits_IsNotReadAsPrimary()
    {
        // controlFlags, orderLength(2), extraFlags(2), orderType(1), body(10):
        // sixteen octets in total, so orderLength is 16 - 13 = 3.
        byte[] orderData =
        [
            0x03,                   // TS_STANDARD | TS_SECONDARY
            0x03, 0x00,             // orderLength
            0x00, 0x00,             // extraFlags
            0x01,                   // TS_CACHE_COLOR_TABLE
            0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        var decoder = new OrderDecoder(new ScreenSurface(4, 4));
        decoder.ExecuteOrdersUpdate(OrdersUpdate(1, orderData));

        Assert.Equal(1, decoder.OrdersInLastUpdate);
        Assert.Equal(0, decoder.BytesLeftAfterLastUpdate);
    }

    /// <summary>
    /// Switch Surface is header plus a two-octet bitmapId, so it is three
    /// octets in total (MS-RDPEGDI 2.2.2.2.1.3.3).
    /// </summary>
    /// <remarks>
    /// The specification states an alternate secondary order's length including
    /// its header octet, but the caller has already consumed that octet before
    /// asking. Returning the specification's figure therefore skips one octet
    /// too many per order, and the stream drifts by one each time without ever
    /// failing outright.
    /// </remarks>
    [Fact]
    public void AlternateSecondary_SwitchSurface_ConsumesThreeOctets()
    {
        byte[] orderData = [0x00, 0xFF, 0xFF];

        var decoder = new OrderDecoder(new ScreenSurface(4, 4));
        decoder.ExecuteOrdersUpdate(OrdersUpdate(1, orderData));

        Assert.Equal(1, decoder.OrdersInLastUpdate);
        Assert.Equal(0, decoder.BytesLeftAfterLastUpdate);
    }

    /// <summary>
    /// numberOrders is the third field of the Orders Update, not the second
    /// (MS-RDPEGDI 2.2.2.1).
    /// </summary>
    /// <remarks>
    /// pad2OctetsA sits between the update type and the count and is
    /// arbitrary. Reading the count at offset 2 reads that pad instead, so the
    /// decoder is told to expect an unrelated number of orders and starts
    /// walking the order data as if it were far longer than it is.
    /// </remarks>
    [Fact]
    public void OrdersUpdate_PadBetweenTypeAndCount_IsNotReadAsTheCount()
    {
        var decoder = new OrderDecoder(new ScreenSurface(4, 4));

        // pad2OctetsA carries a value that would be a plausible order count.
        decoder.ExecuteOrdersUpdate(OrdersUpdate(1, [0x00, 0xFF, 0xFF], padA: 0x00FF));

        Assert.Equal(1, decoder.OrdersInLastUpdate);
        Assert.Equal(0, decoder.BytesLeftAfterLastUpdate);
    }

    /// <summary>
    /// Build an Orders Update body: updateType(2), pad2OctetsA(2),
    /// numberOrders(2), pad2OctetsB(2), then the order data.
    /// </summary>
    private static byte[] OrdersUpdate(int numberOrders, byte[] orderData, ushort padA = 0)
    {
        byte[] body = new byte[8 + orderData.Length];

        body[2] = (byte)padA;
        body[3] = (byte)(padA >> 8);
        body[4] = (byte)numberOrders;
        body[5] = (byte)(numberOrders >> 8);

        orderData.CopyTo(body, 8);
        return body;
    }
}
