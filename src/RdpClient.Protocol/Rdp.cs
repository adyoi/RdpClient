namespace RdpClient.Protocol;

/// <summary>
/// Protocol constants transcribed from Microsoft Open Specifications.
/// </summary>
/// <remarks>
/// Section references are to MS-RDPBCGR (Basic Connectivity and Graphics
/// Remoting) unless noted. Values come from the spec rather than from observed
/// traffic so that the encoders stay auditable against the published tables.
/// </remarks>
public static class Rdp
{
    // --- TPKT / X.224 (ITU-T X.224, T.125) ---------------------------------

    public const int TpktVersion = 3;
    public const byte X224ConnectionRequest = 0xe0;
    public const byte X224ConnectionConfirm = 0xd0;
    public const byte X224DisconnectRequest = 0x80;
    public const byte X224Data = 0xf0;

    /// <summary>Largest TPKT the 7-bit length octet can express, header included.</summary>
    public const int TpktMaxLength = 0x7fff;

    // --- MS-RDPBCGR 2.2.1.1 RDP Negotiation --------------------------------

    public const byte NegReqTypeRdpConnectionReq = 0x01;
    public const byte NegRspTypeRdpConnectionResp = 0x02;
    public const byte NegRspTypeRdpConnectionFailure = 0x03;
    public const byte NegReqTypeCorrelationInfo = 0x06;

    public const uint ProtocolRdp50 = 0x00080005;

    // SelectedProtocol bitmask (MS-RDPBCGR 2.2.1.2.2).
    public const uint ProtocolSsl = 0x00000001;
    public const uint ProtocolHybrid = 0x00000002;
    public const uint ProtocolRdstls = 0x00000004;
    public const uint ProtocolHybridEx = 0x00000008;
    public const uint ProtocolRdsaad = 0x00000010;

    // RDP_NEG_RSP flags (MS-RDPBCGR 2.2.1.2.1). The same bit positions are used by
    // the RDP_NEG_REQ flags field (2.2.1.1.1).
    [Flags]
    public enum NegRspFlags : byte
    {
        None = 0x00,
        RestrictedAdminModeRequired = 0x01,
        RedirectedAuthenticationModeRequired = 0x02,

        /// <summary>The optional correlation block is appended to the request.</summary>
        CorrelationInfoPresent = 0x08,
    }

    public const uint NegRspRestrictedAdminModeSupported = 0x00000001;
    public const uint NegRspRedirectedAuthenticationModeSupported = 0x00000002;
    public const uint NegRspCorrelationInfoPresent = 0x00000008;

    // --- Security (MS-RDPBCGR 2.2.1.4.3, 5.3.2) ----------------------------

    public const uint EncryptionMethodNone = 0x00000000;
    public const uint EncryptionMethod40Bit = 0x00000001;
    public const uint EncryptionMethod128Bit = 0x00000002;
    public const uint EncryptionMethod56Bit = 0x00000008;
    public const uint EncryptionMethodFips = 0x00000010;

    /// <summary>Client key algorithms as a bitmask (MS-RDPBCGR 5.1.2).</summary>
    public const uint SupportedEncryptionMethods =
        EncryptionMethodNone | EncryptionMethod40Bit |
        EncryptionMethod128Bit | EncryptionMethod56Bit | EncryptionMethodFips;

    public const uint EncryptionMethodRsaFull = 0x80000000;
    public const uint KeyExchangeAlgRsaFull = 0x00000001;
    public const uint KeyExchangeAlgDh = 0x00000002;

    // --- MCS (MS-RDPBCGR 2.2.1.3.1, 2.2.1.3.4, 2.2.1.3.6) ------------------

    public const byte McsUdConnectInitial = 0x7f;
    public const byte McsUdConnectResponse = 0x7e;
    public const byte McsUdDisconnectProviderUltimatum = 0x7d;

    public const byte McsErectDomainRequestPdu = 0x05;
    public const byte McsAttachUserRequestPdu = 0x06;
    public const byte McsChannelJoinRequestPdu = 0x07;
    public const byte McsSendDataRequestPdu = 0x0a;

    public const ushort McsGlobalChannel = 1007;
    public const ushort McsUserChannelBase = 1001;

    public const string GccConferenceName = "McsCnxn";
    public const ushort GccConferenceLabel = 0x0001;

    // --- Client-to-server PDU headers (MS-RDPBCGR 2.2.1.3.4.1) ------------
    //
    // These TSFC discriminators are 16-bit little-endian values. Writing them
    // as a single byte truncates 0xC001 to 0x01 and every following field lands
    // at the wrong offset.

    public const ushort TsUdCsCore = 0xc001;
    public const ushort TsUdCsSecurity = 0xc002;
    public const ushort TsUdCsNet = 0xc003;
    public const ushort TsUdCsCluster = 0xc004;
    public const ushort TsUdCsUser = 0xc00e;

    public const uint RdpVersion5Plus = 0x80000005;

    // --- Capability sets (MS-RDPBCGR 2.2.7) --------------------------------

    public const ushort CapSetGeneral = 0x0001;
    public const ushort CapSetBitmap = 0x0002;
    public const ushort CapSetOrder = 0x0003;
    public const ushort CapSetBmpCache = 0x0004;
    public const ushort CapSetControl = 0x0005;
    public const ushort CapSetActivate = 0x0007;
    public const ushort CapSetPointer = 0x0008;
    public const ushort CapSetShare = 0x0009;
    public const ushort CapSetSound = 0x000c;
    public const ushort CapSetInput = 0x000d;
    public const ushort CapSetFont = 0x000e;
    public const ushort CapSetBrush = 0x000f;
    public const ushort CapSetGlyphCache = 0x0010;
    public const ushort CapSetOffscreenCache = 0x0011;
    public const ushort CapSetBmpCacheRev2 = 0x0012;
    public const ushort CapSetVirtualChannel = 0x0013;
    public const ushort CapSetDrawableGdi = 0x0014;
    public const ushort CapSetPduOrder = 0x0015;
    public const ushort CapSetTextInput = 0x0016;
    public const ushort CapSetWindow = 0x0017;
    public const ushort CapSetMultitransport = 0x001a;

    // --- Virtual channel identifiers (MS-RDPBCGR 2.2.1.3.4.1.3.1) ----------

    public static class VChannel
    {
        public const uint Rdpdr = 0x000007f2;
        public const uint Cliprdr = 0x00000c01;
        public const uint Rdpgfx = 0x000003eb;
        public const uint Audin = 0x000003e3;
        public const uint Drdynvc = 0x000007ea;
        public const uint Encomsp = 0x000007ef;
        public const uint Urbout = 0x000007f3;
        public const uint Chat = 0x000007f4;
        public const uint Rail = 0x000007f5;

        public const uint OptionInitialized = 0x80000000;
        public const uint OptionEncapRdprfx = 0x01000000;
    }
}