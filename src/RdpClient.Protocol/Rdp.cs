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

    // --- MCS (MS-RDPBCGR 2.2.1.3 - 2.2.1.9) -------------------------------
    //
    // 2.2.1.3 is the Connect Initial with its GCC Conference Create Request,
    // 2.2.1.4 the Connect Response, and 2.2.1.5 through 2.2.1.9 the domain PDUs
    // that follow: Erect Domain Request, Attach User Request and Confirm,
    // Channel Join Request and Confirm. The 2.2.1.3.x numbers are the client data
    // blocks inside the Connect Initial, not the MCS PDUs, which is an easy and
    // consequential confusion.

    public const byte McsUdConnectInitial = 0x7f;
    public const byte McsUdConnectResponse = 0x7e;
    public const byte McsUdDisconnectProviderUltimatum = 0x7d;

    // DomainMCSPDU choice values (T.125 section 8). These are the numbers of
    // the CHOICE alternatives, NOT the octets that go on the wire: the octet is
    // the choice shifted left by two with the two dataPriority/segmentation
    // option bits in the low positions, because the CHOICE index occupies the
    // top six bits of that octet.
    //
    //   opcode = (choice << 2) | options
    //
    // MS-RDPBCGR 3.3.5.2 lists a different numbering (5, 6, 7, 10) which counts
    // from plumbDomainIndication and is the source of the wrong values this
    // file used to carry. xrdp reports the choice index it read as
    // "choice index %d", so the shift is checkable against its log.
    public const int McsChoiceErectDomainRequest = 1;
    public const int McsChoiceAttachUserRequest = 10;
    public const int McsChoiceAttachUserConfirm = 11;
    public const int McsChoiceChannelJoinRequest = 14;
    public const int McsChoiceChannelJoinConfirm = 15;
    public const int McsChoiceDisconnectProviderUltimatum = 8;
    public const int McsChoiceSendDataRequest = 25;
    public const int McsChoiceSendDataIndication = 26;

    /// <summary>Turn a DomainMCSPDU choice into the octet that carries it.</summary>
    /// <param name="choice">One of the <c>McsChoice*</c> values.</param>
    /// <param name="options">The two option bits, normally zero.</param>
    public static byte McsOpcode(int choice, int options = 0) =>
        (byte)((choice << 2) | (options & 0x03));

    /// <summary>
    /// The MCS global channel, 1003 (T.125 section 7.6, MS-RDPBCGR 2.2.1.8).
    /// </summary>
    /// <remarks>
    /// 1007 is the H.225.0 RTP channel number and appears in some non-RDP
    /// material. xrdp defines this as <c>MCS_GLOBAL_CHANNEL 1003</c>, so a client
    /// that joins 1007 is joining a channel no server created.
    /// </remarks>
    public const ushort McsGlobalChannel = 1003;

    /// <summary>
    /// The MCS server channel, 1002 (MS-RDPBCGR 2.2.1.13.2.1).
    /// </summary>
    /// <remarks>
    /// Not joined by the client: it belongs to the server. It appears here only
    /// as the fixed originator ID the Confirm Active PDU must carry, which is a
    /// different field from the channel the PDU travels on.
    /// </remarks>
    public const ushort McsServerChannel = 1002;

    /// <summary>The MCS user channel, 1001 (MS-RDPBCGR 2.2.1.8).</summary>
    /// <remarks>
    /// This is a channel the client is required to join, and not an optional
    /// extra. xrdp sets <c>self-&gt;chanid = 1001</c> at MCS construction and counts
    /// the joins it expects as
    /// <c>channel_list-&gt;count + 2</c>: one per static virtual channel the client
    /// offered, plus this user channel, plus the global channel. A client that
    /// joins only 1003 is one join short of a count that has nothing to do with
    /// which stage it has implemented.
    /// </remarks>
    public const ushort McsUserChannel = 1001;

    /// <summary>
    /// The first static virtual channel id, one above the global channel
    /// (MS-RDPBCGR 2.2.1.8).
    /// </summary>
    /// <remarks>
    /// Static virtual channels are numbered in the order they were offered in
    /// TS_UD_CS_NET, starting immediately above the global channel. FreeRDP sets
    /// <c>mcs-&gt;baseChannelId = MCS_GLOBAL_CHANNEL_ID + 1</c> and allocates from
    /// there; xrdp assigns <c>MCS_GLOBAL_CHANNEL + (index + 1)</c>. Both make the
    /// Nth offered channel id 1004 + N.
    /// </remarks>
    public const ushort McsStaticChannelBase = 1004;

    /// <summary>The MCS channel id of the Nth static virtual channel, from zero.</summary>
    /// <param name="index">Position in the TS_UD_CS_NET channel list.</param>
    public static ushort McsStaticChannel(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        return (ushort)(McsStaticChannelBase + index);
    }

    /// <summary>Lowest dynamic channel id, the base every MCS UserId is offset from.</summary>
    public const ushort McsUserChannelBase = 1001;

    /// <summary>
    /// The conference name carried in a T.125 Connect-Initial.
    /// </summary>
    /// <remarks>
    /// PER encodes this as a numeric string, so it is digits only. "McsCnxn"
    /// is the H.221 node label from the older T.125 CCPDU and does not belong
    /// here; a real client sends a single digit.
    /// </remarks>
    public const string McsConferenceName = "1";

    // --- Client-to-server PDU headers (MS-RDPBCGR 2.2.1.3.1) ------------
    //
    // The discriminators are 16-bit little-endian values. Writing them
    // as a single byte truncates 0xC001 to 0x01 and every following field lands
    // at the wrong offset. TS_UD_HEADER itself is type(2), length(2), with no
    // flags field.

    public const ushort TsUdCsCore = 0xc001;
    public const ushort TsUdCsSecurity = 0xc002;
    public const ushort TsUdCsNet = 0xc003;
    public const ushort TsUdCsCluster = 0xc004;
    public const ushort TsUdCsUser = 0xc00e;

    public const uint RdpVersion5Plus = 0x80000005;

    // earlyCapabilityFlags in TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.2).
    public const ushort EarlyCapSupportErrInfoPdu = 0x0001;
    public const ushort EarlyCapWant32BppSession = 0x0002;
    public const ushort EarlyCapSupportStatusInfoPdu = 0x0004;
    public const ushort EarlyCapStrongAsymmetricKeys = 0x0008;
    public const ushort EarlyCapRelativeMouseInput = 0x0010;
    public const ushort EarlyCapValidConnectionType = 0x0020;
    public const ushort EarlyCapSupportMonitorLayoutPdu = 0x0040;
    public const ushort EarlyCapSupportNetcharAutodetect = 0x0080;
    public const ushort EarlyCapSupportDynvcGfxProtocol = 0x0100;
    public const ushort EarlyCapSupportDynamicTimeZone = 0x0200;
    public const ushort EarlyCapSupportHeartbeatPdu = 0x0400;

    /// <summary>
    /// RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN, which changes what the client owes
    /// the server (MS-RDPBCGR 2.2.1.3.2).
    /// </summary>
    /// <remarks>
    /// With this flag set the client sends <em>no</em> Channel Join Requests. It
    /// is not an optimisation on top of joining; it replaces it, and a client
    /// that sets it and then joins anyway has told the server two contradictory
    /// things.
    /// <para>
    /// Setting it is also the only way to get past xrdp. Its
    /// <c>handle_channel_join_requests</c> leaves
    /// <c>expected_join_count</c> at zero when the flag is present, so the loop
    /// that consumes joins - and which does a <c>libxrdp_force_read</c> after
    /// each one, waiting for whatever comes next - never runs. A client that
    /// does join leaves xrdp blocked on that read while the client waits for the
    /// Demand Active PDU, and neither side ever speaks again.
    /// </para>
    /// </remarks>
    public const ushort EarlyCapSupportSkipChannelJoin = 0x0800;

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

    // --- Virtual channel identifiers (MS-RDPBCGR 2.2.1.3.4.1) ------------

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