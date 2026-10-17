namespace RdpClient.Protocol;

/// <summary>
/// Client-to-server data blocks carried inside MCS Connect Initial.
/// </summary>
/// <remarks>
/// MS-RDPBCGR 2.2.1.3 defines TS_UD_CS_CORE, SECURITY, NET, CLUSTER and the
/// extended blocks. Every one of them begins with the same 4-byte
/// <c>TS_UD_HEADER</c> (MS-RDPBCGR 2.2.1.3.1), which is <c>type(2)</c> and
/// <c>length(2)</c> - there is <em>no</em> flags field - and whose length is the
/// size of the whole block including the header.
/// </remarks>
public static class ClientPdu
{
    /// <summary>TS_UD_CS_CORE.sasSequence (MS-RDPBCGR 2.2.1.3.2).</summary>
    public const int SasSequenceUnidirectional = 1;
    public const int SasSequenceBidirectional = 2;

    /// <summary>RNS_UD_SAS_DEL, the SAS value a real client sends (2.2.1.3.2).</summary>
    public const int SasSequenceDelayed = 0xAA03;

    public sealed record CoreOptions
    {
        public int DesktopWidth { get; init; } = 1024;
        public int DesktopHeight { get; init; } = 768;

        /// <summary>
        /// Low-order colour depth. Ignored when <see cref="HighColorDepth"/> is
        /// present, which it always is.
        /// </summary>
        public int ColorDepth { get; init; } = 0x01;

        /// <summary>High colour depth; 0x18 selects 24-bit colour.</summary>
        public int HighColorDepth { get; init; } = 0x18;

        public int SupportedColorDepths { get; init; } = 0x07ea;

        /// <summary>1 lets the server send graphics requests, 2 is bidirectional.</summary>
        public int SasSequence { get; init; } = SasSequenceDelayed;
        public uint KeyboardLayout { get; init; } = 0x00000409;
        public uint ClientBuildNumber { get; init; } = 0x00000a00;

        /// <summary>Truncated to the 8 UTF-16 code units of the fixed field.</summary>
        public string ClientName { get; init; } = "rdp-client";
        public uint KeyboardType { get; init; } = 0x00000004;
        public uint KeyboardSubType { get; init; }
        public uint KeyboardFunctionKey { get; init; }

        /// <summary>Truncated to the 32 UTF-16 code units of the fixed field.</summary>
        public string ImeFileName { get; init; } = string.Empty;

        public int ClientProductId { get; init; } = 0x00000001;
        public uint SerialNumber { get; init; }

        /// <summary>Written into the fixed 64-byte field.</summary>
        public string ClientDigProductId { get; init; } = string.Empty;

        /// <summary>
        /// Early capabilities. Only bits this client actually honours are set.
        /// </summary>
        /// <remarks>
        /// Announcing a capability and then not implementing it is worse than
        /// leaving it clear: the server sends the corresponding PDUs and waits
        /// for a reply that never comes.
        /// </remarks>
        public ushort EarlyCapabilityFlags { get; init; }

        public int ConnectionType { get; init; } = 0x07;
        public uint ServerSelectedProtocol { get; init; }

        /// <summary>
        /// Physical desktop width in millimetres.
        /// </summary>
        /// <remarks>
        /// MS-RDPBCGR 2.2.1.3.2 requires a value between 10 and 10,000, and a
        /// zero is invalid rather than merely ignored: xrdp logs
        /// <c>Physical desktop dimensions (0x0) are invalid</c> and sizes the
        /// session to nothing. These defaults describe a 4:3 desktop, which is
        /// what the pixel dimensions above assume.
        /// </remarks>
        public uint DesktopPhysicalWidth { get; init; } = 270;

        /// <summary>Physical desktop height in millimetres; see the width.</summary>
        public uint DesktopPhysicalHeight { get; init; } = 203;

        /// <summary>
        /// postBeta2ColorDepth (MS-RDPBCGR 2.2.1.3.2). Ignored when
        /// <see cref="HighColorDepth"/> is present, which it always is.
        /// </summary>
        public int PostBeta2ColorDepth { get; init; } = 0x01;
    }

    /// <summary>
    /// Build TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// CORE carries the same 4-byte TS_UD_HEADER as every other block - type and
    /// length, with no flags field. It was long described as the one block with
    /// no header, which is what made it 36 octets short of the 234 the
    /// specification lays out: the header, the 64-byte clientDigProductId and
    /// the trailing scale factors are all part of the structure.
    /// </para>
    /// <para>
    /// The fields from postBeta2ColorDepth onwards are declared optional, but
    /// the presence of any one implies the presence of all that precede it, so
    /// they are written as a single group.
    /// </para>
    /// </remarks>
    public static byte[] BuildCore(CoreOptions? options = null)
    {
        var o = options ?? new CoreOptions();
        var w = new ByteWriter(240);

        w.U16(Rdp.TsUdCsCore);   // TS_UD_HEADER type
        w.U16(0);               // TS_UD_HEADER length, patched below

        w.U32(Rdp.RdpVersion5Plus);
        w.U16(o.DesktopWidth);
        w.U16(o.DesktopHeight);
        w.U16(o.ColorDepth);
        w.U16(o.SasSequence);
        w.U32(o.KeyboardLayout);
        w.U32(o.ClientBuildNumber);
        w.FixedUtf16(o.ClientName, 32);        // 8 UTF-16 code units
        w.U32(o.KeyboardType);
        w.U32(o.KeyboardSubType);
        w.U32(o.KeyboardFunctionKey);
        w.FixedUtf16(o.ImeFileName, 64);       // 32 UTF-16 code units

        w.U16(o.PostBeta2ColorDepth);
        w.U16(o.ClientProductId);
        w.U32(o.SerialNumber);
        w.U16(o.HighColorDepth);
        w.U16(o.SupportedColorDepths);
        w.U16(o.EarlyCapabilityFlags);
        w.FixedUtf16(o.ClientDigProductId, 64); // 32 UTF-16 code units
        w.U8(o.ConnectionType);
        w.U8(0);                               // pad1octet
        w.U32(o.ServerSelectedProtocol);
        w.U32(o.DesktopPhysicalWidth);
        w.U32(o.DesktopPhysicalHeight);
        w.U16(0);                              // desktopOrientation, landscape
        w.U32(100);                            // desktopScaleFactor, 100%
        w.U32(100);                            // deviceScaleFactor, 100%

        PatchLength(w);
        return w.ToArray();
    }

    /// <summary>Build TS_UD_CS_SECURITY (MS-RDPBCGR 2.2.1.3.3).</summary>
    /// <remarks>
    /// A fixed 12-byte block: the 4-byte TS_UD_HEADER plus two 4-octet fields.
    /// The header is what makes it 12 rather than 8, so a block that declares 8
    /// octets of payload is 4 octets short of the structure it must describe.
    /// </remarks>
    public static byte[] BuildSecurity(
        uint encryptionMethod = Rdp.EncryptionMethodNone,
        int encryptionLevel = 0,
        int serverRedirection = 0)
    {
        var w = new ByteWriter(16);
        w.U16(Rdp.TsUdCsSecurity);
        w.U16(12);     // the whole block
        w.U32(encryptionMethod);
        w.U32((uint)encryptionLevel);
        PatchLength(w);
        return w.ToArray();
    }

    public sealed record VirtualChannelOption(string Name, uint Options = Rdp.VChannel.OptionInitialized);

    /// <summary>Upper bound on <c>channelCount</c>, from MS-RDPBCGR 2.2.1.3.4.</summary>
    public const int MaxChannelCount = 31;

    /// <summary>
    /// Build TS_UD_CS_NET (MS-RDPBCGR 2.2.1.3.4).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each entry is a CHANNEL_DEF: a fixed 8-octet NUL-padded ASCII name and a
    /// 4-octet options mask, twelve octets in total with no length prefix of its
    /// own. Names longer than 8 bytes are rejected, which is why <c>cliprdr</c>
    /// and <c>drdynvc</c> fit but longer names would not.
    /// </para>
    /// <para>
    /// The declared length covers the <em>whole</em> block, header included -
    /// channelCount plus every CHANNEL_DEF. A reader walks that length to find
    /// the next block, so declaring a fixed portion while sending more
    /// desynchronises every block after it.
    /// </para>
    /// </remarks>
    public static byte[] BuildNet(IReadOnlyList<VirtualChannelOption> channels)
    {
        ArgumentNullException.ThrowIfNull(channels);

        // channelCount is a 32-bit field but the structure caps it at 31
        // (MS-RDPBCGR 2.2.1.3.4). A larger list is rejected here rather than
        // written, because the server is entitled to read only 31 definitions
        // and the rest of the block would be parsed as something else.
        if (channels.Count > MaxChannelCount)
        {
            throw new ArgumentException(
                $"MS-RDPBCGR 2.2.1.3.4 allows at most {MaxChannelCount} static "
                + $"virtual channels, {channels.Count} were given",
                nameof(channels));
        }

        var w = new ByteWriter(16 + channels.Count * 12);
        w.U16(Rdp.TsUdCsNet);
        w.U16(8 + (channels.Count * 12));     // header + channelCount + defs
        w.U32(channels.Count);

        foreach (var channel in channels)
        {
            byte[] name = System.Text.Encoding.ASCII.GetBytes(channel.Name);
            if (name.Length > 8)
            {
                throw new ArgumentException(
                    $"virtual channel '{channel.Name}' exceeds the 8-byte name field", nameof(channels));
            }

            // The name is a fixed 8-octet field, not a length-prefixed string:
            // there is no octet to write for the length.
            w.FixedAscii8(channel.Name);
            w.U32(channel.Options);
        }

        PatchLength(w);
        return w.ToArray();
    }

    // TS_UD_CS_CLUSTER fields (MS-RDPBCGR 2.2.1.3.5).
    public const uint RedirectionSupported = 0x00000001;
    public const uint RedirectionVersion4 = 0x00000002;

    // RedirFlags sub-fields (MS-RDPBCGR 2.2.1.3.5).
    [Flags]
    public enum RedirectionFlags : uint
    {
        None = 0x00000000,
        Clipboard = 0x00000001,
        Drive = 0x00000002,
        Audio = 0x00000008,
        ComPort = 0x00000010,
        SmartCard = 0x00000100,
        WebAuthentication = 0x00000400,
    }

    /// <summary>Build TS_UD_CS_CLUSTER (MS-RDPBCGR 2.2.1.3.5).</summary>
    public static byte[] BuildCluster(
        RedirectionFlags redirection = RedirectionFlags.Clipboard | RedirectionFlags.Drive | RedirectionFlags.Audio,
        uint? flags = null)
    {
        var w = new ByteWriter(12);
        w.U16(Rdp.TsUdCsCluster);
        w.U16(12);
        w.U32(flags ?? (RedirectionSupported | RedirectionVersion4));
        w.U32((uint)redirection);
        PatchLength(w);
        return w.ToArray();
    }

    /// <summary>
    /// Overwrite a block's declared length with the number of bytes it actually
    /// occupies, header included.
    /// </summary>
    /// <remarks>
    /// The length sits at offset 2 of every TS_UD_CS_* block, and the payload
    /// size is only known once the variable-length fields have been written.
    /// Patching afterwards is what keeps the declared length and the real length
    /// from drifting apart: a reader that walks the declared length to locate
    /// the next block stops at the wrong offset the moment they disagree, and
    /// the blocks after it are parsed from the wrong place with no diagnostic.
    /// </remarks>
    private static void PatchLength(ByteWriter writer)
    {
        if (writer.Length < 4)
        {
            throw new InvalidOperationException("a TS_UD_CS_* block needs its 4-byte header");
        }

        writer.U16At(2, writer.Length);
    }

    // MS-RDPBCGR defines no TS_UD_CS_USER block at all. These flags describe the
    // structure this class can still emit for callers that ask for it; they are
    // transcribed from the classic-RDP definition, which is not the Open
    // Specification. See BuildUser.
    [Flags]
    public enum UserFlags : uint
    {
        None = 0,
        Mouse = 0x00000001,
        DisableCtrlAltDel = 0x00000002,
        Autologon = 0x00000004,
        Unicode = 0x00000008,
        MaximizeShell = 0x00000010,
        LogonNotify = 0x00000020,
        Compression = 0x00000040,
        EnableWindowsKey = 0x00000080,
        ForceEncrypt = 0x00000100,
        LogonErrors = 0x00000200,
        MouseHasWheel = 0x00000400,
        PasswordIsScPin = 0x00000800,
        NoAudioPlayback = 0x00001000,
        UsingSaad = 0x00002000,
        LogonUi = 0x00004000,
        ForceEncryptCs = 0x00008000,
        RestrictedAdminLogon = 0x00010000,
    }

    public sealed record UserOptions
    {
        public string Domain { get; init; } = string.Empty;
        public string UserName { get; init; } = string.Empty;
        public string Password { get; init; } = string.Empty;
        public string AlternateShell { get; init; } = string.Empty;
        public string WorkingDir { get; init; } = string.Empty;
        public uint CodePage { get; init; }

        /// <summary>
        /// Defaults to the set a normal interactive session needs. UTF-16 fields
        /// are implied by <see cref="UserFlags.Unicode"/>.
        /// </summary>
        public UserFlags Flags { get; init; } =
            UserFlags.Mouse | UserFlags.DisableCtrlAltDel | UserFlags.Unicode |
            UserFlags.MouseHasWheel | UserFlags.ForceEncryptCs;
    }

    /// <summary>
    /// The classic-RDP user data block, which MS-RDPBCGR does not define.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is not a specified structure. It predates MS-RDPBCGR, is the block
    /// through which a client that authenticates outside the MCS handshake sends
    /// a password, and it is why this client can present one in the clear. xrdp
    /// answers <c>TS_UD_HEADER type 0xc00e is unknown (ignored)</c>, and
    /// MS-RDPBCGR 2.2.1.3 lists no such block at all.
    /// </para>
    /// <para>
    /// It is kept so the classic path stays honest about what it does, and it is
    /// off unless a caller explicitly asks for it. Sending it by default
    /// advertised a credential the server was going to discard.
    /// </para>
    /// </remarks>
    /// <remarks>Field lengths are byte counts, not character counts.</remarks>
    public static byte[] BuildUser(UserOptions? options = null)
    {
        var o = options ?? new UserOptions();
        byte[] domain = System.Text.Encoding.Unicode.GetBytes(o.Domain);
        byte[] user = System.Text.Encoding.Unicode.GetBytes(o.UserName);
        byte[] password = System.Text.Encoding.Unicode.GetBytes(o.Password);
        byte[] shell = System.Text.Encoding.Unicode.GetBytes(o.AlternateShell);
        byte[] workdir = System.Text.Encoding.Unicode.GetBytes(o.WorkingDir);

        var w = new ByteWriter(64 + domain.Length + user.Length + password.Length + shell.Length + workdir.Length);
        w.U16(Rdp.TsUdCsUser);
        w.U16(0);      // placeholder for the declared length
        w.U32(o.CodePage);
        w.U32((uint)o.Flags);

        w.U16(domain.Length);
        w.U16(user.Length);
        w.U16(password.Length);
        w.U16(shell.Length);
        w.U16(workdir.Length);

        w.Bytes(domain);
        w.Bytes(user);
        w.Bytes(password);
        w.Bytes(shell);
        w.Bytes(workdir);
        w.U16(0);      // ClientInfoExtraInfo length

        PatchLength(w);
        return w.ToArray();
    }

    /// <summary>
    /// The static channel set offered in TS_UD_CS_NET.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This list is not measured from a real client. Searching
    /// <c>mstscax.dll</c> for these names finds <c>rdpdr</c>, <c>cliprdr</c> and
    /// <c>drdynvc</c>, each as a UTF-16 string in <c>.rdata</c>; <c>rdpgfx</c>,
    /// <c>urbout</c>, <c>encomsp</c> and <c>audin</c> are absent from that
    /// binary in both ASCII and UTF-16, so the other clients are evidently
    /// registered from somewhere this search does not reach.
    /// </para>
    /// <para>
    /// The order matters beyond the names, because static virtual channel ids
    /// are assigned by position: the Nth channel offered gets MCS id 1004 + N.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<VirtualChannelOption> DefaultChannels() =>
    [
        new("rdpdr"),
        new("cliprdr"),
        new("rdpgfx"),
        new("rail"),
        new("drdynvc"),
        new("audin"),
        new("encomsp"),
        new("urbout"),
    ];
}