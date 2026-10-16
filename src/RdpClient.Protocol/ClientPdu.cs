namespace RdpClient.Protocol;

/// <summary>
/// Client-to-server data blocks carried inside MCS Connect Initial.
/// </summary>
/// <remarks>
/// MS-RDPBCGR 2.2.1.3.4 defines TS_UD_CS_CORE, SECURITY, NET, CLUSTER and USER.
/// A server will not admit a connection without a well-formed set of these, so
/// each encoder preserves the exact field order and fixed-width fields from the
/// spec.
/// </remarks>
public static class ClientPdu
{
    /// <summary>TS_UD_CS_CORE.sasSequence (MS-RDPBCGR 2.2.1.3.4.1.1.1).</summary>
    public const int SasSequenceUnidirectional = 1;
    public const int SasSequenceBidirectional = 2;

    public sealed record CoreOptions
    {
        public int DesktopWidth { get; init; } = 1024;
        public int DesktopHeight { get; init; } = 768;

        /// <summary>Low-order colour depth; 0x18 selects 24-bit colour.</summary>
        public int ColorDepth { get; init; } = 0x18;
        public int HighColorDepth { get; init; } = 0x18;
        public int SupportedColorDepths { get; init; } = 0x07ea;

        /// <summary>1 lets the server send graphics requests, 2 is bidirectional.</summary>
        public int SasSequence { get; init; } = SasSequenceBidirectional;
        public uint KeyboardLayout { get; init; } = 0x00000409;
        public uint ClientBuildNumber { get; init; } = 0x00000a00;

        /// <summary>Truncated to the 8 UTF-16 code units of the fixed field.</summary>
        public string ClientName { get; init; } = "rdp-client";
        public uint KeyboardType { get; init; } = 0x00000004;
        public uint KeyboardSubType { get; init; }
        public uint KeyboardFunctionKey { get; init; }

        /// <summary>Truncated to the 32 UTF-16 code units of the fixed field.</summary>
        public string ImeFileName { get; init; } = string.Empty;
        public int PostWrite2Version { get; init; } = 0x0000000c;
        public int ClientProductId { get; init; } = 0x00010000;
        public uint SerialNumber { get; init; }
        public uint ClientDigProductId { get; init; }
        public int ConnectionType { get; init; } = 0x01;
        public uint ServerSelectedProtocol { get; init; }
        public uint DesktopPhysicalWidth { get; init; }
        public uint DesktopPhysicalHeight { get; init; }
        public uint DesktopPhysicalHorizontalDpi { get; init; }
        public uint DesktopPhysicalVerticalDpi { get; init; }
    }

    /// <summary>Build TS_UD_CS_CORE (MS-RDPBCGR 2.2.1.3.4.1).</summary>
    public static byte[] BuildCore(CoreOptions? options = null)
    {
        var o = options ?? new CoreOptions();
        var w = new ByteWriter(176);

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
        w.U16(o.PostWrite2Version);
        w.U16(o.ClientProductId);
        w.U32(o.SerialNumber);
        w.U16(o.HighColorDepth);
        w.U16(o.SupportedColorDepths);
        w.U16(o.ColorDepth);                   // clientColorDepth
        w.U16(o.ColorDepth);                   // clientPostBeta2ColorDepth
        w.U16(0);                              // clientEarlyCapabilityFlags
        w.U32(o.ClientDigProductId);
        w.U8(o.ConnectionType);
        w.U8(0);                               // pad2octet
        w.U32(o.ServerSelectedProtocol);
        w.U32(o.DesktopPhysicalWidth);
        w.U32(o.DesktopPhysicalHeight);
        w.U32(o.DesktopPhysicalHorizontalDpi);
        w.U32(o.DesktopPhysicalVerticalDpi);
        return w.ToArray();
    }

    /// <summary>Build TS_UD_CS_SECURITY (MS-RDPBCGR 2.2.1.3.4.2).</summary>
    public static byte[] BuildSecurity(
        uint encryptionMethod = Rdp.EncryptionMethodNone,
        int encryptionLevel = 0,
        int serverRedirection = 0)
    {
        var w = new ByteWriter(12);
        w.U32(encryptionMethod);
        w.U32(encryptionLevel);
        w.U8(serverRedirection);
        w.U8(0);   // pad2octetA
        w.U16(0);  // pad2octetB
        return w.ToArray();
    }

    public sealed record VirtualChannelOption(string Name, uint Options = Rdp.VChannel.OptionInitialized);

    /// <summary>
    /// Build TS_UD_CS_NET (MS-RDPBCGR 2.2.1.3.4.3).
    /// </summary>
    /// <remarks>
    /// Each entry is a 1-byte length followed by an 8-byte NUL-padded ASCII name
    /// and a 4-byte options mask. Names longer than 8 bytes are truncated, which
    /// is why <c>cliprdr</c> and <c>drdynvc</c> fit but longer names would not.
    /// </remarks>
    public static byte[] BuildNet(IReadOnlyList<VirtualChannelOption> channels)
    {
        // The TS_UD_CS_* blocks share a 6-byte TLV header: type(2), flags(2), length(2).
        var w = new ByteWriter(64 + channels.Count * 12);
        w.U16(Rdp.TsUdCsNet);
        w.U16(0);      // flags
        w.U16(8);      // length of the fixed portion
        w.U32(channels.Count);

        foreach (var channel in channels)
        {
            byte[] name = System.Text.Encoding.ASCII.GetBytes(channel.Name);
            if (name.Length > 8)
            {
                throw new ArgumentException(
                    $"virtual channel '{channel.Name}' exceeds the 8-byte name field", nameof(channels));
            }

            w.U8(name.Length);
            w.Bytes(name);
            for (int i = name.Length; i < 8; i++)
            {
                w.U8(0);
            }

            w.U32(channel.Options);
        }

        return w.ToArray();
    }

    // TS_UD_CS_CLUSTER flags (MS-RDPBCGR 2.2.1.3.4.4.1).
    public const uint RedirectionSupported = 0x00000001;
    public const uint RedirectionVersion4 = 0x00000002;

    // RedirFlags sub-fields (MS-RDPBCGR 2.2.1.3.4.4.2).
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

    /// <summary>Build TS_UD_CS_CLUSTER (MS-RDPBCGR 2.2.1.3.4.4).</summary>
    public static byte[] BuildCluster(
        RedirectionFlags redirection = RedirectionFlags.Clipboard | RedirectionFlags.Drive | RedirectionFlags.Audio,
        uint? flags = null)
    {
        var w = new ByteWriter(12);
        w.U16(Rdp.TsUdCsCluster);
        w.U16(0);
        w.U16(8);
        w.U32(flags ?? (RedirectionSupported | RedirectionVersion4));
        w.U32((uint)redirection);
        return w.ToArray();
    }

    // TS_UD_CS_USER flags (MS-RDPBCGR 2.2.1.3.4.5.1.1).
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

    /// <summary>Build TS_UD_CS_USER (MS-RDPBCGR 2.2.1.3.4.5).</summary>
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
        w.U16(0);
        w.U16(8);
        w.U32(o.CodePage);
        w.U32((uint)o.Flags);

        // Lengths are byte counts, not character counts.
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
        w.U16(0); // ClientInfoExtraInfo length
        return w.ToArray();
    }

    /// <summary>
    /// The static channel set a Windows RDS host expects to be offered.
    /// </summary>
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