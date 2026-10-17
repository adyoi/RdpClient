using System.Buffers.Binary;

namespace RdpClient.Protocol;

/// <summary>
/// The Client Info PDU (MS-RDPBCGR 2.2.1.11): the Secure Settings Exchange that
/// sits between the channel joins and the Demand Active PDU.
/// </summary>
/// <remarks>
/// This PDU is what the earlier handshake was missing, and it is why the
/// connection stalled at the channel joins with a completely silent server log.
/// The connection sequence (2.2.1.1) puts the Secure Settings Exchange directly
/// after the channel joins, and a server that follows the sequence will not
/// send the Demand Active PDU until it has the logon fields. xrdp shows the
/// dependency in <c>xrdp_sec_recv</c>: its only
/// <c>return -1 /* special error that means send demand active */</c> sits
/// inside the <c>if (flags &amp; SEC_INFO_PKT)</c> branch, so it answers a
/// Client Info PDU with a Licensing PDU and the Demand Active, and answers
/// nothing else. It was first measured as a channel-join problem and then as
/// one <c>RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN</c> would fix; both readings were
/// wrong, as AGENTS.md records.
/// <para>
/// The PDU always carries a security header (2.2.8.1.1.2.1, "the Client Info
/// PDU and licensing PDUs ... always have a security header"), even under TLS
/// where only <c>SEC_INFO_PKT</c> fits. It is not wrapped in a Share Control
/// Header, and it travels in an MCS Send Data Request aimed at the global
/// channel (1003): FreeRDP's <c>rdp_send_client_info</c> targets
/// <c>MCS_GLOBAL_CHANNEL_ID</c>, and xrdp's <c>xrdp_rdp_recv</c> skips every
/// slow-path PDU that does not arrive there.
/// </para>
/// <para>
/// The password is carried in UTF-16 inside the PDU under TLS, protected by the
/// transport and no further. It is never hex-dumped - see
/// <see cref="RdpConnectionOptions.LogTx"/>.
/// </para>
/// </remarks>
public static class ClientInfo
{
    // --- TS_SECURITY_HEADER flags (MS-RDPBCGR 2.2.8.1.1.2.1) ---
    // Transcribed, not remembered: SEC_INFO_PKT is 0x0040, not the 0x0080 a
    // reader guesses first, because 0x0080 is SEC_LICENSE_PKT next to it.
    /// <summary>The packet is a Client Info PDU (2.2.1.11).</summary>
    public const ushort SecInfoPkt = 0x0040;

    /// <summary>The packet is a Licensing PDU (2.2.1.12).</summary>
    public const ushort SecLicensePkt = 0x0080;

    /// <summary>SEC_ENCRYPT; only set when RDP-layer encryption is in force.</summary>
    public const ushort SecEncrypt = 0x0008;

    /// <summary>flags + flagsHi, and nothing else: the Basic Security Header.</summary>
    public const int SecurityHeaderSize = 4;

    // --- TS_INFO_PACKET flags (MS-RDPBCGR 2.2.1.11.1.1) ---
    // Values as the specification numbers them today. An older transcription
    // in ClientPdu.UserFlags carries the pre-spec values (Autologon 0x4,
    // Unicode 0x8); that table belongs to the undocumented 0xc00e block and is
    // left as it is, while this PDU is the specified one.
    public const uint InfoMouse = 0x00000001;
    public const uint InfoDisableCtrlAltDel = 0x00000002;
    public const uint InfoAutoLogon = 0x00000008;
    public const uint InfoUnicode = 0x00000010;
    public const uint InfoMaximizeShell = 0x00000020;
    public const uint InfoEnableWindowsKey = 0x00000100;
    public const uint InfoForceEncryptedCsPdu = 0x00004000;
    public const uint InfoLogonErrors = 0x00010000;
    public const uint InfoMouseHasWheel = 0x00020000;

    /// <summary>
    /// The flag set a desktop-logon client sends, matching the mask xrdp
    /// demands before it will parse the packet at all.
    /// </summary>
    /// <remarks>
    /// xrdp rejects the whole packet unless
    /// <c>(flags &amp; INFO_LOGON_NORMAL) == INFO_LOGON_NORMAL /* 0x33 */</c>,
    /// which covers <c>InfoMouse | InfoDisableCtrlAltDel | InfoUnicode |
    /// InfoMaximizeShell</c>. FreeRDP's <c>rdp_write_info_packet</c> starts from
    /// the same set, adds the conditional flags, and turns
    /// <c>InfoAutoLogon</c> off when no password is known: a set
    /// <c>InfoAutoLogon</c> with empty logon fields is a server-side error, so
    /// <see cref="BuildClientInfoPdu"/> gates that bit the same way.
    /// </remarks>
    public const uint DefaultFlags =
        InfoMouse | InfoDisableCtrlAltDel | InfoUnicode | InfoMaximizeShell |
        InfoEnableWindowsKey | InfoForceEncryptedCsPdu | InfoLogonErrors |
        InfoMouseHasWheel;

    /// <summary>
    /// A TS_INFO_PACKET string is limited to 512 bytes including the mandatory
    /// null terminator (2.2.1.11.1.1), so the declared count alone is 510.
    /// </summary>
    public const int MaxStringBytes = 510;

    /// <summary>
    /// clientAddressFamily = AF_INET (MS-RDPBCGR 2.2.1.11.1.1.1), because the
    /// clientAddress this client writes is an IPv4 dotted quad.
    /// </summary>
    public const ushort AddressFamilyInet = 0x0002;

    /// <summary>
    /// TS_TIME_ZONE_INFORMATION, as one allocation-sized comment so no reader
    /// has to re-derive it: bias (4), StandardName (32 UTF-16 chars, 64),
    /// StandardDate (16) + StandardBias (4), DaylightName (64), DaylightDate
    /// (16) + DaylightBias (4) - 172 octets in total.
    /// </summary>
    public const int TimeZoneLength = 172;

    /// <summary>
    /// A language identifier in the low word, per the INFO_UNICODE contract
    /// for the CodePage field. Servers that read it get "en-US"; xrdp skips
    /// the field either way.
    /// </summary>
    public const uint CodePageEnUs = 0x00000409;

    /// <summary>
    /// The clientAddress this client writes, as a fixed diagnosis value. It is
    /// advisory; xrdp reads the fields and ignores them, and mstsc fills a
    /// real interface address this client has no meaningful view of.
    /// </summary>
    public const string ClientAddress = "127.0.0.1";

    /// <summary>The clientDir companion to <see cref="ClientAddress"/>.</summary>
    public const string ClientDir = "RdpClient";

    /// <summary>
    /// Build the whole Client Info PDU: security header + TS_INFO_PACKET
    /// + TS_EXTENDED_INFO_PACKET, unwrapped (no Share Control Header).
    /// </summary>
    /// <remarks>
    /// Strings are UTF-16 because INFO_UNICODE is part of the mandatory mask,
    /// and each one carries its 2-octet null terminator while <c>cb*</c> counts
    /// only the text (2.2.1.11.1.1). The extended info block is sent, because
    /// xrdp parses it when INFO_ENABLEWINDOWSKEY is in the flags and refuses
    /// the packet if the fields it reads are short - and because every real
    /// client sends it.
    /// </remarks>
    public static byte[] BuildClientInfoPdu(ClientPdu.UserOptions? user = null)
    {
        var options = user ?? new ClientPdu.UserOptions();

        // Capacity is a guess, not a contract: ByteWriter grows when it has to.
        // 288 covers the fixed portions of both packets plus the two extended
        // strings with their terminators; the logon strings add their own.
        var w = new ByteWriter(288
            + System.Text.Encoding.Unicode.GetByteCount(options.Domain)
            + System.Text.Encoding.Unicode.GetByteCount(options.UserName)
            + System.Text.Encoding.Unicode.GetByteCount(options.Password)
            + System.Text.Encoding.Unicode.GetByteCount(options.AlternateShell)
            + System.Text.Encoding.Unicode.GetByteCount(options.WorkingDir));

        // TS_SECURITY_HEADER (2.2.8.1.1.2.1): flags then flagsHi. Under TLS the
        // only client-to-server flag is SEC_INFO_PKT; SEC_ENCRYPT belongs to
        // in-force RDP-layer encryption, which this client does not do.
        w.U16(SecInfoPkt);
        w.U16(0);                                   // flagsHi

        // TS_INFO_PACKET (2.2.1.11.1.1).
        w.U32(CodePageEnUs);                        // CodePage: a language id under INFO_UNICODE

        // InfoAutoLogon follows the password, not the caller's taste: with the
        // flag set and an empty Password the server has to reject the packet
        // (xrdp logs "Client enable auto logon with credentials, but the
        // client did not" and stops).
        uint flags = DefaultFlags;
        if (options.Password.Length > 0)
        {
            flags |= InfoAutoLogon;
        }
        w.U32(flags);

        // The five declared counts exclude the mandatory null terminator.
        w.U16(stringBytes(options.Domain));
        w.U16(stringBytes(options.UserName));
        w.U16(stringBytes(options.Password));
        w.U16(stringBytes(options.AlternateShell));
        w.U16(stringBytes(options.WorkingDir));
        w.Utf16(options.Domain).U16(0);
        w.Utf16(options.UserName).U16(0);
        w.Utf16(options.Password).U16(0);
        w.Utf16(options.AlternateShell).U16(0);
        w.Utf16(options.WorkingDir).U16(0);

        // TS_EXTENDED_INFO_PACKET (2.2.1.11.1.1.1), required fields then the
        // chain that clientTimeZone opens. Both counts here include the null
        // terminator, unlike the five above - a difference read straight from
        // the two field definitions, and one that xrdp's bounds checks notice.
        w.U16(AddressFamilyInet);
        w.U16(2 * (ClientAddress.Length + 1));      // cbClientAddress, incl. terminator
        w.Utf16(ClientAddress).U16(0);
        w.U16(2 * (ClientDir.Length + 1));          // cbClientDir, incl. terminator
        w.Utf16(ClientDir).U16(0);
        w.Bytes(new byte[TimeZoneLength]);          // UTC: all biases and names empty
        w.U32(0);                                   // clientSessionId
        w.U32(0);                                   // performanceFlags
        // The chain stops here: without autoReconnectCookie the optional
        // reserved and Dynamic DST fields must not be present (2.2.1.11.1.1.1).

        return w.ToArray();
    }

    private static int stringBytes(string value)
    {
        int bytes = System.Text.Encoding.Unicode.GetByteCount(value);
        if (bytes > MaxStringBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value), bytes,
                $"a TS_INFO_PACKET string is limited to {MaxStringBytes} octets of text "
                + "plus its null terminator");
        }

        return bytes;
    }

    /// <summary>
    /// Say whether a server-to-client PDU is a Licensing PDU, and how long it
    /// is, so it can be skipped on the way to the Demand Active.
    /// </summary>
    /// <remarks>
    /// A Licensing PDU carries its own security header with
    /// <c>SEC_LICENSE_PKT</c> and no Share Control Header, so the two look alike
    /// only when a Share Control Header's <c>totalLength</c> happens to equal
    /// the licensing flag word. The header's <c>flagsHi</c> distinguishes them
    /// at all times: the licensing security header sets no
    /// <c>SEC_FLAGSHI_VALID</c> (xrdp writes it as zero), while a Share Control
    /// Header's third field is <c>pduType2</c>, which is never zero because the
    /// contained version bits make it at least the protocol version.
    /// </remarks>
    /// <param name="payload">One complete server PDU, security header included.</param>
    /// <param name="totalLength">Security header + the whole licensing message.</param>
    public static bool IsLicensePdu(ReadOnlySpan<byte> payload, out int totalLength)
    {
        totalLength = 0;
        if (payload.Length < SecurityHeaderSize + 4)
        {
            return false;
        }

        int flags = BinaryPrimitives.ReadUInt16LittleEndian(payload);
        if ((flags & SecLicensePkt) == 0)
        {
            return false;
        }

        int flagsHi = BinaryPrimitives.ReadUInt16LittleEndian(payload[2..]);
        if (flagsHi != 0)
        {
            return false;
        }

        // LICENSE_PREAMBLE (MS-RDPELE 2.2.2.1): bMsgType(1) bVersion(1)
        // wMessageSize(2), where wMessageSize counts itself. xrdp's valid-client
        // response is 16, covering the preamble and the eight-octet
        // dwErrorCode + dwStateTransition plus the blob header.
        int messageSize = BinaryPrimitives.ReadUInt16LittleEndian(payload[6..]);
        if (messageSize < 6)
        {
            return false;
        }

        totalLength = SecurityHeaderSize + messageSize;
        return true;
    }
}
