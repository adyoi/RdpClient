namespace RdpClient.Protocol.Security;

/// <summary>How the connection is protected after RDP negotiation.</summary>
/// <remarks>
/// Chosen from the server's <c>SelectedProtocol</c>, never assumed. Each mode
/// changes what happens on the wire after <c>RDP_NEG_RSP</c>.
/// </remarks>
public enum SecurityMode
{
    /// <summary>No external security protocol; MCS runs in plain security mode.</summary>
    None = 0,

    /// <summary><c>PROTOCOL_SSL</c>: TLS only, then MCS (MS-RDPBCGR 5.2).</summary>
    Tls = 1,

    /// <summary>
    /// <c>PROTOCOL_HYBRID</c> or <c>PROTOCOL_HYBRID_EX</c>: the CredSSP External
    /// Security Protocol, TLS plus SPNEGO with NTLM, after which MCS is
    /// protected by the CredSSP key exchange (MS-RDPEA 3.2.1.5.1).
    /// </summary>
    CredSsp = 2,
}

public static class SecurityModes
{
    /// <summary>
    /// Map a negotiated <c>SelectedProtocol</c> bitmask to a security mode.
    /// </summary>
    /// <remarks>
    /// <c>PROTOCOL_RDSTLS</c> and <c>PROTOCOL_RDSAAD</c> are not treated as TLS:
    /// RDSTLS is reserved for future use and RDSAAD implies CredSSP, so a host
    /// selecting either is reported as CredSSP rather than silently downgraded.
    /// </remarks>
    public static SecurityMode FromSelectedProtocol(uint selectedProtocol) => selectedProtocol switch
    {
        Rdp.ProtocolSsl => SecurityMode.Tls,
        Rdp.ProtocolHybrid => SecurityMode.CredSsp,
        Rdp.ProtocolHybridEx => SecurityMode.CredSsp,
        Rdp.ProtocolRdsaad => SecurityMode.CredSsp,
        0 => SecurityMode.None,
        _ => throw new NotSupportedException(
            $"SelectedProtocol 0x{selectedProtocol:x8} does not name a supported "
            + "External Security Protocol"),
    };

    /// <summary>The bit this client advertises for a given mode.</summary>
    public static uint AdvertisedProtocol(SecurityMode mode) => mode switch
    {
        SecurityMode.Tls => Rdp.ProtocolSsl,
        SecurityMode.CredSsp => Rdp.ProtocolHybrid,
        _ => 0,
    };

    /// <summary>
    /// True when the mode runs a TLS handshake on the same TCP connection.
    /// </summary>
    /// <remarks>
    /// Both <c>Tls</c> and <c>CredSsp</c> do. In CredSSP the handshake is the
    /// transport for the SPNEGO exchange, not the security itself.
    /// </remarks>
    public static bool UsesTls(SecurityMode mode) =>
        mode is SecurityMode.Tls or SecurityMode.CredSsp;

    /// <summary>True when the mode additionally runs SPNEGO with NTLM.</summary>
    public static bool UsesSasl(SecurityMode mode) => mode is SecurityMode.CredSsp;

    /// <summary>Human-readable name for logs and error messages.</summary>
    public static string Describe(SecurityMode mode) => mode switch
    {
        SecurityMode.None => "no external security protocol (classic RDP)",
        SecurityMode.Tls => "TLS",
        SecurityMode.CredSsp => "CredSSP (TLS + SPNEGO/NTLM)",
        _ => mode.ToString(),
    };
}