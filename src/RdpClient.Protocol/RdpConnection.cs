using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

using RdpClient.Protocol.Security;

namespace RdpClient.Protocol;

public enum HandshakeStage
{
    Idle,
    TcpConnected,
    Negotiated,
    TlsEstablished,
    Authenticated,
    Renegotiated,
    McsAccepted,
    DomainErected,
    UserAttached,
    ChannelJoined,
    Complete,
    Failed,
}

public sealed record HandshakeEvent(HandshakeStage Stage, string Message, bool IsError = false);

public sealed record RdpConnectionOptions
{
    /// <summary>IANA-assigned RDP port.</summary>
    public const int DefaultPort = 3389;

    public string Host { get; init; } = string.Empty;
    public int Port { get; init; } = DefaultPort;
    public ClientPdu.UserOptions? User { get; init; }
    public ClientPdu.CoreOptions? Core { get; init; }

    /// <summary>
    /// Send the MS-RDPBCGR 2.2.1.1.1 correlation block. Turning this off
    /// produces the minimal 19-byte connection request.
    /// </summary>
    public bool UseCorrelationId { get; init; } = true;

    /// <summary>Log each transmitted PDU as hex. Credential-bearing PDUs are never logged.</summary>
    public bool LogTx { get; init; }

    /// <summary>
    /// External security protocol to require. <see cref="SecurityModeSelection.Negotiate"/>
    /// advertises several protocols and accepts whichever the server selects.
    /// </summary>
    public SecurityModeSelection Security { get; init; } = SecurityModeSelection.Negotiate;

    /// <summary>TLS protocol versions to offer. Defaults to TLS 1.2 and 1.3.</summary>
    public System.Security.Authentication.SslProtocols TlsPolicy { get; init; } =
        System.Security.Authentication.SslProtocols.Tls12 |
        System.Security.Authentication.SslProtocols.Tls13;
}

/// <summary>Which External Security Protocol the caller is willing to use.</summary>
public enum SecurityModeSelection
{
    /// <summary>
    /// Advertise SSL, HYBRID and HYBRID_EX and accept whatever the server picks.
    /// This is what a normal client does.
    /// </summary>
    Negotiate,

    /// <summary>Require <c>PROTOCOL_SSL</c>, so no SPNEGO exchange is needed.</summary>
    TlsOnly,

    /// <summary>Require CredSSP, so authentication happens over TLS.</summary>
    CredSspOnly,
}

/// <summary>
/// Drives the RDP connection sequence up to the MCS channel join.
/// </summary>
/// <remarks>
/// Covers MS-RDPBCGR 2.2.1.1 through 2.2.1.3.8: X.224 negotiation, the
/// External Security Protocol, the MCS/GCC connection, then the domain erect,
/// user attach and channel join that must precede any application traffic.
/// Graphics and input are not yet part of this stage, and the log makes the
/// stopping point explicit so a caller can tell a refused connection from an
/// incomplete one.
/// </remarks>
public sealed class RdpConnection : IAsyncDisposable
{
    public const int DefaultPort = RdpConnectionOptions.DefaultPort;

    private readonly TcpClient _client = new();
    private NetworkStream? _stream;

    /// <summary>Stream carrying RDP PDUs: the TCP stream, or TLS once established.</summary>
    private Stream? _channel;
    private TlsChannel? _tls;

    public HandshakeStage Stage { get; private set; } = HandshakeStage.Idle;
    public string? SelectedProtocol { get; private set; }
    public uint? NegotiatedVersion { get; private set; }
    public string? ServerNodeId { get; private set; }
    public ushort? UserId { get; private set; }
    public string? FailureReason { get; private set; }

    /// <summary>The External Security Protocol the server selected.</summary>
    public SecurityMode SecurityMode { get; private set; } = SecurityMode.None;

    public event Action<HandshakeEvent>? OnEvent;

    private void Report(HandshakeStage stage, string message, bool isError = false)
    {
        Stage = stage;
        OnEvent?.Invoke(new HandshakeEvent(stage, message, isError));
    }

    /// <summary>Run the connection sequence described by <paramref name="options"/>.</summary>
    public async Task<HandshakeStage> ConnectAsync(
        RdpConnectionOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Host);

        string host = options.Host;
        int port = options.Port;

        // Advertise only the protocols the caller is willing to complete. The default
        // offers what mstsc offers, so an unmodified host picks what it prefers.
        uint requestedProtocols = options.Security switch
        {
            SecurityModeSelection.TlsOnly => Rdp.ProtocolSsl,
            SecurityModeSelection.CredSspOnly => Rdp.ProtocolHybrid,
            _ => Rdp.ProtocolSsl | Rdp.ProtocolHybrid | Rdp.ProtocolHybridEx,
        };

        byte[]? correlationId = options.UseCorrelationId
            ? RandomNumberGenerator.GetBytes(16)
            : null;

        try
        {
            Report(HandshakeStage.Idle, $"resolving {host}...");
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
            if (addresses.Length == 0)
            {
                throw new SocketException((int)SocketError.HostNotFound);
            }

            // Prefer IPv4; RDP servers rarely expose usable IPv6 on the default port.
            IPAddress target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                               ?? addresses[0];

            Report(HandshakeStage.Idle, $"connecting to {target}:{port}...");
            await _client.ConnectAsync(target, port, cancellationToken);
            _stream = _client.GetStream();

            // Everything from here is sent on the channel, which starts as the raw
            // TCP stream and is replaced by TLS once the handshake completes.
            _channel = _stream;
            Report(HandshakeStage.TcpConnected, $"TCP established to {target}:{port}");

            // --- 2.2.1.1 X.224 Connection Request with RDP_NEG_REQ ---
            byte[] request = Negotiation.BuildConnectionRequest(requestedProtocols, correlationId);
            await _stream.WriteAsync(request, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
            Report(HandshakeStage.TcpConnected, $"sent X.224 Connection Request ({request.Length} bytes)");
            if (options.LogTx)
            {
                Report(HandshakeStage.TcpConnected, "  TX " + Hex(request));
            }

            byte[] response = await ReadTpktAsync(cancellationToken);
            var confirm = Negotiation.ParseConnectionConfirm(response);
            if (confirm.Failed)
            {
                throw new RdpProtocolException($"RDP negotiation refused: {confirm.Summary}");
            }

            NegotiatedVersion = confirm.NegotiatedVersion;
            SelectedProtocol = Negotiation.DescribeSelectedProtocol(confirm.SelectedProtocol ?? 0);

            bool correlationMatched = correlationId is not null
                && confirm.CorrelationId is not null
                && confirm.CorrelationId.AsSpan().SequenceEqual(correlationId);
            Report(HandshakeStage.Negotiated,
                $"{confirm.Summary}; correlation {(correlationMatched ? "echoed correctly" : "NOT echoed")}");

            // --- Establish the External Security Protocol (MS-RDPEA 3.1.5.1) ---
            uint selected = confirm.SelectedProtocol ?? 0;
            SecurityMode mode;
            try
            {
                mode = SecurityModes.FromSelectedProtocol(selected);
            }
            catch (NotSupportedException ex)
            {
                FailureReason = ex.Message;
                Report(HandshakeStage.Negotiated, FailureReason, isError: true);
                return HandshakeStage.Failed;
            }

            SecurityMode = mode;
            Report(HandshakeStage.Negotiated, $"External Security Protocol: {SecurityModes.Describe(mode)}");

            if (SecurityModes.UsesTls(mode))
            {
                // The TLS handshake runs on the same TCP connection. SNI must be
                // TERMSRV/<host>, which is what an RDP host matches its
                // certificate against.
                string sspiTarget = $"TERMSRV/{host}";
                Report(HandshakeStage.Negotiated, $"starting TLS handshake, SNI '{sspiTarget}'");
                _tls = await TlsChannel.HandshakeAsync(_stream, sspiTarget, options.TlsPolicy, cancellationToken)
                    .ConfigureAwait(false);
                _channel = _tls.Stream;
                Report(HandshakeStage.TlsEstablished, _tls.DescribeCertificate());
            }

            if (SecurityModes.UsesSasl(mode))
            {
                // CredSSP: authenticate over the TLS channel, then the RDP
                // negotiation is repeated inside it (MS-RDPEA 3.2.1.5.1.5).
                if (options.User is null)
                {
                    FailureReason =
                        "the server selected CredSSP, which authenticates with NTLM, but no user name was supplied";
                    Report(HandshakeStage.TlsEstablished, FailureReason, isError: true);
                    return HandshakeStage.Failed;
                }

                var authenticator = new NtlmAuthenticator(
                    options.User.UserName,
                    options.User.Domain,
                    options.User.Password,
                    trace: message => Report(HandshakeStage.TlsEstablished, message));
                await authenticator.AuthenticateAsync(_channel, cancellationToken).ConfigureAwait(false);
                Report(HandshakeStage.Authenticated,
                    $"NTLM authentication succeeded for '{authenticator.AuthenticatedUser}' in domain "
                    + $"'{authenticator.AuthenticatedDomain}'");

                await RenegotiateInsideCredSspAsync(selected, cancellationToken).ConfigureAwait(false);
                Report(HandshakeStage.Renegotiated, "repeated RDP negotiation inside the CredSSP channel");
            }

            // --- 2.2.1.3.4 MCS Connect Initial ---
            byte[] clientInfo = BuildClientInfo(options.User, options.Core, confirm.SelectedProtocol ?? 0);
            byte[] connectInitial = Mcs.BuildConnectInitialPdu(new Mcs.ConnectInitialOptions
            {
                ClientInfo = clientInfo,
            });

            await _channel.WriteAsync(connectInitial, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.McsAccepted, $"sent MCS Connect Initial ({connectInitial.Length} bytes)");

            byte[] connectResponseRaw = await ReadTpktAsync(cancellationToken);
            var connectResponse = Mcs.ParseConnectResponse(connectResponseRaw);
            if (!connectResponse.Success)
            {
                throw new RdpProtocolException($"MCS refused the connection: {connectResponse.Summary}");
            }

            UserId = connectResponse.UserId;
            ServerNodeId = connectResponse.ServerNodeId?.ToString();
            Report(HandshakeStage.McsAccepted, connectResponse.Summary);

            // --- 2.2.1.3.6 Erect Domain, 2.2.1.3.7 Attach User, 2.2.1.3.8 join ---
            byte[] erect = Mcs.BuildErectDomainRequest(0x03fa, Rdp.McsGlobalChannel);
            await _channel.WriteAsync(erect, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.DomainErected, $"sent Erect Domain Request ({erect.Length} bytes)");

            byte[] attach = Mcs.BuildAttachUserRequest(0x03fa, Rdp.McsUserChannelBase);
            await _channel.WriteAsync(attach, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.UserAttached, $"sent Attach User Request, UserID {Rdp.McsUserChannelBase}");

            byte[] join = Mcs.BuildChannelJoinRequest(0x03fa, Rdp.McsGlobalChannel, Rdp.McsUserChannelBase);
            await _channel.WriteAsync(join, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.ChannelJoined, $"joined MCS global channel {Rdp.McsGlobalChannel}");

            Report(HandshakeStage.Complete,
                "MCS channel joined. The capability exchange, graphics and input are "
                + "not implemented yet, so the session will not display a desktop.");
            return HandshakeStage.Complete;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // TLS and SPNEGO failures are usually wrapped; the inner message is
            // the one that says what actually went wrong.
            FailureReason = Describe(ex);
            Report(HandshakeStage.Failed, FailureReason, isError: true);
            return HandshakeStage.Failed;
        }
        finally
        {
            if (Stage is HandshakeStage.Failed)
            {
                _client.Close();
            }
        }
    }

    /// <summary>Concatenate the TS_UD_CS_* blocks a server expects before MCS completes.</summary>
    private static byte[] BuildClientInfo(
        ClientPdu.UserOptions? user,
        ClientPdu.CoreOptions? core,
        uint serverSelectedProtocol)
    {
        core ??= new ClientPdu.CoreOptions { ServerSelectedProtocol = serverSelectedProtocol };

        var blocks = new List<byte[]>
        {
            ClientPdu.BuildCore(core),
            ClientPdu.BuildSecurity(),
            ClientPdu.BuildNet(ClientPdu.DefaultChannels()),
            ClientPdu.BuildCluster(),
        };

        // TS_UD_CS_USER is only sent when there are credentials to present.
        if (user is not null && !string.IsNullOrEmpty(user.UserName))
        {
            blocks.Add(ClientPdu.BuildUser(user));
        }

        var joined = new ByteWriter(512);
        foreach (byte[] block in blocks)
        {
            joined.Bytes(block);
        }

        return joined.ToArray();
    }

    /// <summary>
    /// Repeat the RDP negotiation inside the CredSSP channel.
    /// </summary>
    /// <remarks>
    /// MS-RDPEA 3.2.1.5.1.5 requires the client to send a second
    /// <c>RDP_NEG_REQ</c> inside the authenticated channel, carrying
    /// <c>PROTOCOL_HYBRID</c>. Servers reject the MCS Connect Initial that
    /// follows if it is missing.
    /// </remarks>
    private async Task RenegotiateInsideCredSspAsync(uint selectedProtocol, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(_channel);

        byte[] request = Negotiation.BuildConnectionRequest(
            selectedProtocol == Rdp.ProtocolHybridEx ? Rdp.ProtocolHybridEx : Rdp.ProtocolHybrid);

        await _channel.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await _channel.FlushAsync(cancellationToken).ConfigureAwait(false);

        byte[] response = await ReadTpktAsync(cancellationToken).ConfigureAwait(false);
        var confirm = Negotiation.ParseConnectionConfirm(response);
        if (confirm.Failed)
        {
            throw new RdpProtocolException(
                $"CredSSP renegotiation refused: {confirm.Summary}");
        }

        uint inner = confirm.SelectedProtocol ?? 0;
        if ((inner & (Rdp.ProtocolHybrid | Rdp.ProtocolHybridEx)) == 0)
        {
            throw new RdpProtocolException(
                $"CredSSP renegotiation returned {Negotiation.DescribeSelectedProtocol(inner)}, "
                + "which is not a CredSSP protocol");
        }
    }

    /// <summary>
    /// Flatten an exception chain into one line, so a wrapped TLS or SPNEGO
    /// failure still reports its root cause in the handshake log.
    /// </summary>
    private static string Describe(Exception exception)
    {
        var parts = new List<string>();
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            string message = current.Message;
            if (!parts.Contains(message))
            {
                parts.Add(message);
            }
        }

        return string.Join(" -> ", parts);
    }

    /// <summary>Format bytes as offset-prefixed hex, for protocol debugging.</summary>
    private static string Hex(byte[] data)
    {
        var sb = new System.Text.StringBuilder(data.Length * 3 + 16);
        for (int i = 0; i < data.Length; i++)
        {
            if (i % 16 == 0)
            {
                sb.Append(CultureInfo.InvariantCulture, $"  {i:x4}:  ");
            }

            sb.Append(data[i].ToString("x2", CultureInfo.InvariantCulture));
            sb.Append(i % 16 == 15 ? '\n' : ' ');
        }

        return sb.ToString().TrimEnd();
    }

    /// <summary>Read one complete TPKT-framed PDU.</summary>
    private async Task<byte[]> ReadTpktAsync(CancellationToken cancellationToken)
    {
        // TPKT header: version(1), reserved(1), big-endian length(2).
        byte[] header = await ReadExactlyAsync(4, cancellationToken);
        int totalLength = (header[2] << 8) | header[3];

        if (totalLength < 7 || totalLength > Rdp.TpktMaxLength)
        {
            throw new InvalidDataException($"implausible TPKT length {totalLength}");
        }

        byte[] body = await ReadExactlyAsync(totalLength - 4, cancellationToken);
        var full = new byte[totalLength];
        header.CopyTo(full, 0);
        body.CopyTo(full, 4);
        return full;
    }

    private async Task<byte[]> ReadExactlyAsync(int count, CancellationToken cancellationToken)
    {
        Stream channel = _channel
            ?? throw new InvalidOperationException("the connection is not established");
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await channel.ReadAsync(buffer.AsMemory(read, count - read), cancellationToken);
            if (n == 0)
            {
                throw new EndOfStreamException(
                    $"connection closed after {read} of {count} expected bytes");
            }

            read += n;
        }

        return buffer;
    }

    public async ValueTask DisposeAsync()
    {
        if (_tls is not null)
        {
            await _tls.DisposeAsync().ConfigureAwait(false);
        }
        else if (_stream is not null)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }

        _client.Dispose();
    }
}

public sealed class RdpProtocolException : Exception
{
    public RdpProtocolException(string message) : base(message) { }
}