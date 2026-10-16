using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace RdpClient.Protocol;

public enum HandshakeStage
{
    Idle,
    TcpConnected,
    Negotiated,
    McsAccepted,
    DomainErected,
    UserAttached,
    ChannelJoined,
    Complete,
    Failed,
}

public sealed record HandshakeEvent(HandshakeStage Stage, string Message, bool IsError = false);

public sealed class RdpConnectionOptions
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
}

/// <summary>
/// Drives the RDP connection sequence up to the MCS channel join.
/// </summary>
/// <remarks>
/// This covers MS-RDPBCGR 2.2.1.1 through 2.2.1.3.8: X.224 negotiation, the
/// MCS/GCC connection, then the domain erect, user attach and channel join that
/// must precede any application traffic. Security (RSA key exchange or NLA) and
/// graphics are not yet part of this stage; the log makes the stopping point
/// explicit so a caller can tell a refused connection from an incomplete one.
/// </remarks>
public sealed class RdpConnection : IAsyncDisposable
{
    public const int DefaultPort = RdpConnectionOptions.DefaultPort;

    private readonly TcpClient _client = new();
    private NetworkStream? _stream;

    public HandshakeStage Stage { get; private set; } = HandshakeStage.Idle;
    public string? SelectedProtocol { get; private set; }
    public uint? NegotiatedVersion { get; private set; }
    public string? ServerNodeId { get; private set; }
    public ushort? UserId { get; private set; }
    public string? FailureReason { get; private set; }

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

        // Advertise SSL, HYBRID and HYBRID_EX, matching what mstsc requests. The
        // server picks one; a host that only offers classic RDP selects the
        // SSL bit.
        const uint requestedProtocols =
            Rdp.ProtocolSsl | Rdp.ProtocolHybrid | Rdp.ProtocolHybridEx;

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

            // The server has chosen an External Security Protocol. Anything
            // other than plain TLS (PROTOCOL_SSL) means CredSSP, which carries a
            // full TLS + SPNEGO + NTLM exchange before MCS may start. Sending an
            // MCS Connect Initial now would be a protocol violation, so stop
            // here with an accurate reason instead.
            uint selected = confirm.SelectedProtocol ?? 0;
            if (selected != Rdp.ProtocolSsl && selected != 0)
            {
                FailureReason =
                    $"server selected {Negotiation.DescribeSelectedProtocol(selected)}, which requires the "
                    + "CredSSP/NLA handshake (TLS + SPNEGO + NTLM). That handshake is not implemented, so the "
                    + "MCS layer cannot start.";
                Report(HandshakeStage.Negotiated, FailureReason, isError: true);
                return HandshakeStage.Failed;
            }

            // --- 2.2.1.3.4 MCS Connect Initial ---
            byte[] clientInfo = BuildClientInfo(options.User, options.Core, confirm.SelectedProtocol ?? 0);
            byte[] connectInitial = Mcs.BuildConnectInitialPdu(new Mcs.ConnectInitialOptions
            {
                ClientInfo = clientInfo,
            });

            await _stream.WriteAsync(connectInitial, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
            Report(HandshakeStage.Negotiated, $"sent MCS Connect Initial ({connectInitial.Length} bytes)");

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
            await _stream.WriteAsync(erect, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
            Report(HandshakeStage.DomainErected, $"sent Erect Domain Request ({erect.Length} bytes)");

            byte[] attach = Mcs.BuildAttachUserRequest(0x03fa, Rdp.McsUserChannelBase);
            await _stream.WriteAsync(attach, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
            Report(HandshakeStage.UserAttached, $"sent Attach User Request, UserID {Rdp.McsUserChannelBase}");

            byte[] join = Mcs.BuildChannelJoinRequest(0x03fa, Rdp.McsGlobalChannel, Rdp.McsUserChannelBase);
            await _stream.WriteAsync(join, cancellationToken);
            await _stream.FlushAsync(cancellationToken);
            Report(HandshakeStage.ChannelJoined, $"joined MCS global channel {Rdp.McsGlobalChannel}");

            Report(HandshakeStage.Complete,
                "MCS channel joined. Security negotiation and graphics are not implemented yet, "
                + "so the session will not display a desktop.");
            return HandshakeStage.Complete;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            FailureReason = ex.Message;
            Report(HandshakeStage.Failed, ex.Message, isError: true);
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
        ArgumentNullException.ThrowIfNull(_stream);

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
        ArgumentNullException.ThrowIfNull(_stream);
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await _stream.ReadAsync(buffer.AsMemory(read, count - read), cancellationToken);
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
        if (_stream is not null)
        {
            await _stream.DisposeAsync();
        }

        _client.Dispose();
    }
}

public sealed class RdpProtocolException : Exception
{
    public RdpProtocolException(string message) : base(message) { }
}