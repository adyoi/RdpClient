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
    CapabilityExchanged,
    ActiveConfirmed,
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

    /// <summary>
    /// Append the classic-RDP user data block that carries a password.
    /// </summary>
    /// <remarks>
    /// Off by default. MS-RDPBCGR 2.2.1.3 defines no such block - xrdp answers
    /// <c>TS_UD_HEADER type 0xc00e is unknown (ignored)</c> - so enabling this
    /// sends a credential in UTF-16 in the clear to a server that discards it.
    /// It exists to exercise the classic path deliberately, not by default.
    /// </remarks>
    public bool SendClassicUserBlock { get; init; }

    /// <summary>Log each transmitted PDU as hex. Credential-bearing PDUs are never logged.</summary>
    public bool LogTx { get; init; }

    /// <summary>
    /// Turning this on announces <c>RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN</c> and sends
    /// no Channel Join Requests at all. Off by default.
    /// </summary>
    /// <remarks>
    /// The flag and the behaviour are set together from this one property,
    /// because they contradict each other: announcing the skip and then joining
    /// anyway tells the server two contradictory things.
    /// <para>
    /// It is off by default because it is the unverified path. Sending the joins
    /// is the measured one: xrdp accepts the full set, answers every Confirm and
    /// completes its MCS sequence. Whether it then sends the Demand Active PDU is
    /// a separate question this option does not by itself settle, which is what
    /// <see cref="Timeout"/> is for.
    /// </para>
    /// </remarks>
    public bool SkipChannelJoin { get; init; }

    /// <summary>
    /// How long the whole handshake may take, in seconds. 30 by default.
    /// </summary>
    /// <remarks>
    /// Every read here is a blocking socket read, so a server that stops
    /// mid-sequence leaves the client waiting forever with nothing in the log:
    /// the failure is indistinguishable from a slow server. That was measured
    /// rather than assumed - the probe had to be killed instead of returning. A
    /// bounded handshake turns it into a reported failure with a cause, which is
    /// the only useful outcome; the alternative is a process that looks hung.
    /// </remarks>
    public int Timeout { get; init; } = 30;

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
/// Covers MS-RDPBCGR 2.2.1.1 through 2.2.1.9: X.224 negotiation, the
/// External Security Protocol, the MCS/GCC connection, then the domain erect,
/// user attach and channel joins that must precede any application traffic.
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
        CancellationToken callerToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Host);

        string host = options.Host;
        int port = options.Port;

        // A blocking socket read cannot tell a stalled server from a slow one, so
        // the whole handshake is bounded. Without this the client waits forever
        // and looks hung, which is exactly what a truncated capture shows: the
        // server logs nothing and the client never returns.
        using var deadline = new CancellationTokenSource(
            TimeSpan.FromSeconds(options.Timeout > 0 ? options.Timeout : 30));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            deadline.Token, callerToken);

        // Named for the rest of the method so that every await below is bounded
        // without each one having to know where the deadline came from.
        CancellationToken cancellationToken = linked.Token;

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

                if (_tls?.ServerCertificate is null)
                {
                    FailureReason = "the server presented no certificate, so the CredSSP "
                        + "channel binding cannot be computed";
                    Report(HandshakeStage.TlsEstablished, FailureReason, isError: true);
                    return HandshakeStage.Failed;
                }

                var authenticator = new NtlmAuthenticator(
                    options.User.UserName,
                    options.User.Domain,
                    options.User.Password,
                    CredSsp.ExtractSubjectPublicKey(_tls.ServerCertificate),
                    trace: message => Report(HandshakeStage.TlsEstablished, message));
                await authenticator.AuthenticateAsync(_channel, cancellationToken).ConfigureAwait(false);
                Report(HandshakeStage.Authenticated,
                    $"NTLM authentication succeeded for '{authenticator.AuthenticatedUser}' in domain "
                    + $"'{authenticator.AuthenticatedDomain}'");

                await RenegotiateInsideCredSspAsync(selected, cancellationToken).ConfigureAwait(false);
                Report(HandshakeStage.Renegotiated, "repeated RDP negotiation inside the CredSSP channel");
            }

            // --- 2.2.1.3 MCS Connect Initial ---
            byte[] clientInfo = BuildClientInfo(options.User, options.Core, selected, options);
            var channels = ClientPdu.DefaultChannels();
            int channelCount = channels.Count;
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

            // --- 2.2.1.5 Erect Domain, 2.2.1.6 Attach User, 2.2.1.8 channel join ---
            //
            // Each step the server answers is answered with a reply, and the
            // reply is what proves the step worked. Sending them and declaring
            // success without reading the replies is how a connection that the
            // server rejected at the first PDU gets reported as a completed
            // channel join.
            //
            // The Erect Domain Request is the exception: T.125 has no confirm for
            // it, which is why the Attach User Confirm is the first reply read
            // here. xrdp says as much where it sets
            // expecting_channel_join_requests, "after the attach user confirm".
            byte[] erect = Mcs.BuildErectDomainRequest();
            await _channel.WriteAsync(erect, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.DomainErected, $"sent Erect Domain Request ({erect.Length} bytes)");

            byte[] attach = Mcs.BuildAttachUserRequest();
            await _channel.WriteAsync(attach, cancellationToken);
            await _channel.FlushAsync(cancellationToken);
            Report(HandshakeStage.UserAttached, $"sent Attach User Request ({attach.Length} bytes)");

            // The Attach User Confirm is where the server states which user id
            // it assigned. The Channel Join Request must carry that id, not a
            // conventional 1001, so it cannot be built until this has been read.
            var attachConfirm = Mcs.ParseAttachUserConfirm(await ReadTpktAsync(cancellationToken));
            if (!attachConfirm.Success || attachConfirm.UserId is not ushort assigned)
            {
                throw new RdpProtocolException($"the server did not attach the user: {attachConfirm.Summary}");
            }

            UserId = assigned;
            Report(HandshakeStage.UserAttached, attachConfirm.Summary);

            // Every channel offered in TS_UD_CS_NET is joined by its own Channel
            // Join Request, then the MCS user channel and the global channel -
            // unless the client announced RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN, in
            // which case it owes the server no joins at all. Both paths are here
            // because the flag is what selects between them.
            if (options.SkipChannelJoin)
            {
                Report(HandshakeStage.ChannelJoined,
                    $"announced RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN "
                    + $"({Rdp.EarlyCapSupportSkipChannelJoin:x4}); sent no Channel Join Requests");
            }
            else
            {
                await JoinChannelsAsync(assigned, channelCount, cancellationToken).ConfigureAwait(false);
            }

            // --- 2.2.1.13 Mandatory capability exchange ---
            //
            // The server now asks for capabilities with a Demand Active PDU and
            // will not send anything further until a Confirm Active comes back.
            // Reading it is also the first proof that the channel joins landed:
            // the server only gets here once its expected joins have arrived.
            Capability.DemandActive demand = await ReadDemandActiveAsync(cancellationToken)
                .ConfigureAwait(false);
            Report(HandshakeStage.CapabilityExchanged,
                $"server demanded {demand.Capabilities.Count} capability sets "
                + $"({demand.Summary}), session {demand.SessionId}");

            byte[] confirmActive = Capability.BuildConfirmActivePdu(
                demand.ShareId, [Capability.BuildGeneralCapabilitySet()]);
            await SendOnGlobalChannelAsync(assigned, confirmActive, cancellationToken).ConfigureAwait(false);
            Report(HandshakeStage.ActiveConfirmed,
                $"answered with {Capability.DescribeCapabilitySets(
                    Capability.ParseCapabilitySets(
                        confirmActive,
                        Capability.ShareControlHeaderSize + 4 + 2 + 2 + 2 + 4,
                        confirmActive.Length - Capability.ShareControlHeaderSize - 4 - 2 - 2 - 2 - 4))} "
                + $"in {confirmActive.Length} bytes");

            Report(HandshakeStage.Complete,
                "Capability exchange complete. Licensing, the Synchronize PDUs, graphics "
                + "and input are not implemented yet, so the session will not display a desktop.");
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
        catch (OperationCanceledException) when (deadline.IsCancellationRequested)
        {
            // The stage is still whatever was last reported, which is the useful
            // part: "it stopped while waiting for the Demand Active PDU" is a
            // diagnosable failure, and waiting forever is not a failure at all.
            FailureReason =
                $"the server stopped responding after {options.Timeout}s; the last thing that "
                + $"worked was {DescribeStage(Stage)}";
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
    /// <remarks>
    /// The negotiated protocol is written into CORE's serverSelectedProtocol
    /// whatever the caller supplied, because MS-RDPBCGR 2.2.1.3.2 says the field
    /// carries the value the server returned in its RDP_NEG_RSP and the server
    /// compares it against what it actually selected.
    /// </remarks>
    private static byte[] BuildClientInfo(
        ClientPdu.UserOptions? user,
        ClientPdu.CoreOptions? core,
        uint serverSelectedProtocol,
        RdpConnectionOptions options)
    {
        core = (core ?? new ClientPdu.CoreOptions()) with
        {
            ServerSelectedProtocol = serverSelectedProtocol,

            // Announcing the skip and then joining anyway tells the server two
            // contradictory things, so the flag and the channel joins are decided
            // in the same place.
            EarlyCapabilityFlags = (ushort)((core?.EarlyCapabilityFlags ?? 0)
                | (options.SkipChannelJoin ? Rdp.EarlyCapSupportSkipChannelJoin : 0)),
        };

        var blocks = new List<byte[]>
        {
            ClientPdu.BuildCore(core),
            ClientPdu.BuildSecurity(),
            ClientPdu.BuildNet(ClientPdu.DefaultChannels()),
            ClientPdu.BuildCluster(),
        };

        // The user block is not part of MS-RDPBCGR and xrdp answers
        // "TS_UD_HEADER type 0xc00e is unknown (ignored)". Sending it sends a
        // password the server is about to discard, so it is opt-in rather than
        // automatic: a caller that wants the classic cleartext path has to say
        // so, which is the point at which the README's security warning applies.
        if (user is not null && !string.IsNullOrEmpty(user.UserName) && options.SendClassicUserBlock)
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
    /// Join every channel the connection needs, one Channel Join Request each,
    /// reading a Confirm for every one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The order and the count are not this client's invention. xrdp's
    /// <c>handle_channel_join_requests</c> says it expects a join "for each of the
    /// static virtual channels, plus the user channel (self-&gt;chanid) and the I/O
    /// channel (MCS_GLOBAL_CHANNEL)", and computes
    /// <c>expected_join_count = channel_list-&gt;count + 2</c>. Its
    /// <c>channel_list</c> is built from the client's own TS_UD_CS_NET, so the
    /// count depends on what was offered, not on a fixed number.
    /// </para>
    /// <para>
    /// Static channel ids are assigned by position, so the Nth channel offered
    /// gets 1004 + N. FreeRDP and xrdp both derive the base from the global
    /// channel id rather than hardcoding 1004.
    /// </para>
    /// <para>
    /// Every Confirm is checked against the channel that was asked for. A Confirm
    /// that reports success for a different channel is a failure, not a success
    /// to be reported.
    /// </para>
    /// </remarks>
    private async Task JoinChannelsAsync(
        ushort userId, int staticChannelCount, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(_channel);

        var targets = new List<ushort>(staticChannelCount + 2);
        for (int i = 0; i < staticChannelCount; i++)
        {
            targets.Add(Rdp.McsStaticChannel(i));
        }

        targets.Add(Rdp.McsUserChannel);
        targets.Add(Rdp.McsGlobalChannel);

        foreach (ushort channel in targets)
        {
            byte[] join = Mcs.BuildChannelJoinRequest(userId, channel);
            await _channel.WriteAsync(join, cancellationToken).ConfigureAwait(false);
            await _channel.FlushAsync(cancellationToken).ConfigureAwait(false);

            var confirm = Mcs.ParseChannelJoinConfirm(
                await ReadTpktAsync(cancellationToken).ConfigureAwait(false),
                expectedChannel: channel);

            if (!confirm.Success)
            {
                throw new RdpProtocolException($"the server refused the channel join: {confirm.Summary}");
            }

            Report(HandshakeStage.ChannelJoined, confirm.Summary);
        }
    }

    /// <summary>
    /// Read the server's Demand Active PDU, reassembling it if it arrives in
    /// several MCS fragments.
    /// </summary>
    /// <remarks>
    /// A PDU larger than one MCS fragment arrives as a run of Send Data
    /// Indications and only the one marked as the last fragment completes it.
    /// Reading a single one of those is the same mistake as reading a single
    /// reply: the PDU would be parsed from a prefix and every field after the cut
    /// would come from the wrong place.
    /// </remarks>
    private async Task<Capability.DemandActive> ReadDemandActiveAsync(CancellationToken cancellationToken)
    {
        var buffer = new MemoryStream();
        int fragments = 0;

        while (true)
        {
            var indication = Mcs.ParseSendDataIndication(
                await ReadTpktAsync(cancellationToken).ConfigureAwait(false));

            if (indication.ChannelId != Rdp.McsGlobalChannel)
            {
                throw new RdpProtocolException(
                    $"expected the Demand Active PDU on MCS channel {Rdp.McsGlobalChannel}, "
                    + $"the server used {indication.ChannelId}");
            }

            buffer.Write(indication.Payload, 0, indication.Payload.Length);

            if (indication.Segmentation is Mcs.SegmentationLast or Mcs.SegmentationSingle)
            {
                break;
            }

            // A misread segmentation value would otherwise loop on this read
            // until the socket closed, which is how a parse bug turns into a
            // hang with no diagnostic at all.
            if (++fragments > Mcs.MaxSendDataFragments)
            {
                throw new RdpProtocolException(
                    $"the Demand Active PDU is still incomplete after {fragments} fragments "
                    + $"({buffer.Length} octets); the segmentation field is probably being read wrong");
            }
        }

        return Capability.ParseDemandActive(buffer.ToArray());
    }

    /// <summary>Send one PDU on the MCS global channel as an MCS Send Data Request.</summary>
    private async Task SendOnGlobalChannelAsync(
        ushort userId, byte[] payload, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(_channel);

        foreach (byte[] frame in Mcs.BuildSendDataRequest(userId, Rdp.McsGlobalChannel, payload))
        {
            await _channel.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        }

        await _channel.FlushAsync(cancellationToken).ConfigureAwait(false);
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

    /// <summary>Name the stage a timeout interrupted, for a failure with no other cause.</summary>
    private static string DescribeStage(HandshakeStage stage) => stage switch
    {
        HandshakeStage.Idle => "the TCP connection",
        HandshakeStage.TcpConnected => "the X.224 connection request",
        HandshakeStage.Negotiated => "the security protocol negotiation",
        HandshakeStage.TlsEstablished => "the TLS handshake",
        HandshakeStage.Authenticated => "NTLM authentication",
        HandshakeStage.Renegotiated => "the negotiation inside the CredSSP channel",
        HandshakeStage.McsAccepted => "the MCS Connect Initial",
        HandshakeStage.DomainErected => "the Erect Domain Request",
        HandshakeStage.UserAttached => "the Attach User Confirm",
        HandshakeStage.ChannelJoined => "the channel joins; it never sent the Demand Active PDU",
        HandshakeStage.CapabilityExchanged => "the capability sets it demanded",
        HandshakeStage.ActiveConfirmed => "the Confirm Active PDU",
        _ => stage.ToString(),
    };

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