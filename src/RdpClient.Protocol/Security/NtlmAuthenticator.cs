using System.Security.Cryptography;

namespace RdpClient.Protocol.Security;

/// <summary>
/// Runs the NTLM authentication exchange that CredSSP requires.
/// </summary>
/// <remarks>
/// <para>
/// MS-NLMP 3.1.5.1 defines a three-message exchange. MS-CSSP 2.2.1 wraps each
/// message in a <c>TSRequest</c>: the server reads the first bytes after the TLS
/// handshake as ASN.1, so sending the NTLM message bare makes it reset the
/// connection without a diagnostic.
/// </para>
/// <para>
/// CredSSP performs its own mechanism negotiation, so the NTLM message travels
/// unwrapped in <c>negoToken</c>. A SPNEGO layer here is rejected.
/// </para>
/// </remarks>
public sealed class NtlmAuthenticator
{
    private const int MaxTokenBytes = 64 * 1024;

    private readonly string _userName;
    private readonly string _domain;
    private readonly string _password;
    private readonly string _workstation;
    private readonly Action<string>? _trace;

    public NtlmAuthenticator(
        string userName,
        string domain,
        string password,
        string workstation = "RDPCLIENT",
        Action<string>? trace = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentNullException.ThrowIfNull(password);

        _userName = userName;
        // RDP frequently presents a bare user name; an empty domain is legal.
        _domain = domain ?? string.Empty;
        _password = password;
        _workstation = workstation;
        _trace = trace;
    }

    public string AuthenticatedUser => _userName;

    public string AuthenticatedDomain => _domain;

    /// <summary>
    /// Perform the exchange over an already-established secure channel.
    /// </summary>
    /// <param name="channel">The TLS stream to exchange tokens over.</param>
    /// <param name="cancellationToken">Cancels the exchange.</param>
    public async Task AuthenticateAsync(Stream channel, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(channel);

        // 1. NEGOTIATE, inside a TSRequest.
        // CredSSP performs its own mechanism negotiation, so the NTLM message
        // travels bare in negoToken. SPNEGO is only added for Kerberos; the
        // reference implementation uses NTLM directly here.
        byte[] negotiate = Ntlm.BuildNegotiateMessage(_workstation);
        await WriteRequestAsync(channel, [negotiate], cancellationToken).ConfigureAwait(false);

        // 2. The server answers with a TSRequest carrying the CHALLENGE.
        _trace?.Invoke("<- awaiting TSRequest");
        CredSsp.Request challengeReply = await ReadRequestAsync(channel, cancellationToken)
            .ConfigureAwait(false);
        _trace?.Invoke($"server sent TSRequest: {CredSsp.Describe(challengeReply)}");
        CredSsp.TryThrowServerError(challengeReply);

        byte[] challengeToken = SingleNegoToken(challengeReply, "NTLM challenge");
        _trace?.Invoke($"<- {Ntlm.DescribeType(challengeToken)} ({challengeToken.Length} bytes)");
        _trace?.Invoke($"   {Convert.ToHexString(challengeToken).ToLowerInvariant()}");
        var challenge = Ntlm.ParseChallengeMessage(challengeToken);

        // 3. Compute NTLMv2 and send the AUTHENTICATE message.
        byte[] ntHash = Ntlm.NtHash(_password);
        byte[] clientChallenge = RandomNumberGenerator.GetBytes(8);

        // The challenge's TargetInfo carries the server's time and channel
        // bindings. An absent blob means we must synthesise one, otherwise the
        // response will not match what the server computed.
        byte[] targetInfo = challenge.TargetInfo.Length > 0
            ? challenge.TargetInfo.ToArray()
            : Ntlm.BuildMinimalTargetInfo(_domain);

        byte[] ntlmResponse = Ntlm.ComputeNtlmV2Response(
            ntHash, _userName, _domain, challenge.ServerChallenge.Span, targetInfo, clientChallenge);

        byte[] authenticate = Ntlm.BuildAuthenticateMessage(
            _userName,
            _domain,
            _workstation,
            ntlmResponse,
            challenge.Flags & NtlmFlags.NegotiateUnicode,
            challenge.ServerChallenge.Span);

        await WriteRequestAsync(channel, [authenticate], cancellationToken).ConfigureAwait(false);

        // 4. Final request: success, or the NTSTATUS the server reports.
        CredSsp.Request result = await ReadRequestAsync(channel, cancellationToken).ConfigureAwait(false);
        CredSsp.TryThrowServerError(result);

        // A server that authenticates us answers with a bare acknowledgement, so
        // an absent errorCode is the success signal.
    }

    /// <summary>
    /// Send one <c>TSRequest</c>.
    /// </summary>
    /// <remarks>
    /// The DER length prefix delimits the structure, so the request goes out as
    /// a single write and no framing of our own is added.
    /// </remarks>
    private async Task WriteRequestAsync(
        Stream channel,
        IReadOnlyList<byte[]> negoTokens,
        CancellationToken cancellationToken)
    {
        byte[] request = CredSsp.BuildRequest(negoTokens);
        string kinds = string.Join(", ", negoTokens.Select(Ntlm.DescribeType));
        _trace?.Invoke($"-> TSRequest {request.Length} bytes: {kinds}");
        _trace?.Invoke($"   {Convert.ToHexString(request).ToLowerInvariant()}");
        await channel.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await channel.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static byte[] SingleNegoToken(CredSsp.Request request, string what)
    {
        if (request.NegoTokens.Count == 0)
        {
            throw new NtlmAuthenticationException($"the server sent no {what}");
        }

        byte[] token = request.NegoTokens[0];
        string kind = Ntlm.DescribeType(token);
        if (!kind.StartsWith("CHALLENGE", StringComparison.Ordinal))
        {
            throw new NtlmAuthenticationException(
                $"expected an NTLM CHALLENGE but the server sent {kind}");
        }

        return token;
    }

    /// <summary>
    /// Read exactly one <c>TSRequest</c> from the channel.
    /// </summary>
    /// <remarks>
    /// Messages arrive as a contiguous DER blob rather than a length-prefixed
    /// frame, so the outer SEQUENCE header supplies the length. The header is
    /// kept and passed to the parser, which expects the full encoding.
    /// </remarks>
    private static async Task<CredSsp.Request> ReadRequestAsync(
        Stream channel,
        CancellationToken cancellationToken)
    {
        byte[] prefix = await ReadExactAsync(channel, 2, cancellationToken).ConfigureAwait(false);
        if (prefix[0] != 0x30)
        {
            throw new NtlmAuthenticationException(
                $"expected a CredSSP TSRequest SEQUENCE, got tag 0x{prefix[0]:x2}");
        }

        int headerLength;
        int contentLength;
        byte[] lengthOctets;

        if ((prefix[1] & 0x80) == 0)
        {
            headerLength = 2;
            contentLength = prefix[1];
            lengthOctets = [];
        }
        else
        {
            int count = prefix[1] & 0x7F;
            if (count is 0 or > 3)
            {
                throw new NtlmAuthenticationException(
                    $"unsupported CredSSP length form 0x{prefix[1]:x2}");
            }

            lengthOctets = await ReadExactAsync(channel, count, cancellationToken).ConfigureAwait(false);
            headerLength = 2 + count;

            contentLength = 0;
            foreach (byte b in lengthOctets)
            {
                contentLength = (contentLength << 8) | b;
            }
        }

        if (contentLength < 0 || (long)headerLength + contentLength > MaxTokenBytes)
        {
            throw new NtlmAuthenticationException(
                $"CredSSP request declares an implausible length of {contentLength} bytes");
        }

        byte[] content = await ReadExactAsync(channel, contentLength, cancellationToken)
            .ConfigureAwait(false);

        var der = new byte[headerLength + contentLength];
        prefix.CopyTo(der, 0);
        lengthOctets.CopyTo(der, 2);
        content.CopyTo(der.AsSpan(headerLength));

        return CredSsp.ParseRequest(der);
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read, count - read), cancellationToken)
                .ConfigureAwait(false);
            if (n == 0)
            {
                throw new EndOfStreamException(
                    $"connection closed after {read} of {count} expected bytes during authentication");
            }

            read += n;
        }

        return buffer;
    }
}

public sealed class NtlmAuthenticationException : Exception
{
    public NtlmAuthenticationException(string message) : base(message) { }
}