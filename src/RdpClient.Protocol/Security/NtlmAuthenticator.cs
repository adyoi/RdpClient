using System.Security.Cryptography;

namespace RdpClient.Protocol.Security;

/// <summary>
/// Runs the NTLM authentication exchange that CredSSP requires.
/// </summary>
/// <remarks>
/// MS-NLMP 3.1.5.1 defines a three-message exchange. Each message is carried in
/// a SPNEGO token over the TLS channel that <see cref="TlsChannel"/> has already
/// established, so this type deals only in tokens and never touches the socket
/// framing itself.
/// </remarks>
public sealed class NtlmAuthenticator
{
    private const int MaxTokenBytes = 64 * 1024;

    private readonly string _userName;
    private readonly string _domain;
    private readonly string _password;
    private readonly string _workstation;

    public NtlmAuthenticator(string userName, string domain, string password, string workstation = "RDPCLIENT")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentNullException.ThrowIfNull(password);

        _userName = userName;
        // RDP frequently presents a bare user name; an empty domain is legal.
        _domain = domain ?? string.Empty;
        _password = password;
        _workstation = workstation;
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

        // 1. NEGOTIATE wrapped in SPNEGO.
        byte[] negotiate = Ntlm.BuildNegotiateMessage();
        await WriteTokenAsync(channel, Spnego.BuildNegotiateToken(negotiate), cancellationToken)
            .ConfigureAwait(false);

        // 2. The server answers with a CHALLENGE inside the response token.
        byte[] challengeToken = await ReadTokenAsync(channel, cancellationToken).ConfigureAwait(false);
        var first = Spnego.ParseServerToken(challengeToken);

        if (first.NegResult is not (0 or 1))
        {
            throw new NtlmAuthenticationException(
                $"server rejected the authentication mechanism (negResult {first.NegResult})");
        }

        if (first.ResponseToken is not null && Spnego.TryReadError(first.ResponseToken, out string? error))
        {
            throw new NtlmAuthenticationException($"server reported: {error}");
        }

        if (first.ResponseToken is null || first.ResponseToken.Length == 0)
        {
            throw new NtlmAuthenticationException("server sent no NTLM challenge");
        }

        var challenge = Ntlm.ParseChallengeMessage(first.ResponseToken);

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

        await WriteTokenAsync(channel, Spnego.BuildAuthenticateToken(authenticate), cancellationToken)
            .ConfigureAwait(false);

        // 4. Final token: success, or a status the server reports.
        byte[] resultToken = await ReadTokenAsync(channel, cancellationToken).ConfigureAwait(false);
        var result = Spnego.ParseServerToken(resultToken);

        if (result.ResponseToken is not null && Spnego.TryReadError(result.ResponseToken, out string? failure))
        {
            throw new NtlmAuthenticationException($"authentication failed: {failure}");
        }

        // A server that omits negResult has authenticated us; the absence of an
        // error token is the success signal.
        if (result.NegResult is 2 or 3)
        {
            throw new NtlmAuthenticationException(
                $"authentication was not completed (negResult {result.NegResult})");
        }
    }

    private static async Task WriteTokenAsync(Stream channel, byte[] token, CancellationToken cancellationToken)
    {
        // The BER header is already length-delimited, so the token is written as
        // one unit; SslStream preserves message boundaries for our purposes.
        await channel.WriteAsync(token, cancellationToken).ConfigureAwait(false);
        await channel.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Read exactly one BER SEQUENCE from the channel.
    /// </summary>
    /// <remarks>
    /// Tokens arrive as a contiguous DER blob rather than a length-prefixed
    /// frame, so the outer SEQUENCE header supplies the length.
    /// </remarks>
    private static async Task<byte[]> ReadTokenAsync(Stream channel, CancellationToken cancellationToken)
    {
        // Tag and first length octet.
        byte[] prefix = await ReadExactAsync(channel, 2, cancellationToken).ConfigureAwait(false);
        if (prefix[0] != 0x30)
        {
            throw new NtlmAuthenticationException(
                $"expected a SPNEGO SEQUENCE, got tag 0x{prefix[0]:x2}");
        }

        int headerLength;
        int contentLength;

        if ((prefix[1] & 0x80) == 0)
        {
            headerLength = 2;
            contentLength = prefix[1];
        }
        else
        {
            int lengthOctets = prefix[1] & 0x7F;
            if (lengthOctets is 0 or > 3)
            {
                throw new NtlmAuthenticationException(
                    $"unsupported SPNEGO token length form 0x{prefix[1]:x2}");
            }

            headerLength = 2 + lengthOctets;
            byte[] lengthBytes = await ReadExactAsync(channel, lengthOctets, cancellationToken)
                .ConfigureAwait(false);

            contentLength = 0;
            foreach (byte b in lengthBytes)
            {
                contentLength = (contentLength << 8) | b;
            }
        }

        if (contentLength < 0 || headerLength + contentLength > MaxTokenBytes)
        {
            throw new NtlmAuthenticationException(
                $"SPNEGO token declares an implausible length of {contentLength} bytes");
        }

        byte[] content = await ReadExactAsync(channel, contentLength, cancellationToken).ConfigureAwait(false);
        byte[] token = new byte[headerLength + contentLength];
        prefix.CopyTo(token, 0);
        if (headerLength > 2)
        {
            // Re-read is unnecessary: the length octets were consumed above.
        }

        content.CopyTo(token, headerLength);
        return token;
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