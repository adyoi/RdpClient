using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace RdpClient.Protocol;

/// <summary>Runs the TLS handshake that carries an RDP External Security Protocol.</summary>
/// <remarks>
/// MS-RDPEA 3.1.5.1 places the TLS handshake on the same TCP connection, before
/// any SPNEGO token. The server's certificate is normally self-signed and issued
/// for <c>TERMSRV/&lt;host&gt;</c>, so chain validation always fails and the
/// default callback would reject every real host. The certificate is therefore
/// accepted unconditionally, and what was accepted is reported so the caller can
/// record it.
/// </remarks>
public sealed class TlsChannel
{
    private readonly SslStream _stream;

    private TlsChannel(SslStream stream, X509Certificate2? serverCertificate, string protocol)
    {
        _stream = stream;
        ServerCertificate = serverCertificate;
        NegotiatedProtocol = protocol;
    }

    /// <summary>The certificate the server presented, if any.</summary>
    public X509Certificate2? ServerCertificate { get; }

    /// <summary>The negotiated TLS protocol version, e.g. <c>Tls13</c>.</summary>
    public string NegotiatedProtocol { get; }

    /// <summary>Stream to send RDP PDUs over once the handshake has completed.</summary>
    public Stream Stream => _stream;

    /// <summary>
    /// Complete the TLS handshake over <paramref name="inner"/>.
    /// </summary>
    /// <param name="inner">The TCP stream carrying the RDP connection so far.</param>
    /// <param name="targetHost">
    /// The name to present in SNI. RDP expects <c>TERMSRV/&lt;host&gt;</c>.
    /// </param>
    /// <param name="tlsPolicy">
    /// Requested protocol versions. Defaults to TLS 1.2 or better, which is what
    /// current RDP hosts negotiate.
    /// </param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    public static async Task<TlsChannel> HandshakeAsync(
        Stream inner,
        string targetHost,
        SslProtocols tlsPolicy = SslProtocols.Tls12 | SslProtocols.Tls13,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetHost);

        var remoteCertificate = new List<X509Certificate2>();

        // leaveInnerStreamOpen: the TcpClient owns the socket and disposes it.
        var tls = new SslStream(inner, leaveInnerStreamOpen: false, (_, certificate, _, errors) =>
        {
            // A self-signed RDP certificate always trips this. Record it for the
            // caller's diagnostics instead of discarding the detail.
            if (certificate is not null)
            {
                remoteCertificate.Add(new X509Certificate2(certificate));
            }

            return true;
        });

        try
        {
            await tls.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions
                {
                    TargetHost = targetHost,
                    EnabledSslProtocols = tlsPolicy,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        X509Certificate2? presented = remoteCertificate.Count > 0 ? remoteCertificate[0] : null;
        return new TlsChannel(tls, presented, tls.SslProtocol.ToString());
    }

    /// <summary>A one-line description of the peer certificate, for the handshake log.</summary>
    public string DescribeCertificate()
    {
        if (ServerCertificate is null)
        {
            return "server presented no certificate";
        }

        string subject = ServerCertificate.Subject;
        string issuer = ServerCertificate.Issuer;
        return $"{NegotiatedProtocol}, subject '{subject}' issued by '{issuer}' "
               + $"(self-signed certificate accepted; RDP does not chain-validate)";
    }

    public ValueTask DisposeAsync() => _stream.DisposeAsync();
}