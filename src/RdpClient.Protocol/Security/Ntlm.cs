using System.Security.Cryptography;
using System.Text;

namespace RdpClient.Protocol.Security;

/// <summary>NTLM negotiate flags (MS-NLMP 2.2.2.5).</summary>
[Flags]
public enum NtlmFlags : uint
{
    None = 0x00000000,
    NegotiateUnicode = 0x00000001,
    NegotiateOem = 0x00000002,
    RequestTarget = 0x00000004,
    NegotiateSign = 0x00000010,
    NegotiateSeal = 0x00000020,
    NegotiateDatagram = 0x00000040,
    NegotiateLdapKey = 0x00000080,
    NegotiateNtlm = 0x00000200,
    NegotiateAnonymous = 0x00000800,
    NegotiateOemDomainSupplied = 0x00001000,
    NegotiateOemWorkstationSupplied = 0x00002000,
    AlwaysSign = 0x00008000,
    TargetTypeDomain = 0x00010000,
    TargetTypeServer = 0x00020000,
    TargetTypeShare = 0x00040000,
    NegotiateExtendedSessionSecurity = 0x00080000,
    NegotiateIdentify = 0x00100000,
    RequestNonNTSessionKey = 0x00400000,
    NegotiateTargetInfo = 0x00800000,
    NegotiateVersion = 0x02000000,
    Negotiate128 = 0x20000000,
    NegotiateKeyExchange = 0x40000000,
    Negotiate56 = 0x80000000,
}

/// <summary>Messages exchanged in an NTLM authentication exchange (MS-NLMP 2.2).</summary>
public static class NtlmMessageType
{
    public const uint Negotiate = 1;
    public const uint Challenge = 2;
    public const uint Authenticate = 3;
}

/// <summary>NTLM payload AV_PAIR identifiers (MS-NLMP 2.2.2.1).</summary>
public enum NtlmAvPair : ushort
{
    Eol = 0x0000,
    NbComputerName = 0x0001,
    NbDomainName = 0x0002,
    DnsComputerName = 0x0003,
    DnsDomainName = 0x0004,
    DnsTreeName = 0x0005,
    Flags = 0x0006,
    Timestamp = 0x0007,
    SingleHost = 0x0008,
    TargetName = 0x0009,
    ChannelBindings = 0x000A,
}

/// <summary>
/// NTLM message construction and parsing.
/// </summary>
/// <remarks>
/// Only NTLMv2 is produced. MS-NLMP 2.2.2.4 deprecates NTLMv1 and current
/// Windows hosts refuse it unless
/// <see cref="NtlmFlags.NegotiateExtendedSessionSecurity"/> is absent, so a v1
/// response would be rejected in practice.
/// </remarks>
public static class Ntlm
{
    internal static ReadOnlySpan<byte> Signature => "NTLMSSP\0"u8;

    /// <summary>
    /// Flags a Windows client offers.
    /// </summary>
    /// <remarks>
    /// <see cref="NtlmFlags.NegotiateKeyExchange"/> asks the server not to send
    /// an exported session key, which is what modern RDP expects.
    /// </remarks>
    public const NtlmFlags ClientFlags =
        NtlmFlags.NegotiateUnicode |
        NtlmFlags.NegotiateOem |
        NtlmFlags.RequestTarget |
        NtlmFlags.NegotiateNtlm |
        NtlmFlags.NegotiateExtendedSessionSecurity |
        NtlmFlags.NegotiateTargetInfo |
        NtlmFlags.NegotiateVersion |
        NtlmFlags.Negotiate128 |
        NtlmFlags.Negotiate56 |
        NtlmFlags.NegotiateKeyExchange;

    /// <summary>The NT hash of a password: MD4 over UTF-16LE (MS-NLMP 3.1.4.2).</summary>
    public static byte[] NtHash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        using var md4 = new Md4();
        md4.Update(Encoding.Unicode.GetBytes(password));
        return md4.Finish();
    }

    /// <summary>Build an NTLM NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1).</summary>
    public static byte[] BuildNegotiateMessage(NtlmFlags? flags = null)
    {
        var message = new byte[40];
        Signature.CopyTo(message);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(8), NtlmMessageType.Negotiate);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(12), (uint)(flags ?? ClientFlags));

        // Domain and workstation are empty length-prefixed fields.
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(18), 40); // buffer offset
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(26), 40); // workstation offset
        return message;
    }

    /// <summary>Build an NTLM AUTHENTICATE_MESSAGE (MS-NLMP 2.2.1.3).</summary>
    /// <param name="userName">Account name, UTF-16 encoded into the payload.</param>
    /// <param name="domain">Account domain, UTF-16 encoded into the payload.</param>
    /// <param name="workstation">Client workstation name.</param>
    /// <param name="ntResponse">The full NTLMv2 challenge response.</param>
    /// <param name="flags">Flags echoed from the server's challenge.</param>
    /// <param name="serverChallenge">The server's 8-byte challenge.</param>
    /// <param name="encryptedRandomSessionKey">Key wrapped with the server key, or empty.</param>
    public static byte[] BuildAuthenticateMessage(
        string userName,
        string domain,
        string workstation,
        byte[] ntResponse,
        NtlmFlags flags,
        ReadOnlySpan<byte> serverChallenge,
        ReadOnlySpan<byte> encryptedRandomSessionKey = default)
    {
        byte[] userBytes = Encoding.Unicode.GetBytes(userName);
        byte[] domainBytes = Encoding.Unicode.GetBytes(domain);
        byte[] workstationBytes = Encoding.Unicode.GetBytes(workstation);

        const int HeaderLength = 88;
        var payload = new List<byte>(userBytes.Length + domainBytes.Length
            + workstationBytes.Length + ntResponse.Length + encryptedRandomSessionKey.Length);
        payload.AddRange(ntResponse);

        int offset = HeaderLength;

        offset = Append(payload, domainBytes, offset);
        offset = Append(payload, userBytes, offset);
        offset = Append(payload, workstationBytes, offset);
        offset = Append(payload, encryptedRandomSessionKey.ToArray(), offset);

        var message = new byte[HeaderLength + payload.Count];
        Signature.CopyTo(message);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(8), NtlmMessageType.Authenticate);

        // LM response is always empty: NTLMv2 has no LM response.
        WriteField(message.AsSpan(12), 0, 0, 0);
        WriteField(message.AsSpan(20), (ushort)ntResponse.Length, (ushort)ntResponse.Length, (ushort)HeaderLength);
        WriteField(message.AsSpan(28), (ushort)domainBytes.Length, (ushort)domainBytes.Length, (ushort)offset);

        offset = HeaderLength + ntResponse.Length;
        offset = domainBytes.Length + offset;

        WriteField(message.AsSpan(36), (ushort)userBytes.Length, (ushort)userBytes.Length, (ushort)offset);
        WriteField(message.AsSpan(44), (ushort)workstationBytes.Length, (ushort)workstationBytes.Length, (ushort)offset);
        WriteField(message.AsSpan(52), (ushort)encryptedRandomSessionKey.Length, (ushort)encryptedRandomSessionKey.Length, (ushort)offset);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(60), (uint)flags);
        message.AsSpan(72, 16).Clear();   // MIC: not computed

        payload.CopyTo(message.AsSpan(HeaderLength));

        // The offsets above were advanced optimistically; recompute them from
        // the real payload layout so the server can locate each field.
        int domainOffset = HeaderLength;
        int userOffset = domainOffset + domainBytes.Length;
        int workstationOffset = userOffset + userBytes.Length;
        int keyOffset = workstationOffset + workstationBytes.Length;

        WriteField(message.AsSpan(28), (ushort)domainBytes.Length, (ushort)domainBytes.Length, (ushort)domainOffset);
        WriteField(message.AsSpan(36), (ushort)userBytes.Length, (ushort)userBytes.Length, (ushort)userOffset);
        WriteField(message.AsSpan(44), (ushort)workstationBytes.Length, (ushort)workstationBytes.Length, (ushort)workstationOffset);
        WriteField(message.AsSpan(52), (ushort)encryptedRandomSessionKey.Length, (ushort)encryptedRandomSessionKey.Length, (ushort)keyOffset);

        return message;
    }

    public sealed record Challenge(
        ReadOnlyMemory<byte> ServerChallenge,
        NtlmFlags Flags,
        ReadOnlyMemory<byte> TargetName,
        ReadOnlyMemory<byte> TargetInfo);

    /// <summary>Parse an NTLM CHALLENGE_MESSAGE (MS-NLMP 2.2.1.2).</summary>
    public static Challenge ParseChallengeMessage(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (message.Length < 48)
        {
            throw new InvalidDataException($"NTLM challenge too short: {message.Length} bytes");
        }

        if (!message.AsSpan(0, 8).SequenceEqual(Signature))
        {
            throw new InvalidDataException("message does not start with the NTLMSSP signature");
        }

        uint type = BinaryPrimitivesCompat.ReadUInt32LittleEndian(message.AsSpan(8));
        if (type != NtlmMessageType.Challenge)
        {
            throw new InvalidDataException($"expected an NTLM challenge, got message type {type}");
        }

        var flags = (NtlmFlags)BinaryPrimitivesCompat.ReadUInt32LittleEndian(message.AsSpan(20));
        byte[] serverChallenge = message.AsSpan(24, 8).ToArray();

        (ushort targetLen, ushort targetOffset) = ReadField(message.AsSpan(12));
        (ushort infoLen, ushort infoOffset) = ReadField(message.AsSpan(40));

        return new Challenge(
            serverChallenge,
            flags,
            Slice(message, targetOffset, targetLen),
            Slice(message, infoOffset, infoLen));
    }

    private static byte[] Slice(byte[] message, ushort offset, ushort length) =>
        offset + length <= message.Length ? message.AsSpan(offset, length).ToArray() : [];

    private static (ushort Length, ushort Offset) ReadField(ReadOnlySpan<byte> field) =>
        (BinaryPrimitivesCompat.ReadUInt16LittleEndian(field[4..]),
         BinaryPrimitivesCompat.ReadUInt16LittleEndian(field[6..]));

    private static void WriteField(Span<byte> destination, ushort maxLength, ushort length, ushort offset)
    {
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(destination, maxLength);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(destination[2..], length);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(destination[4..], offset);
    }

    private static int Append(List<byte> payload, byte[] field, int offset)
    {
        payload.AddRange(field);
        return offset + field.Length;
    }

    /// <summary>
    /// Compute the NTLMv2 challenge response (MS-NLMP 3.3.2).
    /// </summary>
    /// <param name="ntHash">The NT hash of the account password.</param>
    /// <param name="userName">Account name; uppercased into the key derivation.</param>
    /// <param name="domain">Account domain; matches the server's target name.</param>
    /// <param name="serverChallenge">The server's 8-byte challenge.</param>
    /// <param name="targetInfo">TargetInfo AV_PAIR blob from the challenge.</param>
    /// <param name="clientChallenge">8 bytes of client entropy.</param>
    public static byte[] ComputeNtlmV2Response(
        byte[] ntHash,
        string userName,
        string domain,
        ReadOnlySpan<byte> serverChallenge,
        ReadOnlySpan<byte> targetInfo,
        ReadOnlySpan<byte> clientChallenge)
    {
        ArgumentNullException.ThrowIfNull(ntHash);
        ArgumentNullException.ThrowIfNull(userName);
        ArgumentNullException.ThrowIfNull(domain);

        if (serverChallenge.Length != 8)
        {
            throw new ArgumentException("the server challenge must be 8 bytes", nameof(serverChallenge));
        }

        if (clientChallenge.Length < 8)
        {
            throw new ArgumentException("the client challenge must be at least 8 bytes", nameof(clientChallenge));
        }

        // NTOWFv2 = HMAC-MD5(NT hash, UTF-16LE(Uppercase(user) + domain))
        byte[] identity = Encoding.Unicode.GetBytes(userName.ToUpperInvariant() + domain);
        byte[] ntowfv2 = HMACMD5.HashData(ntHash, identity);

        var temp = new List<byte>(64 + targetInfo.Length)
        {
            0x01,                          // Responserversion
            0x01,                          // HiResponserversion
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Z(6)
        };
        temp.AddRange(BitConverter.GetBytes(DateTime.UtcNow.Ticks)); // FILETIME, 8 bytes
        temp.AddRange(clientChallenge[..8]);
        temp.AddRange([0x00, 0x00, 0x00, 0x00]);                       // Z(4)
        temp.AddRange(targetInfo);
        temp.AddRange([0x00, 0x00, 0x00, 0x00]);                       // Z(4)

        // NTProofStr = HMAC-MD5(NTOWFv2, server challenge || temp)
        var proofInput = new byte[serverChallenge.Length + temp.Count];
        serverChallenge.CopyTo(proofInput);
        temp.CopyTo(proofInput.AsSpan(serverChallenge.Length));
        byte[] proof = HMACMD5.HashData(ntowfv2, proofInput);

        var response = new byte[proof.Length + temp.Count];
        proof.CopyTo(response, 0);
        temp.CopyTo(response, proof.Length);
        return response;
    }

    /// <summary>Build a minimal TargetInfo blob when the server sent none.</summary>
    public static byte[] BuildMinimalTargetInfo(string domain)
    {
        var pairs = new List<byte>();
        if (!string.IsNullOrEmpty(domain))
        {
            pairs.AddRange([0x02, 0x00]);                                     // NbDomainName
            pairs.AddRange(BitConverter.GetBytes((ushort)domain.Length));
            pairs.AddRange(BitConverter.GetBytes((ushort)(6 + domain.Length * 2)));
            pairs.AddRange(Encoding.Unicode.GetBytes(domain));
        }

        pairs.AddRange([0x00, 0x00]);                                         // MsvAvEOL
        return [.. pairs];
    }
}