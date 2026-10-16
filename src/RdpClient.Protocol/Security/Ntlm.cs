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
    /// <para>
    /// <see cref="NtlmFlags.NegotiateKeyExchange"/> asks the server not to send
    /// an exported session key.
    /// </para>
    /// <para>
    /// Two flags are deliberately absent. <c>NEGOTIATE_TARGET_INFO</c> announces
    /// that a message <em>carries</em> TargetInfo and is a server-side bit; a
    /// client that sets it in NEGOTIATE is rejected. <c>NEGOTIATE_VERSION</c> is
    /// included, which makes the 8-octet Version field mandatory at offset 32,
    /// so it must carry a real version rather than zeroes.
    /// </para>
    /// </remarks>
    public const NtlmFlags ClientFlags =
        NtlmFlags.NegotiateUnicode |
        NtlmFlags.NegotiateOem |
        NtlmFlags.RequestTarget |
        NtlmFlags.NegotiateNtlm |
        NtlmFlags.AlwaysSign |
        NtlmFlags.NegotiateSign |
        NtlmFlags.NegotiateSeal |
        NtlmFlags.NegotiateExtendedSessionSecurity |
        NtlmFlags.NegotiateVersion |
        NtlmFlags.Negotiate128 |
        NtlmFlags.Negotiate56 |
        NtlmFlags.NegotiateKeyExchange;

    /// <summary>Version written when <see cref="NtlmFlags.NegotiateVersion"/> is set.</summary>
    private static ReadOnlySpan<byte> ClientVersion => [0x0A, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0F];

    /// <summary>The NT hash of a password: MD4 over UTF-16LE (MS-NLMP 3.1.4.2).</summary>
    public static byte[] NtHash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);

        using var md4 = new Md4();
        md4.Update(Encoding.Unicode.GetBytes(password));
        return md4.Finish();
    }

    /// <summary>Build an NTLM NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1).</summary>
    public static byte[] BuildNegotiateMessage(string? workstation = null, NtlmFlags? flags = null)
    {
        // MS-NLMP 2.2.1.1 fixes the header at 32 bytes and, when
        // NEGOTIATE_VERSION is set, an 8-octet Version, so the payload starts at
        // offset 40.
        const int PayloadOffset = 40;

        byte[] workstationBytes = string.IsNullOrEmpty(workstation)
            ? []
            : Encoding.Unicode.GetBytes(workstation);

        NtlmFlags effective = flags ?? ClientFlags;
        if (workstationBytes.Length > 0)
        {
            // The flag may only be set when the name is actually present in the
            // payload; announcing it without the payload is what the server
            // reads as a malformed NEGOTIATE.
            effective |= NtlmFlags.NegotiateOemWorkstationSupplied;
        }

        var message = new byte[PayloadOffset + workstationBytes.Length];
        Signature.CopyTo(message);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(8), NtlmMessageType.Negotiate);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(12), (uint)effective);

        // Domain and workstation are { Length(2), MaxLen(2), BufferOffset(2) }
        // starting at offset 16 and 24, so the BufferOffset members sit at 20
        // and 28. The domain is always empty; the workstation follows it.
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(16), 0);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(18), 0);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(20), PayloadOffset);

        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(24), (ushort)workstationBytes.Length);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(26), (ushort)workstationBytes.Length);
        BinaryPrimitivesCompat.WriteUInt16LittleEndian(message.AsSpan(28), PayloadOffset);

        ClientVersion.CopyTo(message.AsSpan(32));
        workstationBytes.CopyTo(message.AsSpan(PayloadOffset));
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
        byte[] keyBytes = encryptedRandomSessionKey.ToArray();

        const int HeaderLength = 88;

        // The payload order is fixed by the spec: NT response, domain, user,
        // workstation, encrypted random session key. Every field descriptor in
        // the header carries a BufferOffset into this block, so the offsets are
        // computed once here rather than guessed.
        int ntOffset = HeaderLength;
        int domainOffset = ntOffset + ntResponse.Length;
        int userOffset = domainOffset + domainBytes.Length;
        int workstationOffset = userOffset + userBytes.Length;
        int keyOffset = workstationOffset + workstationBytes.Length;
        int total = keyOffset + keyBytes.Length;

        var message = new byte[total];
        Signature.CopyTo(message);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(8), NtlmMessageType.Authenticate);

        // LM response stays empty: NTLMv2 has no LM response.
        WriteField(message.AsSpan(12), 0, 0, 0);
        WriteField(message.AsSpan(20), (ushort)ntResponse.Length, (ushort)ntResponse.Length, (ushort)ntOffset);
        WriteField(message.AsSpan(28), (ushort)domainBytes.Length, (ushort)domainBytes.Length, (ushort)domainOffset);
        WriteField(message.AsSpan(36), (ushort)userBytes.Length, (ushort)userBytes.Length, (ushort)userOffset);
        WriteField(message.AsSpan(44), (ushort)workstationBytes.Length, (ushort)workstationBytes.Length, (ushort)workstationOffset);
        WriteField(message.AsSpan(52), (ushort)keyBytes.Length, (ushort)keyBytes.Length, (ushort)keyOffset);
        BinaryPrimitivesCompat.WriteUInt32LittleEndian(message.AsSpan(60), (uint)flags);

        // MIC (offset 72, 16 bytes) is only present when the server offered
        // NegotiateKeyExchange; leaving it zeroed is the accepted encoding.
        message.AsSpan(72, 16).Clear();

        ntResponse.CopyTo(message.AsSpan(ntOffset));
        domainBytes.CopyTo(message.AsSpan(domainOffset));
        userBytes.CopyTo(message.AsSpan(userOffset));
        workstationBytes.CopyTo(message.AsSpan(workstationOffset));
        keyBytes.CopyTo(message.AsSpan(keyOffset));
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

        (ushort targetLen, uint targetOffset) = ReadField(message.AsSpan(12));
        (ushort infoLen, uint infoOffset) = ReadField(message.AsSpan(40));

        return new Challenge(
            serverChallenge,
            flags,
            Slice(message, targetOffset, targetLen),
            Slice(message, infoOffset, infoLen));
    }

    private static byte[] Slice(byte[] message, uint offset, int length) =>
        offset + (uint)length <= message.Length ? message.AsSpan((int)offset, length).ToArray() : [];

    /// <summary>Read a <c>{ Len, MaxLen, Offset }</c> field descriptor.</summary>
    /// <remarks>
    /// The descriptor is Length(2), MaxLen(2), BufferOffset(4) - a 32-bit
    /// offset. Reading Length from <c>[4..6]</c> and Offset from <c>[6..8]</c>
    /// instead returns the two halves of the offset, which for a CHALLENGE
    /// yields the offset as the length and zero as the offset. That silently
    /// hands the caller the front of the message rather than the AV_PAIR blob,
    /// and the resulting AUTHENTICATE embeds an entire NTLM header.
    /// </remarks>
    private static (ushort Length, uint Offset) ReadField(ReadOnlySpan<byte> field) =>
        (BinaryPrimitivesCompat.ReadUInt16LittleEndian(field[..2]),
         BinaryPrimitivesCompat.ReadUInt32LittleEndian(field[4..]));

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

    /// <summary>
    /// Name an NTLM message for logging, given its message type.
    /// </summary>
    /// <remarks>
    /// A token too short to hold the 32-bit type at offset 8 is reported as
    /// such rather than throwing: this is a diagnostic, and a malformed token is
    /// exactly the case where the caller wants a name rather than an exception.
    /// </remarks>
    public static string DescribeType(byte[] message)
    {
        ArgumentNullException.ThrowIfNull(message);

        if (message.Length < 12 || !message.AsSpan(0, 8).SequenceEqual(Signature))
        {
            return "not an NTLM message";
        }

        uint type = BitConverter.ToUInt32(message, 8);
        return type switch
        {
            NtlmMessageType.Negotiate => "NEGOTIATE",
            NtlmMessageType.Challenge => "CHALLENGE",
            NtlmMessageType.Authenticate => "AUTHENTICATE",
            _ => $"type {type}",
        };
    }
}