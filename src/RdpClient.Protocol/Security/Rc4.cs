namespace RdpClient.Protocol.Security;

/// <summary>
/// RC4, as NTLM uses it.
/// </summary>
/// <remarks>
/// MS-NLMP 3.4.4 defines the confidentiality service in terms of RC4 keyed
/// directly with the session key. That is a plain RC4 key schedule with no
/// key derivation and no discarded bytes, which is why this is written out
/// rather than delegated: the platform's RC4 is gone from .NET, and reusing a
/// TLS cipher here would produce a different stream entirely.
/// </remarks>
public static class Rc4
{
    /// <summary>
    /// Encrypt or decrypt <paramref name="data"/>.
    /// </summary>
    /// <remarks>
    /// RC4 is its own inverse, so the same call both seals and opens a message.
    /// </remarks>
    /// <param name="key">The RC4 key. May be any non-empty length.</param>
    /// <param name="data">The bytes to transform.</param>
    public static byte[] Transform(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        if (key.IsEmpty)
        {
            throw new ArgumentException("RC4 requires a non-empty key", nameof(key));
        }

        byte[] state = new byte[256];
        for (int i = 0; i < 256; i++)
        {
            state[i] = (byte)i;
        }

        // Key scheduling: swap state[i] with state[j] while j accumulates
        // key[i mod keylen].
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + state[i] + key[i % key.Length]) & 0xFF;
            (state[i], state[j]) = (state[j], state[i]);
        }

        var output = new byte[data.Length];
        int x = 0;
        int y = 0;
        for (int n = 0; n < data.Length; n++)
        {
            x = (x + 1) & 0xFF;
            y = (y + state[x]) & 0xFF;
            (state[x], state[y]) = (state[y], state[x]);
            output[n] = (byte)(data[n] ^ state[(state[x] + state[y]) & 0xFF]);
        }

        return output;
    }
}