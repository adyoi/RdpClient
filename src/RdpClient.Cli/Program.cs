using RdpClient.Protocol;

namespace RdpClient.Cli;

/// <summary>
/// Console harness that exercises the connection sequence without the GUI.
/// </summary>
/// <remarks>
/// Every PDU it emits comes from the same encoders the WinUI app uses, so a
/// successful run here means the wire format is correct. The password is read
/// from <c>RDP_PASSWORD</c> and is never echoed, so credentials do not end up
/// in shell history or console logs.
/// </remarks>
internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        Dictionary<string, string> options = ParseArgs(args);

        if (options.TryGetValue("help", out _))
        {
            PrintUsage();
            return 0;
        }

        if (!options.TryGetValue("host", out string? host) || string.IsNullOrWhiteSpace(host))
        {
            Console.Error.WriteLine("error: --host is required");
            PrintUsage();
            return 2;
        }

        int port = 3389;
        if (options.TryGetValue("port", out string? portText)
            && (!int.TryParse(portText, out port) || port is < 1 or > 65535))
        {
            Console.Error.WriteLine($"error: '{portText}' is not a valid TCP port");
            return 2;
        }

        ClientPdu.UserOptions? user = null;
        string? userName = Get(options, "user");
        if (!string.IsNullOrWhiteSpace(userName))
        {
            user = new ClientPdu.UserOptions
            {
                UserName = userName,
                Domain = Get(options, "domain") ?? string.Empty,
                Password = Environment.GetEnvironmentVariable("RDP_PASSWORD") ?? string.Empty,
            };
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var connectionOptions = new RdpConnectionOptions
        {
            Host = host,
            Port = port,
            User = user,
            UseCorrelationId = !options.ContainsKey("no-correlation"),
            LogTx = options.ContainsKey("hex"),
            SkipChannelJoin = options.ContainsKey("skip-channel-join"),
        };

        if (options.TryGetValue("timeout", out string? seconds)
            && int.TryParse(seconds, out int timeout))
        {
            connectionOptions = connectionOptions with { Timeout = timeout };
        }

        if (options.ContainsKey("tls12"))
        {
            connectionOptions = connectionOptions with
            {
                TlsPolicy = System.Security.Authentication.SslProtocols.Tls12,
            };
        }

        if (options.ContainsKey("credssp-only"))
        {
            connectionOptions = connectionOptions with { Security = SecurityModeSelection.CredSspOnly };
        }

        if (options.ContainsKey("tls-only"))
        {
            connectionOptions = connectionOptions with { Security = SecurityModeSelection.TlsOnly };
        }

        if (options.TryGetValue("graphics", out string? graphicsText)
            && int.TryParse(graphicsText, out int graphics))
        {
            connectionOptions = connectionOptions with { GraphicsPduLimit = graphics };
        }

        if (options.TryGetValue("width", out string? widthText)
            && int.TryParse(widthText, out int width))
        {
            connectionOptions = connectionOptions with { DesktopWidth = width };
        }

        if (options.TryGetValue("height", out string? heightText)
            && int.TryParse(heightText, out int height))
        {
            connectionOptions = connectionOptions with { DesktopHeight = height };
        }

        if (options.TryGetValue("depth", out string? depthText)
            && int.TryParse(depthText, out int depth))
        {
            connectionOptions = connectionOptions with { ColourDepth = depth };
        }

        string? bmpPath = Get(options, "dump-bmp");

        if (options.TryGetValue("dump-graphics", out string? capturePath))
        {
            // Truncated at the start rather than appended to: a second run
            // would otherwise leave two sessions' updates interleaved in one
            // file, which is indistinguishable from a stream that desynced.
            if (File.Exists(capturePath))
            {
                File.Delete(capturePath);
            }

            connectionOptions = connectionOptions with { GraphicsCapturePath = capturePath };
        }

        if (options.ContainsKey("classic-user"))
        {
            // Off by default: the block puts the password on the wire in the
            // clear, and MS-RDPBCGR does not define it.
            connectionOptions = connectionOptions with { SendClassicUserBlock = true };
        }

        await using var connection = new RdpConnection();
        connection.OnEvent += evt =>
        {
            string level = evt.IsError ? "error" : "info";
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff}  {level,-7} {evt.Message}");
        };

        Console.WriteLine($"RdpClient protocol probe -> {host}:{port}");
        Console.WriteLine($"protocol core: {typeof(RdpConnection).Assembly.GetName().Name} "
                          + $"{typeof(RdpConnection).Assembly.GetName().Version}");
        Console.WriteLine();

        HandshakeStage stage = await connection.ConnectAsync(connectionOptions, cts.Token);

        Console.WriteLine();
        if (stage == HandshakeStage.Complete)
        {
            if (connection.Surface is { } surface && bmpPath is not null)
            {
                // Written rather than displayed: the probe has no UI, and a BMP
                // is the one image format that needs no encoder, so what the
                // decoder produced can be looked at directly.
                await File.WriteAllBytesAsync(bmpPath, surface.ToBmp(), cts.Token);
                Console.WriteLine($"wrote a {surface.Width}x{surface.Height} surface to {bmpPath}");
            }

            Console.WriteLine(
                $"RESULT: connection finalised; {connection.GraphicsUpdatesApplied} "
                + "graphics update(s) applied.");
            Console.WriteLine("        Input is not implemented, so the session is "
                              + "not interactive.");
            return 0;
        }

        if (stage == HandshakeStage.Failed)
        {
            Console.WriteLine($"RESULT: failed - {connection.FailureReason}");
            return 1;
        }

        Console.WriteLine($"RESULT: stopped at stage {stage}");
        return 1;
    }

    private static Dictionary<string, string> ParseArgs(string[] args)
    {
        var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            string key = arg[2..];
            int equals = key.IndexOf('=', StringComparison.Ordinal);
            if (equals >= 0)
            {
                parsed[key[..equals]] = key[(equals + 1)..];
            }
            else if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                parsed[key] = args[++i];
            }
            else
            {
                parsed[key] = "true";
            }
        }

        return parsed;
    }

    private static string? Get(Dictionary<string, string> map, string key)
        => map.TryGetValue(key, out string? value) ? value : null;

    private static void PrintUsage()
    {
        Console.WriteLine("""
            rdpprobe - exercise the RdpClient connection sequence from a terminal

            Usage:
              rdpprobe --host <host> [--port <port>] [--user <name>] [--domain <name>]

            Options:
              --host     RDP host to connect to (required)
              --port     TCP port, default 3389
              --user     user name; when set, TS_UD_CS_USER is sent
              --domain   domain for the user name
              --hex      dump transmitted PDUs as hex
              --timeout <seconds>
                         give up on the handshake after this long (default 30)
              --skip-channel-join
                         announce RNS_UD_CS_SUPPORT_SKIP_CHANNELJOIN and
                         send no Channel Join Requests. Unverified against xrdp.
              --graphics <n>
                         after the connection is finalised, read and paint up to
                         <n> graphics update PDUs, then stop
              --width <px> --height <px>
                         desktop size requested in the Bitmap Capability Set,
                         default 1024x768
              --depth <bpp>  colour depth requested, 16 or 32, default 16
              --dump-bmp <path>
                         write the composited desktop to a BMP on completion
              --tls12     restrict TLS to 1.2 instead of 1.2/1.3
              --tls-only  require PROTOCOL_SSL (TLS only, no SPNEGO)
              --credssp-only
                         require CredSSP
              --no-correlation
                         omit the MS-RDPBCGR 2.2.1.1.1 correlation block,
                         sending the minimal 19-byte connection request
              --classic-user
                         send the classic-RDP user block, which carries the
                         password in UTF-16 in the clear. MS-RDPBCGR does not
                         define it and most servers ignore it.
              --help     show this help

            The password is read from the RDP_PASSWORD environment variable and is
            never echoed. Example:

              $env:RDP_PASSWORD = '...'
              rdpprobe --host 192.0.2.10 --user alice --domain CORP
            """);
    }
}