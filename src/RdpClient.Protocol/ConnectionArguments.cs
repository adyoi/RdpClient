namespace RdpClient.Protocol;

/// <summary>
/// Command-line arguments that pre-fill the connection form.
/// </summary>
/// <remarks>
/// The point is to make a run reproducible and scriptable: a test harness should
/// be able to launch the client at a known target and compare two runs, without
/// anyone re-typing a host into the form. Parsing lives here rather than in the
/// UI project so it can be tested, and so the CLI and the app accept the same
/// spelling of the same options.
/// </remarks>
public sealed record ConnectionArguments
{
    /// <summary>Host to pre-fill. Null leaves the field alone.</summary>
    public string? Host { get; init; }

    /// <summary>Port to pre-fill, as text so an invalid value can be reported.</summary>
    public string? Port { get; init; }

    public string? UserName { get; init; }
    public string? Domain { get; init; }

    /// <summary>
    /// Password, or null to leave the field empty.
    /// </summary>
    /// <remarks>
    /// Accepted for symmetry with the other fields, but a command line is
    /// visible to every process on the machine and lands in shell history.
    /// <c>--no-password</c> plus <c>RDP_PASSWORD</c> is the safer pairing, and
    /// the tool's own guidance says the password is never echoed for that reason.
    /// </remarks>
    public string? Password { get; init; }

    /// <summary>Require TLS and refuse CredSSP.</summary>
    public bool TlsOnly { get; init; }

    /// <summary>Require CredSSP.</summary>
    public bool CredSspOnly { get; init; }

    /// <summary>Log every transmitted PDU as hex.</summary>
    public bool LogHex { get; init; }

    /// <summary>Start the handshake as soon as the window appears.</summary>
    public bool ConnectImmediately { get; init; }

    /// <summary>Set when an argument could not be understood; the caller reports it.</summary>
    public string? Error { get; init; }

    /// <summary>True when at least one field would be pre-filled or a mode was requested.</summary>
    public bool HasAnyValue =>
        Host is not null || Port is not null || UserName is not null ||
        Domain is not null || Password is not null ||
        TlsOnly || CredSspOnly || LogHex || ConnectImmediately;

    /// <summary>Options to hand to <see cref="RdpConnection"/>.</summary>
    /// <remarks>
    /// An unparsable or out-of-range port falls back to the default rather than
    /// propagating 0: <see cref="Parse"/> has already recorded the problem in
    /// <see cref="Error"/>, and this conversion still has to yield something the
    /// form can display.
    /// </remarks>
    public RdpConnectionOptions ToConnectionOptions() => new()
    {
        Host = Host ?? string.Empty,
        Port = int.TryParse(Port, out int parsed) && parsed is >= 1 and <= 65535
            ? parsed
            : RdpConnectionOptions.DefaultPort,
        Security = TlsOnly ? SecurityModeSelection.TlsOnly
            : CredSspOnly ? SecurityModeSelection.CredSspOnly
            : SecurityModeSelection.Negotiate,
        LogTx = LogHex,
        User = UserName is null ? null : new ClientPdu.UserOptions
        {
            UserName = UserName,
            Domain = Domain ?? string.Empty,
            Password = Password ?? string.Empty,
        },
    };

    /// <summary>
    /// Parse arguments of the form <c>--name value</c> or <c>--name=value</c>.
    /// </summary>
    /// <remarks>
    /// An unknown name is an error rather than a shrug: a silently ignored
    /// <c>--hos</c> would connect to the wrong host, which is the kind of
    /// mistake a scripted test should never make.
    /// </remarks>
    public static ConnectionArguments Parse(
        IReadOnlyList<string> args,
        string passwordEnvironmentVariable = "RDP_PASSWORD")
    {
        ArgumentNullException.ThrowIfNull(args);

        string? host = null, port = null, user = null, domain = null, password = null;
        bool tlsOnly = false, credSspOnly = false, logHex = false, connectNow = false;
        bool passwordGiven = false, suppressPassword = false;
        string? error = null;

        for (int i = 0; i < args.Count && error is null; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            string name = arg[2..];
            string? inlineValue = null;
            int equals = name.IndexOf('=');
            if (equals >= 0)
            {
                inlineValue = name[(equals + 1)..];
                name = name[..equals];
            }

            // A switch takes no value; anything else consumes the next argument
            // when one was not supplied inline.
            switch (name.ToLowerInvariant())
            {
                case "tls-only":
                    tlsOnly = true;
                    break;
                case "credssp-only":
                    credSspOnly = true;
                    break;
                case "hex":
                    logHex = true;
                    break;
                case "connect":
                case "auto-connect":
                    connectNow = true;
                    break;
                case "no-password":
                    suppressPassword = true;
                    break;

                case "host":
                case "user":
                case "username":
                case "domain":
                case "password":
                case "port":
                {
                    string? value = inlineValue;
                    if (value is null)
                    {
                        if (i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                        {
                            value = args[++i];
                        }
                        else
                        {
                            error = $"--{name} needs a value";
                            break;
                        }
                    }

                    switch (name.ToLowerInvariant())
                    {
                        case "host": host = value; break;
                        case "user":
                        case "username": user = value; break;
                        case "domain": domain = value; break;
                        case "password": password = value; passwordGiven = true; break;
                        case "port": port = value; break;
                    }

                    break;
                }

                default:
                    error = $"unknown argument --{name}";
                    break;
            }
        }

        if (error is null && port is not null
            && (!int.TryParse(port, out int parsed) || parsed is < 1 or > 65535))
        {
            error = $"'{port}' is not a valid TCP port";
        }

        if (error is null && tlsOnly && credSspOnly)
        {
            error = "--tls-only and --credssp-only contradict each other";
        }

        // Precedence: an explicit --password wins, then --no-password suppresses
        // the environment entirely, and only if neither was given is the
        // environment consulted. Keeping the suppression separate from "no
        // password seen" is what makes --no-password mean what it says.
        if (passwordGiven == false && suppressPassword == false)
        {
            password = Environment.GetEnvironmentVariable(passwordEnvironmentVariable);
        }
        else if (suppressPassword)
        {
            password = null;
        }

        return new ConnectionArguments
        {
            Host = host,
            Port = port,
            UserName = user,
            Domain = domain,
            Password = password,
            TlsOnly = tlsOnly,
            CredSspOnly = credSspOnly,
            LogHex = logHex,
            ConnectImmediately = connectNow,
            Error = error,
        };
    }
}
