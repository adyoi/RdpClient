using RdpClient.Protocol;
using Xunit;

namespace RdpClient.Protocol.Tests;

/// <summary>
/// Tests for the command-line arguments that pre-fill the connection form.
/// </summary>
/// <remarks>
/// The parser exists so a scripted run is reproducible: the same command line
/// must always produce the same form and the same connection options. Two
/// mistakes matter most, and both are silent unless tested: a misspelled
/// argument that gets ignored instead of rejected, and a password read from
/// somewhere it leaks from.
/// </remarks>
public class ConnectionArgumentsTests
{
    [Fact]
    public void NoArguments_MeansNothingToPreFill()
    {
        ConnectionArguments parsed = ConnectionArguments.Parse([]);

        Assert.Null(parsed.Error);
        Assert.False(parsed.HasAnyValue);
        Assert.Null(parsed.Host);
    }

    [Theory]
    [InlineData(new[] { "--host", "192.0.2.10" }, "192.0.2.10")]
    [InlineData(new[] { "--host=192.0.2.10" }, "192.0.2.10")]
    [InlineData(new[] { "--host", "192.0.2.10", "--port", "3390" }, "192.0.2.10")]
    public void HostIsAcceptedInBothSpellings(string[] args, string expected)
    {
        ConnectionArguments parsed = ConnectionArguments.Parse(args);

        Assert.Null(parsed.Error);
        Assert.Equal(expected, parsed.Host);
    }

    [Fact]
    public void AnUnknownArgumentIsRejectedRatherThanIgnored()
    {
        // A silent shrug here would connect to whatever host the form already
        // held, which is exactly the mistake a scripted run must not make.
        ConnectionArguments parsed = ConnectionArguments.Parse(["--hos", "192.0.2.10"]);

        Assert.Equal("unknown argument --hos", parsed.Error);
    }

    [Fact]
    public void AMissingValueIsReported()
    {
        ConnectionArguments parsed = ConnectionArguments.Parse(["--host"]);

        Assert.Equal("--host needs a value", parsed.Error);
    }

    [Fact]
    public void ASwitchDoesNotSwallowTheNextArgument()
    {
        ConnectionArguments parsed = ConnectionArguments.Parse(
            ["--hex", "--host", "192.0.2.10"]);

        Assert.Null(parsed.Error);
        Assert.True(parsed.LogHex);
        Assert.Equal("192.0.2.10", parsed.Host);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("http")]
    public void AnInvalidPortIsRejected(string port)
    {
        ConnectionArguments parsed = ConnectionArguments.Parse(["--port", port]);

        Assert.Equal($"'{port}' is not a valid TCP port", parsed.Error);
    }

    [Fact]
    public void ContradictorySecurityModesAreRejected()
    {
        ConnectionArguments parsed = ConnectionArguments.Parse(["--tls-only", "--credssp-only"]);

        Assert.Equal("--tls-only and --credssp-only contradict each other", parsed.Error);
    }

    [Fact]
    public void ThePasswordComesFromTheEnvironmentWhenNotGiven()
    {
        const string previous = "PROTOCOL_TEST_RDP_PASSWORD";

        try
        {
            Environment.SetEnvironmentVariable(previous, "from-environment");
            ConnectionArguments parsed = ConnectionArguments.Parse(
                ["--host", "192.0.2.10"], passwordEnvironmentVariable: previous);

            Assert.Null(parsed.Error);
            Assert.Equal("from-environment", parsed.Password);
        }
        finally
        {
            Environment.SetEnvironmentVariable(previous, null);
        }
    }

    [Fact]
    public void AnExplicitPasswordWinsOverTheEnvironment()
    {
        const string previous = "PROTOCOL_TEST_RDP_PASSWORD";

        try
        {
            Environment.SetEnvironmentVariable(previous, "from-environment");
            ConnectionArguments parsed = ConnectionArguments.Parse(
                ["--password", "explicit"], passwordEnvironmentVariable: previous);

            Assert.Equal("explicit", parsed.Password);
        }
        finally
        {
            Environment.SetEnvironmentVariable(previous, null);
        }
    }

    [Fact]
    public void NoPasswordAsksForTheEnvironmentNotToBeRead()
    {
        const string previous = "PROTOCOL_TEST_RDP_PASSWORD";

        try
        {
            Environment.SetEnvironmentVariable(previous, "from-environment");
            ConnectionArguments parsed = ConnectionArguments.Parse(
                ["--no-password"], passwordEnvironmentVariable: previous);

            Assert.Null(parsed.Password);
        }
        finally
        {
            Environment.SetEnvironmentVariable(previous, null);
        }
    }

    [Fact]
    public void ConnectionOptionsCarryTheParsedSecurityMode()
    {
        RdpConnectionOptions options = ConnectionArguments
            .Parse(["--host", "192.0.2.10", "--port", "3390", "--tls-only", "--hex"])
            .ToConnectionOptions();

        Assert.Equal("192.0.2.10", options.Host);
        Assert.Equal(3390, options.Port);
        Assert.Equal(SecurityModeSelection.TlsOnly, options.Security);
        Assert.True(options.LogTx);
        Assert.Null(options.User);
    }

    [Fact]
    public void AUserNameProducesCredentialsAndNoneDoesNot()
    {
        RdpConnectionOptions withUser = ConnectionArguments
            .Parse(["--user", "alice", "--domain", "CORP"])
            .ToConnectionOptions();

        Assert.NotNull(withUser.User);
        Assert.Equal("alice", withUser.User.UserName);
        Assert.Equal("CORP", withUser.User.Domain);

        Assert.Null(ConnectionArguments.Parse(["--host", "192.0.2.10"]).ToConnectionOptions().User);
    }

    [Fact]
    public void AnInvalidPortFallsBackToTheDefaultInOptions()
    {
        // Parse reports the error; the conversion still yields something usable
        // so the caller can show the form rather than refuse to start.
        RdpConnectionOptions options = ConnectionArguments
            .Parse(["--port", "0"])
            .ToConnectionOptions();

        Assert.Equal(RdpConnectionOptions.DefaultPort, options.Port);
    }
}
