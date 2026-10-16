using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using RdpClient.Protocol;

namespace RdpClient.ViewModels;

/// <summary>
/// Drives the connection form and the handshake log.
/// </summary>
/// <remarks>
/// <see cref="RdpConnection"/> raises events on the socket's continuation
/// thread, so every observable mutation is marshalled through the captured
/// <see cref="DispatcherQueue"/> before it touches bound state.
/// </remarks>
public sealed partial class MainPageViewModel : ObservableObject, IAsyncDisposable
{
    private readonly DispatcherQueue _dispatcher;
    private RdpConnection? _connection;
    private CancellationTokenSource? _cts;

    public MainPageViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;

        // Partial properties cannot carry initialisers, so defaults are assigned
        // here instead of at the declaration.
        Host = string.Empty;
        Port = "3389";
        UserName = string.Empty;
        Domain = string.Empty;
        Password = string.Empty;
        StatusText = "Idle";
    }

    public ObservableCollection<LogEntry> Log { get; } = [];

    [ObservableProperty]
    public partial string Host { get; set; }

    [ObservableProperty]
    public partial string Port { get; set; }

    [ObservableProperty]
    public partial string UserName { get; set; }

    [ObservableProperty]
    public partial string Domain { get; set; }

    [ObservableProperty]
    public partial string Password { get; set; }

    [ObservableProperty]
    public partial bool IsBusy { get; set; }

    [ObservableProperty]
    public partial string StatusText { get; set; }

    [ObservableProperty]
    public partial HandshakeStage Stage { get; set; }

    public bool CanConnect => !IsBusy && !string.IsNullOrWhiteSpace(Host);

    partial void OnHostChanged(string value) => RefreshCommands();
    partial void OnIsBusyChanged(bool value) => RefreshCommands();

    private void RefreshCommands() => ConnectCommand.NotifyCanExecuteChanged();

    [RelayCommand(CanExecute = nameof(CanConnect))]
    private async Task ConnectAsync()
    {
        if (!int.TryParse(Port, out int port) || port is < 1 or > 65535)
        {
            Append("error", $"'{Port}' is not a valid TCP port.");
            StatusText = "Invalid port";
            return;
        }

        Log.Clear();
        _cts = new CancellationTokenSource();
        _connection = new RdpConnection();
        _connection.OnEvent += OnHandshakeEvent;

        IsBusy = true;
        StatusText = "Connecting...";
        Stage = HandshakeStage.Idle;

        try
        {
            var user = string.IsNullOrWhiteSpace(UserName)
                ? null
                : new ClientPdu.UserOptions
                {
                    UserName = UserName,
                    Domain = Domain,

                    // TS_UD_CS_USER needs the UTF-16 byte length up front, so the
                    // secret has to exist as a string. A shipping client would
                    // authenticate through CredSSP instead and never hold it.
                    Password = Password,
                };

            var connectionOptions = new RdpConnectionOptions
            {
                Host = Host.Trim(),
                Port = port,
                User = user,
            };

            await _connection.ConnectAsync(connectionOptions, _cts.Token);
        }
        finally
        {
            IsBusy = false;
        }
    }

    [RelayCommand]
    private void Cancel() => _cts?.Cancel();

    [RelayCommand]
    private void Clear()
    {
        Log.Clear();
        StatusText = "Idle";
        Stage = HandshakeStage.Idle;
    }

    private void OnHandshakeEvent(HandshakeEvent evt) => _dispatcher.TryEnqueue(() =>
    {
        Stage = evt.Stage;
        StatusText = evt.Stage.ToString();
        Append(evt.IsError ? "error" : "info", evt.Message);
    });

    private void Append(string level, string message) =>
        Log.Add(new LogEntry(DateTime.Now.ToString("HH:mm:ss"), level, message));

    public async ValueTask DisposeAsync()
    {
        _cts?.Cancel();
        if (_connection is not null)
        {
            await _connection.DisposeAsync();
        }

        _cts?.Dispose();
    }
}

public sealed record LogEntry(string Timestamp, string Level, string Message);