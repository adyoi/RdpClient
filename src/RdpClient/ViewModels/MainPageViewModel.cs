using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Dispatching;
using RdpClient.Protocol;
using Windows.ApplicationModel.DataTransfer;

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
    private readonly DispatcherQueueTimer _copyFeedback;
    private RdpConnection? _connection;
    private CancellationTokenSource? _cts;

    public MainPageViewModel(DispatcherQueue dispatcher)
    {
        _dispatcher = dispatcher;
        _copyFeedback = dispatcher.CreateTimer();

        // Partial properties cannot carry initialisers, so defaults are assigned
        // here instead of at the declaration.
        Host = string.Empty;
        Port = "3389";
        UserName = string.Empty;
        Domain = string.Empty;
        Password = string.Empty;
        StatusText = "Idle";
        CopyButtonText = "Copy log";

        // Both log commands depend on whether there is anything to copy, and the
        // collection is the only thing that changes the answer.
        Log.CollectionChanged += (_, _) => RefreshLogCommands();
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

    /// <summary>Label of the copy button; flips to confirm the copy happened.</summary>
    [ObservableProperty]
    public partial string CopyButtonText { get; set; }

    public bool CanConnect => !IsBusy && !string.IsNullOrWhiteSpace(Host);

    /// <summary>Nothing to copy and nothing to clear while the log is empty.</summary>
    public bool CanCopyLog => Log.Count > 0;

    partial void OnHostChanged(string value) => RefreshCommands();
    partial void OnIsBusyChanged(bool value) => RefreshCommands();

    private void RefreshCommands()
    {
        ConnectCommand.NotifyCanExecuteChanged();
        RefreshLogCommands();
    }

    private void RefreshLogCommands()
    {
        OnPropertyChanged(nameof(CanCopyLog));
        CopyLogCommand.NotifyCanExecuteChanged();
        ClearCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Render the log as plain text, with the target in a header.
    /// </summary>
    /// <remarks>
    /// The point of the header is that a pasted log says which host and stage it
    /// came from. The password is deliberately absent: nothing in the handshake
    /// log contains it. The protocol hex the authenticator traces does include
    /// NTLM messages, which are hash-derived rather than the password itself, so
    /// a log is still worth reading before posting it in public.
    /// </remarks>
    public string BuildLogText()
    {
        var text = new StringBuilder();
        text.AppendLine($"RdpClient log, {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        text.AppendLine($"target: {Host.Trim()}:{Port}  stage: {Stage}");

        if (!string.IsNullOrWhiteSpace(UserName))
        {
            string account = string.IsNullOrWhiteSpace(Domain) ? UserName : $"{Domain}\\{UserName}";
            text.AppendLine($"account: {account}");
        }

        text.AppendLine();

        foreach (LogEntry entry in Log)
        {
            text.AppendLine($"{entry.Timestamp}  {entry.Level,-5}  {entry.Message}");
        }

        return text.ToString();
    }

    /// <summary>Copy the log so it can be pasted into a bug report.</summary>
    [RelayCommand(CanExecute = nameof(CanCopyLog))]
    private void CopyLog()
    {
        try
        {
            var package = new DataPackage { RequestedOperation = DataPackageOperation.Copy };
            package.SetText(BuildLogText());

            // The clipboard is a WinRT API and needs a registered package
            // identity. Running the app without one fails here rather than at
            // startup, which is why the error is reported into the log itself.
            Clipboard.SetContent(package);
            ShowCopyFeedback("Copied");
        }
        catch (Exception ex)
        {
            Append("error", $"could not copy the log: {ex.Message}");
        }
    }

    private void ShowCopyFeedback(string text)
    {
        CopyButtonText = text;
        _copyFeedback.Stop();
        _copyFeedback.Interval = TimeSpan.FromSeconds(1.5);
        _copyFeedback.IsRepeating = false;
        _copyFeedback.Tick -= OnCopyFeedbackElapsed;
        _copyFeedback.Tick += OnCopyFeedbackElapsed;
        _copyFeedback.Start();
    }

    private void OnCopyFeedbackElapsed(DispatcherQueueTimer sender, object args)
    {
        sender.Stop();
        CopyButtonText = "Copy log";
    }

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

                    // The classic-RDP user block needs the UTF-16 byte length
                    // up front, so the secret has to exist as a string. A
                    // shipping client would authenticate through CredSSP
                    // instead and never hold it, and this block is opt-in
                    // precisely because it puts the password on the wire.
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

    [RelayCommand(CanExecute = nameof(CanCopyLog))]
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

    /// <summary>Add one line to the log, stamped and level-tagged.</summary>
    public void Append(string level, string message) =>
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