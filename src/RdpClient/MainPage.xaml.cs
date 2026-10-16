using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using RdpClient.Protocol;
using RdpClient.ViewModels;

// To learn more about WinUI, the WinUI project structure,
// and more about your project templates, see: http://aka.ms/winui-project-info.

namespace RdpClient;

/// <summary>
/// The main content page displayed inside the application window.
/// </summary>
public sealed partial class MainPage : Page
{
    public MainPageViewModel ViewModel { get; }

    public MainPage()
        : this(null)
    {
    }

    public MainPage(object? parameter)
    {
        // The ViewModel needs the UI thread's dispatcher so handshake events
        // raised on the socket continuation thread can update observable state.
        ViewModel = new MainPageViewModel(DispatcherQueue);
        InitializeComponent();

        ApplyArguments(parameter as ConnectionArguments);

        Unloaded += OnUnloaded;
    }

    /// <summary>
    /// Pre-fill the form from the command line, then connect if asked to.
    /// </summary>
    /// <remarks>
    /// An argument that could not be parsed is reported into the connection log
    /// rather than a dialog: the point of the command line is unattended runs,
    /// and a modal window would hang one. The password is only ever assigned to
    /// the box, never to the log.
    /// </remarks>
    private void ApplyArguments(ConnectionArguments? arguments)
    {
        if (arguments is null)
        {
            return;
        }

        if (arguments.Error is not null)
        {
            ViewModel.Log.Clear();
            ViewModel.Append("error", $"command line: {arguments.Error}");
        }

        if (arguments.Host is not null)
        {
            ViewModel.Host = arguments.Host;
        }

        if (arguments.Port is not null)
        {
            ViewModel.Port = arguments.Port;
        }

        if (arguments.UserName is not null)
        {
            ViewModel.UserName = arguments.UserName;
        }

        if (arguments.Domain is not null)
        {
            ViewModel.Domain = arguments.Domain;
        }

        if (arguments.Password is not null)
        {
            ViewModel.Password = arguments.Password;
        }

        if (arguments.ConnectImmediately && arguments.Error is null
            && !string.IsNullOrWhiteSpace(ViewModel.Host))
        {
            ViewModel.ConnectCommand.Execute(null);
        }
    }

    private async void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Unloaded -= OnUnloaded;
        await ViewModel.DisposeAsync();
    }
}