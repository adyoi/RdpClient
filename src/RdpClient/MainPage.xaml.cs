using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
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
    {
        // The ViewModel needs the UI thread's dispatcher so handshake events
        // raised on the socket continuation thread can update observable state.
        ViewModel = new MainPageViewModel(DispatcherQueue);
        InitializeComponent();

        Unloaded += OnUnloaded;
    }

    private async void OnUnloaded(object sender, RoutedEventArgs e)
    {
        Unloaded -= OnUnloaded;
        await ViewModel.DisposeAsync();
    }
}