using System.Diagnostics;

namespace ACPScanner;

/// <summary>
/// Opens web links from an app that runs as administrator.
///
/// Starting a URL directly from an elevated process launches the browser elevated too, with
/// full rights over the machine - the last thing a web page should have. Handing the URL to
/// Explorer instead lets the already-running, non-elevated desktop shell open it with the
/// player's normal rights. Only http and https are accepted: the report link comes back from
/// a server, and must never be able to start anything else.
/// </summary>
public static class BrowserLink
{
    public static bool Open(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)
            || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return false;
        }

        try
        {
            using var explorer = Process.Start(new ProcessStartInfo("explorer.exe", "\"" + uri.AbsoluteUri + "\"") { UseShellExecute = false });
            return true;
        }
        catch
        {
            return false;
        }
    }
}

public sealed record ScanUploadResult(
    bool Uploaded,
    string Status,
    int Detected,
    int Warnings,
    int Processes,
    int Drivers,
    int HlFiles,
    string? ReportUrl,
    string? Error,
    bool UploadDeclined = false,
    // The game server as the engine reported it when the scan started - the same values the
    // report page shows, so the app and the website never disagree.
    string ServerStatus = "",
    string ServerName = "",
    string ServerAddress = "",
    string ServerMap = "");
