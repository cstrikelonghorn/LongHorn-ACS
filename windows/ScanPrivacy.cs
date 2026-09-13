using System.Text.Json;

namespace ACPScanner;

internal static class ScanPrivacy
{
    internal const string Disclosure = "ACS scans only after you choose Start scan. It inspects the running game, loaded modules, drivers, other processes, game files/configs, and execution/download/deletion traces. It briefly samples game input state.\r\n\r\nReports can contain player/Steam identifiers, machine name, volume serial/device fingerprint, paths, hashes, game/server details, memory strings and findings. The receiving server also sees your IP address.\r\n\r\nYou will review the complete report before choosing Upload. Declining upload keeps it from being sent. The scan downloads detection rules first, so that connection exposes your IP to the configured server.\r\n\r\nServer operators control report access and retention. This client cannot guarantee deletion after upload. Only use an operator you trust. This release is not independently audited or publisher-signed.";

    internal static bool ConfirmScan(IWin32Window owner, string apiUrl)
    {
        using var dialog = new Form { Text = "Before you scan — privacy", StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(650, 485), MinimizeBox = false, MaximizeBox = false, FormBorderStyle = FormBorderStyle.FixedDialog };
        var body = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
            Text = "Report destination: " + new Uri(apiUrl).GetLeftPart(UriPartial.Path) + "\r\n\r\n" + Disclosure,
            Dock = DockStyle.Fill, Font = new Font("Segoe UI", 10), BorderStyle = BorderStyle.None, BackColor = SystemColors.Window };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 58, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(10) };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, AutoSize = true };
        var start = new Button { Text = "I understand — start scan", DialogResult = DialogResult.OK, AutoSize = true };
        buttons.Controls.AddRange(new Control[] { cancel, start });
        dialog.Controls.Add(body); dialog.Controls.Add(buttons);
        dialog.Padding = new Padding(18); dialog.CancelButton = cancel;
        return dialog.ShowDialog(owner) == DialogResult.OK;
    }

    internal static bool ConfirmUpload(IWin32Window owner, string apiUrl, string reportJson)
    {
        using var dialog = new Form { Text = "Review your report before upload", StartPosition = FormStartPosition.CenterParent,
            ClientSize = new Size(850, 610), MinimizeBox = false };
        var intro = new Label { Dock = DockStyle.Top, Height = 68,
            Text = "Destination: " + new Uri(apiUrl).GetLeftPart(UriPartial.Path) + "\r\nReview all data below. Upload sends this report to that operator. Closing this window declines upload.", AutoEllipsis = true };
        using var document = JsonDocument.Parse(reportJson);
        var body = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9), Text = JsonSerializer.Serialize(document.RootElement, new JsonSerializerOptions { WriteIndented = true }) };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 56, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
        var decline = new Button { Text = "Do not upload", DialogResult = DialogResult.Cancel, AutoSize = true };
        var upload = new Button { Text = "Upload this report", DialogResult = DialogResult.OK, AutoSize = true };
        buttons.Controls.AddRange(new Control[] { decline, upload });
        dialog.Controls.Add(body); dialog.Controls.Add(intro); dialog.Controls.Add(buttons);
        dialog.Padding = new Padding(16); dialog.CancelButton = decline;
        return dialog.ShowDialog(owner) == DialogResult.OK;
    }
}
