using System.ComponentModel;
using System.Drawing.Drawing2D;
using System.Drawing.Text;

namespace ACPScanner;

/// <summary>
/// The one consent step before a scan.
///
/// It used to be two stock Windows dialogs: a grey text box before the scan, and a raw JSON
/// dump with an Upload button after it. The second one is gone - the report now uploads as
/// soon as the scan finishes - which makes this screen the whole of the player's consent. So
/// it has to say plainly, before anything happens, that the upload is automatic and where it
/// goes. Everything it said before is still said; it is set out so it can be read in the few
/// seconds a player will actually give it.
/// </summary>
internal static class ScanPrivacy
{
    /// <summary>Plain-text form of the notice, for anywhere it has to be shown as text.</summary>
    internal const string Disclosure =
        "ACS scans only after you choose Start scan. It inspects the running game, its loaded modules, drivers, other processes, game files and configs, and recent launch, download and deletion traces. It briefly samples game input, and queries the game server via Valve A2S protocol to identify the server you are joined to. ACS runs in user space without requiring administrator rights. Nothing on your PC is changed.\r\n\r\n" +
        "The report can contain player and Steam identifiers, machine name, device fingerprint, file paths, hashes, game server details, memory strings and findings. The receiving server also sees your IP address.\r\n\r\n" +
        "The report is uploaded automatically as soon as the scan finishes. Choose Cancel now if you do not want it sent.\r\n\r\n" +
        "The server operator controls who can view reports and how long they are kept. This client cannot delete a report after upload. Only scan for a server you trust. This build is not independently audited or code-signed.";

    /// <summary>Shows the notice. True only if the player chose to start the scan.</summary>
    internal static bool ConfirmScan(IWin32Window owner, string apiUrl)
    {
        using var dialog = new PrivacyForm(apiUrl);
        return dialog.ShowDialog(owner) == DialogResult.OK;
    }
}

internal sealed class PrivacyForm : Form
{
    private const int BaseW = 620;
    private const int BaseH = 536;
    private const int LayoutMargin = 28;

    private float _scale = 1f;
    private int S(float v) => (int)Math.Round(v * _scale);

    private readonly string _destination;
    private readonly bool _secure;
    private readonly HudButton _accept = new();
    private readonly HudButton _cancel = new();

    private Rectangle _closeRect;
    private bool _closeHot;
    private Point _dragFrom;
    private bool _dragging;

    private Font _fTitle = null!, _fEyebrow = null!, _fHead = null!, _fBody = null!, _fMono = null!, _fFine = null!;

    private enum Mark { Scan, Report, Upload, Owner }

    private readonly record struct Section(Mark Mark, string Title, string Body, bool Emphasis);

    private static readonly Section[] Sections =
    {
        new(Mark.Scan, "WHAT IS CHECKED",
            "The running game, its modules, drivers, other processes, game files and configs, and recent launch, download and deletion traces. The game server is queried directly via Valve A2S protocol to identify the server you are on. Nothing on your PC is changed.", false),
        new(Mark.Report, "WHAT THE REPORT CONTAINS",
            "Player and Steam identifiers, machine name, device fingerprint, file paths, hashes, game server details, memory strings and findings. The server also sees your IP address.", false),
        // The one fact a player must not miss: there is no later step at which to say no.
        new(Mark.Upload, "UPLOADED AUTOMATICALLY",
            "When the scan finishes, the report is sent to the server below and its link opens in your browser. There is no second confirmation - choose Cancel now if you do not want it sent.", true),
        new(Mark.Owner, "WHO CONTROLS IT",
            "The server operator decides who can view reports and how long they are kept. This app cannot delete a report after upload. Only scan for a server you trust.", false)
    };

    public PrivacyForm(string apiUrl)
    {
        var uri = new Uri(apiUrl);
        _destination = uri.GetLeftPart(UriPartial.Path);
        _secure = uri.Scheme == Uri.UriSchemeHttps;

        Text = "ACS — Before you scan";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoScaleMode = AutoScaleMode.None;
        DoubleBuffered = true;
        BackColor = AcpTheme.Bg;
        ForeColor = AcpTheme.Ink;
        KeyPreview = true;

        _accept.Text = "I AGREE — START SCAN";
        _accept.Primary = true;
        _accept.Accent = AcpTheme.Gold;
        _accept.Glyph = HudGlyph.Scan;
        _accept.Click += (_, _) => { DialogResult = DialogResult.OK; Close(); };

        _cancel.Text = "CANCEL";
        _cancel.Accent = AcpTheme.Muted;
        _cancel.Glyph = HudGlyph.Close;
        _cancel.Click += (_, _) => { DialogResult = DialogResult.Cancel; Close(); };

        Controls.Add(_accept);
        Controls.Add(_cancel);

        ApplyScale();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyScale();
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        ApplyScale();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _cancel.Focus();   // Enter must not agree by accident; it has to be a choice
    }

    private bool _applyingScale;

    private void ApplyScale()
    {
        if (_applyingScale)
        {
            return;
        }

        var dpi = DeviceDpi / 96f;
        var screen = IsHandleCreated ? Screen.FromControl(this) : Screen.PrimaryScreen;
        var work = screen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        var fit = Math.Min((work.Width - 60f) / (BaseW * dpi), (work.Height - 60f) / (BaseH * dpi));
        var next = dpi * Math.Clamp(fit, 0.6f, 1f);
        if (_fTitle is not null && Math.Abs(next - _scale) < 0.001f)
        {
            return;
        }

        _applyingScale = true;
        try
        {
            _scale = next;
            BuildFonts();
            ClientSize = new Size(S(BaseW), S(BaseH));

            void Place(HudButton b, int x, int w)
            {
                var old = b.Font;
                b.VisualScale = _scale;
                b.Font = AcpFonts.Mono(S(10.5f), FontStyle.Bold);
                b.Bounds = new Rectangle(S(x), S(BaseH - 62), S(w), S(40));
                old?.Dispose();
            }

            Place(_cancel, LayoutMargin, 120);
            Place(_accept, BaseW - LayoutMargin - 232, 232);
            Invalidate();
        }
        finally
        {
            _applyingScale = false;
        }
    }

    private void BuildFonts()
    {
        DisposeFonts();
        _fTitle   = AcpFonts.Mono(S(13), FontStyle.Bold);
        _fEyebrow = AcpFonts.Mono(S(9.5f), FontStyle.Bold);
        _fHead    = AcpFonts.Mono(S(10.5f), FontStyle.Bold);
        _fBody    = AcpFonts.Display(S(13));
        _fMono    = AcpFonts.Mono(S(11));
        _fFine    = AcpFonts.Display(S(11));
    }

    private void DisposeFonts()
    {
        foreach (var f in new[] { _fTitle, _fEyebrow, _fHead, _fBody, _fMono, _fFine })
        {
            f?.Dispose();
        }
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Escape)
        {
            DialogResult = DialogResult.Cancel;
            Close();
            e.Handled = true;
        }
        base.OnKeyDown(e);
    }

    // ── Chrome ───────────────────────────────────────────────────────────────

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            if (_closeRect.Contains(e.Location)) { DialogResult = DialogResult.Cancel; Close(); return; }
            if (e.Y <= S(58)) { _dragging = true; _dragFrom = e.Location; }
        }
        base.OnMouseDown(e);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_dragging)
        {
            Location = new Point(Location.X + e.X - _dragFrom.X, Location.Y + e.Y - _dragFrom.Y);
        }
        else if (_closeRect.Contains(e.Location) != _closeHot)
        {
            _closeHot = !_closeHot;
            Invalidate(_closeRect);
        }
        base.OnMouseMove(e);
    }

    protected override void OnMouseUp(MouseEventArgs e) { _dragging = false; base.OnMouseUp(e); }

    // ── Painting ─────────────────────────────────────────────────────────────

    protected override void OnPaintBackground(PaintEventArgs e) { }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

        var w = ClientSize.Width;
        var h = ClientSize.Height;

        using (var back = new LinearGradientBrush(new Rectangle(0, 0, w, h),
                   Color.FromArgb(17, 20, 27), Color.FromArgb(7, 9, 13), 70f))
        {
            g.FillRectangle(back, 0, 0, w, h);
        }

        DrawHeader(g, w);
        var y = DrawSections(g, w);
        DrawDestination(g, w, y);
        DrawFooter(g, w, h);

        AcpTheme.DrawWindowEdge(g, w, h);
    }

    private void DrawHeader(Graphics g, int w)
    {
        var barH = S(58);
        var x = (float)S(LayoutMargin);

        // A shield: this screen is about the player's data, not about the scan.
        var cx = x + S(12);
        var cy = barH / 2f;
        using (var shield = new GraphicsPath())
        {
            var sw = S(20f);
            var sh = S(23f);
            var top = cy - sh / 2f;
            shield.AddLine(cx - sw / 2f, top + S(4), cx, top);
            shield.AddLine(cx, top, cx + sw / 2f, top + S(4));
            shield.AddBezier(cx + sw / 2f, top + S(4), cx + sw / 2f, top + sh * 0.62f, cx + S(4), top + sh * 0.86f, cx, top + sh);
            shield.AddBezier(cx, top + sh, cx - S(4), top + sh * 0.86f, cx - sw / 2f, top + sh * 0.62f, cx - sw / 2f, top + S(4));
            shield.CloseFigure();
            using var fill = new SolidBrush(AcpTheme.Fade(AcpTheme.Gold, 36));
            using var pen = new Pen(AcpTheme.Gold, Math.Max(1.2f, 1.5f * _scale));
            g.FillPath(fill, shield);
            g.DrawPath(pen, shield);
        }
        using (var tick = new Pen(AcpTheme.GoldBright, Math.Max(1.4f, 1.8f * _scale)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
        {
            g.DrawLines(tick, new[]
            {
                new PointF(cx - S(4.5f), cy + S(0.5f)),
                new PointF(cx - S(1), cy + S(4)),
                new PointF(cx + S(5), cy - S(3.5f))
            });
        }

        var tx = x + S(36);
        Txt.DrawTracked(g, "BEFORE YOU SCAN", _fTitle, tx, cy - S(15), AcpTheme.Ink, S(1.3f));
        Txt.DrawTracked(g, "PRIVACY & CONSENT · READ ONCE", _fEyebrow, tx, cy + S(3), AcpTheme.Fade(AcpTheme.Gold, 200), S(1f));

        var btn = S(32);
        _closeRect = new Rectangle(w - btn - S(10), (barH - btn) / 2, btn, btn);
        if (_closeHot)
        {
            using var hb = new SolidBrush(Color.FromArgb(180, 200, 50, 45));
            g.FillRectangle(hb, _closeRect);
        }
        using (var pen = new Pen(_closeHot ? Color.White : AcpTheme.Muted, 1.4f))
        {
            var c = new Point(_closeRect.X + _closeRect.Width / 2, _closeRect.Y + _closeRect.Height / 2);
            g.DrawLine(pen, c.X - S(6), c.Y - S(6), c.X + S(6), c.Y + S(6));
            g.DrawLine(pen, c.X + S(6), c.Y - S(6), c.X - S(6), c.Y + S(6));
        }

        using var rule = new LinearGradientBrush(new Rectangle(0, barH, w, 1),
            Color.FromArgb(34, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 0f);
        g.FillRectangle(rule, 0, barH, w, 1);
    }

    /// <summary>The four points, each measured so long text never overlaps the next.</summary>
    private float DrawSections(Graphics g, int w)
    {
        var x = (float)S(LayoutMargin);
        var y = (float)S(76);
        var iconBox = S(30);
        var textX = x + iconBox + S(14);
        var textW = w - textX - S(LayoutMargin);

        using var wrap = (StringFormat)StringFormat.GenericTypographic.Clone();
        wrap.Trimming = StringTrimming.Word;

        foreach (var section in Sections)
        {
            var bodyH = g.MeasureString(section.Body, _fBody, new SizeF(textW, 1000), wrap).Height;
            var blockH = S(18) + bodyH;

            if (section.Emphasis)
            {
                // The automatic upload is set apart: an amber panel behind the whole point.
                var panel = new RectangleF(x - S(12), y - S(10), w - S(LayoutMargin) * 2 + S(24), blockH + S(20));
                using var path = AcpTheme.RoundedRect(Rectangle.Round(panel), S(5));
                using var fill = new SolidBrush(AcpTheme.Fade(AcpTheme.Amber, 20));
                using var pen = new Pen(AcpTheme.Fade(AcpTheme.Amber, 110), 1f);
                g.FillPath(fill, path);
                g.DrawPath(pen, path);
            }

            var accent = section.Emphasis ? AcpTheme.Amber : AcpTheme.Gold;
            var icon = new RectangleF(x, y, iconBox, iconBox);
            using (var iconPath = AcpTheme.RoundedRect(Rectangle.Round(icon), S(6)))
            using (var iconFill = new SolidBrush(AcpTheme.Fade(accent, section.Emphasis ? 52 : 30)))
            {
                g.FillPath(iconFill, iconPath);
            }
            DrawMark(g, section.Mark, RectangleF.Inflate(icon, -S(8), -S(8)), AcpTheme.Fade(accent, 255));

            Txt.DrawTracked(g, section.Title, _fHead, textX, y - S(1),
                section.Emphasis ? AcpTheme.Amber : AcpTheme.Fade(AcpTheme.Ink, 235), S(1f));

            using (var brush = new SolidBrush(AcpTheme.Fade(AcpTheme.Ink, section.Emphasis ? 225 : 180)))
            {
                g.DrawString(section.Body, _fBody, brush, new RectangleF(textX, y + S(17), textW, bodyH + S(4)), wrap);
            }

            y += Math.Max(iconBox, blockH) + (section.Emphasis ? S(28) : S(18));
        }

        return y;
    }

    private void DrawDestination(Graphics g, int w, float y)
    {
        var x = (float)S(LayoutMargin);
        Txt.DrawTracked(g, "REPORT DESTINATION", _fEyebrow, x, y, AcpTheme.Fade(AcpTheme.Gold, 200), S(1.1f));

        var field = new Rectangle((int)x, (int)(y + S(16)), w - S(LayoutMargin) * 2, S(36));
        using (var path = AcpTheme.RoundedRect(field, S(4)))
        using (var fill = new SolidBrush(Color.FromArgb(200, 11, 15, 21)))
        using (var pen = new Pen(Color.FromArgb(52, 255, 255, 255), 1f))
        {
            g.FillPath(fill, path);
            g.DrawPath(pen, path);
        }

        // Green for an encrypted connection; amber for plain HTTP, which only a local test
        // server is allowed to use.
        var dot = _secure ? AcpTheme.Green : AcpTheme.Amber;
        var cy = field.Y + field.Height / 2f;
        using (var db = new SolidBrush(dot))
        {
            g.FillEllipse(db, field.X + S(14), cy - S(4), S(8), S(8));
        }

        var tag = _secure ? "ENCRYPTED" : "LOCAL · NOT ENCRYPTED";
        var tagW = Txt.TrackedWidth(g, tag, _fEyebrow, S(0.8f));
        Txt.DrawTracked(g, tag, _fEyebrow, field.Right - S(14) - tagW, cy - _fEyebrow.GetHeight(g) / 2f, AcpTheme.Fade(dot, 230), S(0.8f));

        var textX = field.X + S(32);
        var room = field.Right - S(28) - tagW - textX;
        var shown = _destination;
        while (shown.Length > 12 && Txt.Width(g, shown, _fMono) > room)
        {
            shown = shown[..^2];
        }
        if (shown.Length < _destination.Length)
        {
            shown += "…";
        }
        Txt.Draw(g, shown, _fMono, textX, cy - _fMono.GetHeight(g) / 2f, AcpTheme.Fade(AcpTheme.Ink, 235));
    }

    private void DrawFooter(Graphics g, int w, int h)
    {
        var line = "This build is not independently audited or code-signed.";
        var lw = Txt.Width(g, line, _fFine);
        var y = h - S(62) - S(26);
        Txt.Draw(g, line, _fFine, (w - lw) / 2f, y, AcpTheme.Fade(AcpTheme.Faint, 230));
    }

    private void DrawMark(Graphics g, Mark mark, RectangleF box, Color color)
    {
        var width = Math.Max(1.3f, 1.6f * _scale);
        using var pen = new Pen(color, width) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        var cx = box.X + box.Width / 2f;
        var cy = box.Y + box.Height / 2f;

        switch (mark)
        {
            case Mark.Scan:
            {
                var r = box.Width * 0.36f;
                g.DrawEllipse(pen, cx - r - box.Width * 0.06f, cy - r - box.Height * 0.06f, r * 2, r * 2);
                g.DrawLine(pen, cx + r * 0.62f, cy + r * 0.62f, box.Right, box.Bottom);
                break;
            }
            case Mark.Report:
            {
                var page = new RectangleF(box.X + box.Width * 0.14f, box.Y, box.Width * 0.72f, box.Height);
                g.DrawRectangle(pen, page.X, page.Y, page.Width, page.Height);
                for (var i = 1; i <= 3; i++)
                {
                    var ly = page.Y + page.Height * (0.22f * i + 0.04f);
                    g.DrawLine(pen, page.X + page.Width * 0.22f, ly, page.Right - page.Width * (i == 3 ? 0.42f : 0.22f), ly);
                }
                break;
            }
            case Mark.Upload:
            {
                g.DrawLine(pen, cx, box.Bottom - box.Height * 0.28f, cx, box.Y);
                g.DrawLine(pen, cx - box.Width * 0.3f, box.Y + box.Height * 0.3f, cx, box.Y);
                g.DrawLine(pen, cx + box.Width * 0.3f, box.Y + box.Height * 0.3f, cx, box.Y);
                g.DrawLine(pen, box.X, box.Bottom, box.Right, box.Bottom);
                break;
            }
            case Mark.Owner:
            {
                var r = box.Width * 0.22f;
                g.DrawEllipse(pen, cx - r, box.Y, r * 2, r * 2);
                using var body = new GraphicsPath();
                body.AddArc(box.X + box.Width * 0.08f, box.Y + box.Height * 0.52f, box.Width * 0.84f, box.Height * 0.9f, 180, 180);
                g.DrawPath(pen, body);
                break;
            }
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeFonts();
        }
        base.Dispose(disposing);
    }
}
