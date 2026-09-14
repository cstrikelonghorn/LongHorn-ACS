using System.ComponentModel;
using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.Reflection;
using System.Text.Json;

namespace ACPScanner;

internal enum LogLevel { Info, Stage, Ok, Warn, Detected, Error, Muted }

internal sealed record LogEntry(DateTime Time, LogLevel Level, string Message);

internal enum ScanMood { Idle, Scanning, Clean, Warning, Detected }

// ─────────────────────────────────────────────────────────────────────────────
// Theme
//
// The window sits on Counter-Strike key art, so the palette is taken from it rather
// than imposed on it: warm gunmetal shadows, the amber that runs through the artwork,
// and a cold cyan reserved exclusively for the act of scanning. That contrast is the
// whole point - amber is the product, cyan is the machine looking at you.
//
// Semantic colour stays separate from chrome, so a WARNING never reads as decoration.
// ─────────────────────────────────────────────────────────────────────────────
internal static class AcpTheme
{
    public static readonly Color Bg          = Color.FromArgb(7, 9, 13);
    public static readonly Color BgLift      = Color.FromArgb(15, 19, 26);
    public static readonly Color Panel       = Color.FromArgb(18, 23, 31);
    public static readonly Color PanelEdge   = Color.FromArgb(44, 55, 68);
    public static readonly Color PanelInner  = Color.FromArgb(11, 15, 21);

    public static readonly Color Gold        = Color.FromArgb(240, 173, 58);
    public static readonly Color GoldBright  = Color.FromArgb(255, 201, 102);
    public static readonly Color GoldDim     = Color.FromArgb(120, 94, 40);
    public static readonly Color Scan        = Color.FromArgb(90, 214, 255);
    public static readonly Color ScanDim     = Color.FromArgb(40, 110, 140);

    public static readonly Color Ink         = Color.FromArgb(236, 232, 224);
    public static readonly Color Muted       = Color.FromArgb(148, 162, 176);
    public static readonly Color Faint       = Color.FromArgb(96, 108, 122);

    public static readonly Color Red         = Color.FromArgb(226, 75, 60);
    public static readonly Color RedBright   = Color.FromArgb(255, 110, 94);
    public static readonly Color Amber       = Color.FromArgb(240, 166, 58);
    public static readonly Color Green       = Color.FromArgb(79, 208, 140);

    public static (Color Color, string Tag) Style(LogLevel level) => level switch
    {
        LogLevel.Stage    => (GoldBright, ">"),
        LogLevel.Ok       => (Green,      "+"),
        LogLevel.Warn     => (Amber,      "!"),
        LogLevel.Detected => (RedBright,  "x"),
        LogLevel.Error    => (RedBright,  "x"),
        LogLevel.Muted    => (Muted,      "-"),
        _                 => (Ink,        "-")
    };

    public static void Append(RichTextBox box, LogEntry entry)
    {
        var (color, tag) = Style(entry.Level);
        AppendColored(box, $"{entry.Time:HH:mm:ss}  ", Muted);
        AppendColored(box, $"{tag}  ", color);
        AppendColored(box, entry.Message + Environment.NewLine, color);
        box.SelectionStart = box.TextLength;
        box.ScrollToCaret();
    }

    private static void AppendColored(RichTextBox box, string text, Color color)
    {
        box.SelectionStart = box.TextLength;
        box.SelectionLength = 0;
        box.SelectionColor = color;
        box.AppendText(text);
        box.SelectionColor = box.ForeColor;
    }

    public static GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        var path = new GraphicsPath();
        var d = Math.Max(2, radius * 2);
        path.AddArc(r.Left, r.Top, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static Color Fade(Color c, int alpha) => Color.FromArgb(MathUtils.Clamp(alpha, 0, 255), c);

    /// <summary>
    /// The border of a borderless window: one near-black pixel all the way round, then a
    /// barely-there highlight on the top and sides only.
    ///
    /// Two details matter. The frame used to be gold, which turned "no border" back into a
    /// bordered window in a colour. And these are filled rectangles rather than DrawRectangle
    /// under antialiasing - a 1px antialiased pen straddles two rows at half strength each,
    /// which is how a hairline becomes a visible grey band. The bottom is left out on purpose:
    /// the red accent rail lives there, and a light line beneath it read as one thick edge.
    /// </summary>
    public static void DrawWindowEdge(Graphics g, int w, int h)
    {
        var mode = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.None;

        using (var edge = new SolidBrush(Color.FromArgb(225, 3, 4, 7)))
        {
            g.FillRectangle(edge, 0, 0, w, 1);
            g.FillRectangle(edge, 0, h - 1, w, 1);
            g.FillRectangle(edge, 0, 0, 1, h);
            g.FillRectangle(edge, w - 1, 0, 1, h);
        }

        using (var lift = new SolidBrush(Color.FromArgb(15, 255, 255, 255)))
        {
            g.FillRectangle(lift, 1, 1, w - 2, 1);
            g.FillRectangle(lift, 1, 1, 1, h - 2);
            g.FillRectangle(lift, w - 2, 1, 1, h - 2);
        }

        g.SmoothingMode = mode;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fonts
//
// Resolved against what is actually installed. Bahnschrift is the condensed DIN-style
// face that ships with Windows 10/11 and carries the HUD feel with no bundled font.
// Sizes are PIXELS: the layout is pixel-authored and scaled by one factor, so type in
// points would grow independently and overflow the boxes it sits in.
// ─────────────────────────────────────────────────────────────────────────────
internal static class AcpFonts
{
    private static readonly HashSet<string> Installed = LoadInstalled();

    private static readonly string DisplayFamily = Pick(
        "Bahnschrift SemiCondensed", "Bahnschrift", "Arial Narrow", "Segoe UI Semibold", "Segoe UI");

    private static readonly string MonoFamily = Pick(
        "Consolas", "Cascadia Mono", "Lucida Console", "Courier New");

    private static HashSet<string> LoadInstalled()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var collection = new InstalledFontCollection();
            foreach (var family in collection.Families)
            {
                set.Add(family.Name);
            }
        }
        catch
        {
            // If enumeration fails the Pick fallbacks still resolve to a stock face.
        }

        return set;
    }

    private static string Pick(params string[] candidates)
    {
        foreach (var name in candidates)
        {
            if (Installed.Contains(name))
            {
                return name;
            }
        }

        return candidates[^1];
    }

    public static Font Display(float px, FontStyle style = FontStyle.Regular) =>
        new(DisplayFamily, Math.Max(6f, px), style, GraphicsUnit.Pixel);

    public static Font Mono(float px, FontStyle style = FontStyle.Regular) =>
        new(MonoFamily, Math.Max(6f, px), style, GraphicsUnit.Pixel);
}

// ─────────────────────────────────────────────────────────────────────────────
// Text
//
// Every label is drawn through here rather than through TextRenderer.
//
// TextRenderer is GDI, which renders with the system's ClearType. Subpixel rendering
// assumes it knows the colour behind the glyph, and over a photograph it does not - the
// result is coloured fringing on the stems and type that looks dirty against the art.
// GDI+ with grid-fitted grayscale antialiasing has no such assumption, so the letterforms
// stay neutral on any background.
//
// GenericTypographic is used instead of the default format because the default adds
// invisible padding around a string, which quietly breaks any layout that measures text
// and places something after it.
// ─────────────────────────────────────────────────────────────────────────────
internal static class Txt
{
    private static readonly StringFormat Flow = Build(StringAlignment.Near);
    private static readonly StringFormat Mid  = Build(StringAlignment.Center);

    // Character advances, cached per font. Tracked text used to measure every glyph on
    // every frame, which is one of the most expensive things GDI+ offers.
    private static readonly Dictionary<(Font, char), float> Advances = new();

    /// <summary>Drops cached metrics. Call whenever the font set is rebuilt.</summary>
    public static void ResetMetrics() => Advances.Clear();

    private static float Advance(Graphics g, Font font, char ch)
    {
        if (Advances.TryGetValue((font, ch), out var w))
        {
            return w;
        }

        w = g.MeasureString(ch.ToString(), font, PointF.Empty, Flow).Width;
        Advances[(font, ch)] = w;
        return w;
    }

    private static StringFormat Build(StringAlignment align)
    {
        var f = (StringFormat)StringFormat.GenericTypographic.Clone();
        f.FormatFlags |= StringFormatFlags.MeasureTrailingSpaces | StringFormatFlags.NoWrap | StringFormatFlags.NoClip;
        f.Alignment = align;
        f.LineAlignment = StringAlignment.Near;
        return f;
    }

    public static void Draw(Graphics g, string text, Font font, float x, float y, Color color)
    {
        using var brush = new SolidBrush(color);
        g.DrawString(text, font, brush, x, y, Flow);
    }

    public static float Width(Graphics g, string text, Font font) =>
        g.MeasureString(text, font, PointF.Empty, Flow).Width;

    /// <summary>Centres a single line in a box, vertically and horizontally.</summary>
    public static void DrawCentered(Graphics g, string text, Font font, RectangleF box, Color color)
    {
        using var brush = new SolidBrush(color);
        var h = font.GetHeight(g);
        g.DrawString(text, font, brush, new RectangleF(box.X, box.Y + (box.Height - h) / 2f, box.Width, h), Mid);
    }

    /// <summary>
    /// Letter-spaced small caps. GDI+ has no tracking control, so glyphs are placed one at
    /// a time. Only short labels use this - it is what makes a HUD caption read as an
    /// instrument rather than as body copy.
    /// </summary>
    public static void DrawTracked(Graphics g, string text, Font font, float x, float y, Color color, float tracking)
    {
        using var brush = new SolidBrush(color);
        var cx = x;
        foreach (var ch in text)
        {
            g.DrawString(ch.ToString(), font, brush, cx, y, Flow);
            cx += Advance(g, font, ch) + tracking;
        }
    }

    public static float TrackedWidth(Graphics g, string text, Font font, float tracking)
    {
        var w = 0f;
        foreach (var ch in text)
        {
            w += Advance(g, font, ch) + tracking;
        }
        return Math.Max(0f, w - tracking);
    }
}

/// <summary>Mark drawn to the left of a button's label. Each one names the action.</summary>
internal enum HudGlyph { None, Scan, Stop, Log, Copy, Link, Close }

// ─────────────────────────────────────────────────────────────────────────────
// Button
//
// Flat, wide-tracked, and lit from its accent. The hover state raises a soft glow
// behind the plate rather than changing the fill, so a button over the artwork never
// turns into an opaque grey slab.
//
// Each button carries a drawn mark next to its label. The three actions are not
// interchangeable - one starts a scan, one stops it, one opens evidence - and a shape
// separates them at a glance where three same-sized text plates do not.
// ─────────────────────────────────────────────────────────────────────────────
internal sealed class HudButton : Control
{
    private bool _hover;
    private bool _down;
    private float _glow;                 // eased 0..1, drives the hover bloom
    private double _phase;               // 0..1, drives the idle sheen
    private readonly System.Windows.Forms.Timer _ease = new() { Interval = 33 };
    private bool _pulse;

    // Hidden from the designer serializer: these are set in code only, and the WinForms
    // analyzer (WFO1000) requires every public control property to declare its intent.
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Color Accent { get; set; } = AcpTheme.Gold;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool Primary { get; set; }

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public float VisualScale { get; set; } = 1f;

    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public HudGlyph Glyph { get; set; } = HudGlyph.None;

    /// <summary>
    /// Sends a slow sheen across the plate while the button is enabled and idle. Set on the
    /// primary action only: it is what tells a player who has never opened this app where
    /// to start, and it stops on its own the moment the button is disabled.
    /// </summary>
    [DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public bool Pulse
    {
        get => _pulse;
        set { _pulse = value; if (value) StartEase(); }
    }

    public HudButton()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw |
                 ControlStyles.SupportsTransparentBackColor, true);
        BackColor = Color.Transparent;
        Cursor = Cursors.Hand;
        TabStop = true;

        _ease.Tick += (_, _) =>
        {
            var target = _hover && Enabled ? 1f : 0f;
            var delta = target - _glow;
            _glow = Math.Abs(delta) < 0.02f ? target : _glow + delta * 0.30f;

            var breathing = _pulse && Enabled;
            _phase = breathing ? (_phase + 0.011) % 1.0 : 0.0;

            // Only stop once the hover ease has settled AND there is no sheen to advance.
            if (Math.Abs(target - _glow) < 0.001f && !breathing)
            {
                _ease.Stop();
            }

            Invalidate();
        };
    }

    private void StartEase() { if (!_ease.Enabled && !IsDisposed) _ease.Start(); }

    protected override void OnMouseEnter(EventArgs e) { _hover = true; StartEase(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; StartEase(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); Focus(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnGotFocus(EventArgs e) { Invalidate(); base.OnGotFocus(e); }
    protected override void OnLostFocus(EventArgs e) { Invalidate(); base.OnLostFocus(e); }

    protected override void OnEnabledChanged(EventArgs e)
    {
        _hover = false;
        _glow = 0f;
        Cursor = Enabled ? Cursors.Hand : Cursors.Default;
        if (_pulse && Enabled) StartEase();
        Invalidate();
        base.OnEnabledChanged(e);
    }

    protected override bool IsInputKey(Keys keyData) => keyData is Keys.Enter or Keys.Space || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode is Keys.Enter or Keys.Space) { OnClick(EventArgs.Empty); e.Handled = true; }
        base.OnKeyDown(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _ease.Stop(); _ease.Dispose(); }
        base.Dispose(disposing);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;

        var accent = Enabled ? Accent : AcpTheme.Faint;
        var radius = (int)Math.Round(4 * VisualScale);

        // The plate is inset by a pixel so the drop shadow below it has somewhere to fall.
        var r = new Rectangle(0, 0, Width - 1, Height - 2);

        // Hover bloom sits behind the plate so the artwork stays visible through it.
        if (_glow > 0.01f)
        {
            var bloom = r;
            bloom.Inflate((int)(7 * VisualScale * _glow), (int)(6 * VisualScale * _glow));
            using var bp = AcpTheme.RoundedRect(bloom, radius + 3);
            using var bb = new PathGradientBrush(bp)
            {
                CenterColor = AcpTheme.Fade(accent, (int)(76 * _glow)),
                SurroundColors = new[] { Color.FromArgb(0, accent) }
            };
            g.FillPath(bb, bp);
        }

        // Drop shadow. One pixel of separation is the difference between a plate sitting on
        // the artwork and a rectangle cut out of it.
        if (Enabled)
        {
            var shadow = new Rectangle(r.X + 1, r.Y + 2, r.Width - 2, r.Height);
            using var sp = AcpTheme.RoundedRect(shadow, radius);
            using var sb = new SolidBrush(Color.FromArgb(70, 0, 0, 0));
            g.FillPath(sb, sp);
        }

        using var path = AcpTheme.RoundedRect(r, radius);

        // Plate: dark enough to carry text over the key art, never fully opaque.
        var top = Primary ? AcpTheme.Fade(accent, 52) : Color.FromArgb(158, 16, 20, 28);
        var bottom = Primary ? AcpTheme.Fade(accent, 20) : Color.FromArgb(178, 9, 12, 17);
        if (_hover && Enabled) { top = Primary ? AcpTheme.Fade(accent, 74) : Color.FromArgb(176, 23, 29, 39); }
        if (_down) { top = AcpTheme.Fade(accent, 86); bottom = AcpTheme.Fade(accent, 44); }
        using (var fill = new LinearGradientBrush(new Rectangle(0, 0, Math.Max(1, Width), Math.Max(1, Height)), top, bottom, 90f))
        {
            g.FillPath(fill, path);
        }

        // Idle sheen, clipped to the plate. Present for under half the cycle, so it reads as
        // an occasional glint rather than as something permanently in motion.
        if (_phase is > 0.0 and < 0.42 && !_down)
        {
            var p = (float)(_phase / 0.42);
            var band = Width * 0.42f;
            var x = -band + p * (Width + band * 2);
            var clip = g.Clip;
            g.SetClip(path, CombineMode.Intersect);
            using (var sheen = new LinearGradientBrush(
                       new RectangleF(x - band, -1, band * 2, Height + 2),
                       Color.FromArgb(0, 255, 255, 255), Color.FromArgb(Primary ? 34 : 20, 255, 255, 255), 0f))
            {
                sheen.SetBlendTriangularShape(0.5f);
                g.FillRectangle(sheen, x - band, -1, band * 2, Height + 2);
            }
            g.Clip = clip;
        }

        // Inner bevel: a light along the top edge only, the way a raised surface catches it.
        using (var bevel = new LinearGradientBrush(
                   new Rectangle(r.X, r.Y, Math.Max(1, r.Width), Math.Max(2, (int)(r.Height * 0.5f))),
                   Color.FromArgb(Primary ? 46 : 30, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 90f))
        {
            var clip = g.Clip;
            g.SetClip(path, CombineMode.Intersect);
            g.FillRectangle(bevel, r.X, r.Y, r.Width, r.Height * 0.5f);
            g.Clip = clip;
        }

        using (var pen = new Pen(AcpTheme.Fade(accent, Primary ? 215 : 108 + (int)(96 * _glow)), 1f))
        {
            g.DrawPath(pen, path);
        }

        // A lit rail along the left edge marks the primary action without a fill change.
        if (Primary && Enabled)
        {
            var railW = Math.Max(2f, 2.5f * VisualScale);
            using var rb = new LinearGradientBrush(
                new RectangleF(1.5f, r.Y + 2, railW, r.Height - 4),
                AcpTheme.Fade(accent, 255), AcpTheme.Fade(accent, 150), 90f);
            g.FillRectangle(rb, 1.5f, r.Y + 3, railW, r.Height - 6);
        }

        // Focus ring, but only once the window has been driven from the keyboard. WinForms
        // hands the first control focus on open, and a dotted rectangle around the primary
        // button before anyone has touched anything just looks like a rendering fault.
        if (Focused && Enabled && ShowFocusCues)
        {
            // A solid inset hairline, not the dotted marching rectangle Windows defaults to:
            // it says the same thing without dating the whole button by twenty years.
            var fr = r; fr.Inflate(-3, -3);
            using var fp = AcpTheme.RoundedRect(fr, Math.Max(1, radius - 1));
            using var pen = new Pen(AcpTheme.Fade(accent, 105), 1f);
            g.DrawPath(pen, fp);
        }

        var textColor = Enabled
            ? (Primary ? Color.FromArgb(255, 250, 240) : AcpTheme.Ink)
            : AcpTheme.Faint;
        var markColor = Enabled ? AcpTheme.Fade(accent, Primary ? 255 : 220) : AcpTheme.Faint;

        // Label and mark are centred as one group, so the pair stays optically balanced
        // whatever the button's width.
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        var track = Math.Max(0.6f, 1.1f * VisualScale);
        var textW = Txt.TrackedWidth(g, Text, Font, track);
        var markW = Glyph == HudGlyph.None ? 0f : Font.GetHeight(g) * 0.98f;
        var gap = Glyph == HudGlyph.None ? 0f : 7f * VisualScale;
        var startX = (Width - (markW + gap + textW)) / 2f;
        var midY = r.Y + r.Height / 2f + (_down ? 1f : 0f);

        if (Glyph != HudGlyph.None)
        {
            DrawGlyph(g, new RectangleF(startX, midY - markW / 2f, markW, markW), markColor);
        }

        Txt.DrawTracked(g, Text, Font, startX + markW + gap, midY - Font.GetHeight(g) / 2f, textColor, track);
    }

    /// <summary>The action marks. Drawn rather than shipped as glyphs so they scale cleanly.</summary>
    private void DrawGlyph(Graphics g, RectangleF box, Color color)
    {
        var w = Math.Max(1.2f, 1.4f * VisualScale);
        using var pen = new Pen(color, w) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        using var brush = new SolidBrush(color);

        switch (Glyph)
        {
            // A reticle over the target: the scan is a look, not a launch.
            case HudGlyph.Scan:
            {
                var inset = box.Width * 0.16f;
                var ring = RectangleF.Inflate(box, -inset, -inset);
                g.DrawEllipse(pen, ring);
                var cx = box.X + box.Width / 2f;
                var cy = box.Y + box.Height / 2f;
                var tick = box.Width * 0.17f;
                g.DrawLine(pen, cx, box.Y, cx, box.Y + tick);
                g.DrawLine(pen, cx, box.Bottom - tick, cx, box.Bottom);
                g.DrawLine(pen, box.X, cy, box.X + tick, cy);
                g.DrawLine(pen, box.Right - tick, cy, box.Right, cy);
                g.FillEllipse(brush, cx - w, cy - w, w * 2, w * 2);
                break;
            }

            // A stop square, the universal "this is running, end it".
            case HudGlyph.Stop:
            {
                var s = box.Width * 0.52f;
                var sq = new RectangleF(box.X + (box.Width - s) / 2f, box.Y + (box.Height - s) / 2f, s, s);
                using var sp = AcpTheme.RoundedRect(Rectangle.Round(sq), Math.Max(1, (int)VisualScale));
                g.FillPath(brush, sp);
                break;
            }

            // Ruled lines: a record of what happened.
            case HudGlyph.Log:
            {
                var rows = 3;
                var step = box.Height / (rows + 1f);
                for (var i = 1; i <= rows; i++)
                {
                    var y = box.Y + step * i;
                    var len = box.Width * (i == rows ? 0.62f : 1f);
                    g.DrawLine(pen, box.X, y, box.X + len, y);
                }
                break;
            }

            // Two sheets, one behind the other.
            case HudGlyph.Copy:
            {
                var s = box.Width * 0.66f;
                var back = new RectangleF(box.X, box.Y, s, s);
                var front = new RectangleF(box.Right - s, box.Bottom - s, s, s);
                using (var faint = new Pen(Color.FromArgb(color.A / 2, color), w))
                {
                    g.DrawRectangle(faint, back.X, back.Y, back.Width, back.Height);
                }
                g.DrawRectangle(pen, front.X, front.Y, front.Width, front.Height);
                break;
            }

            // An arrow leaving a frame: this one goes somewhere else.
            case HudGlyph.Link:
            {
                var s = box.Width * 0.72f;
                var frame = new RectangleF(box.X, box.Bottom - s, s, s);
                g.DrawLine(pen, frame.X, frame.Y + frame.Height * 0.34f, frame.X, frame.Bottom);
                g.DrawLine(pen, frame.X, frame.Bottom, frame.Right, frame.Bottom);
                g.DrawLine(pen, frame.Right, frame.Bottom, frame.Right, frame.Bottom - frame.Height * 0.34f);
                var tip = new PointF(box.Right, box.Y);
                g.DrawLine(pen, box.X + box.Width * 0.42f, box.Bottom - box.Height * 0.42f, tip.X, tip.Y);
                g.DrawLine(pen, tip.X - box.Width * 0.30f, tip.Y, tip.X, tip.Y);
                g.DrawLine(pen, tip.X, tip.Y, tip.X, tip.Y + box.Height * 0.30f);
                break;
            }

            case HudGlyph.Close:
            {
                var inset = box.Width * 0.22f;
                g.DrawLine(pen, box.X + inset, box.Y + inset, box.Right - inset, box.Bottom - inset);
                g.DrawLine(pen, box.Right - inset, box.Y + inset, box.X + inset, box.Bottom - inset);
                break;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main window
//
// Two rules shape this layout.
//
// FIXED AND SMALL. The window is authored at 980x600 and never resizes or maximises.
// On a smaller screen the whole canvas is multiplied by one scale factor - geometry and
// type together - so it fits a 1280x720 laptop without a separate layout. There is one
// coordinate system and one number that changes.
//
// THE ARTWORK IS THE INTERFACE. Everything is painted directly onto the key art in a
// single OnPaint pass, so nothing has an opaque box behind it. Only the buttons are real
// controls; every label is drawn. That is why readability comes from a gradient scrim on
// the left rather than from panels.
// ─────────────────────────────────────────────────────────────────────────────
public sealed class MainForm : Form
{
    // Authoring canvas. Every coordinate below is in these units.
    private const int BaseW = 800;
    private const int BaseH = 500;

    // DPI x fit. Not readonly: it is recomputed when the window learns its real DPI and
    // again if it is dragged to a monitor with a different one.
    private float _scale = 1f;
    private int S(float v) => (int)Math.Round(v * _scale);

    private readonly HudButton _scanButton = new();
    private readonly HudButton _cancelButton = new();
    private readonly HudButton _logButton = new();
    private readonly ToolTip _tips = new();

    private CancellationTokenSource? _scanCancellation;
    private readonly Stopwatch _elapsed = new();
    private readonly List<LogEntry> _logEntries = new();
    private LogForm? _logForm;
    private string _lastReportUrl = "";

    // Painted state. Held as plain fields because there are no label controls to update.
    private string _verdict = "READY";
    private Color _verdictColor = AcpTheme.GoldBright;
    private string _verdictNote = "LAUNCH COUNTER-STRIKE, THEN START THE SCAN";
    private string _status = "Waiting to start";
    private string _stage = "IDLE";
    private int _progress;
    private int _detected;
    private int _warnings;
    private ScanMood _mood = ScanMood.Idle;
    private string _moodState = "STANDBY";

    private readonly Image? _hero;

    // The photograph, its scrim and the scanline texture never change between frames, but
    // redrawing them meant a bicubic DrawImage, four gradient fills and 180-odd lines on
    // every tick. At PerMonitorV2 that pushed a single paint past the frame interval, so
    // the message queue stopped draining. They are composited once per size instead.
    private Bitmap? _backdrop;

    // The LongHorn mark. Stored white with the silhouette in the alpha channel, so it can
    // be tinted to whatever the interface needs rather than baked to one colour.
    private readonly Image? _logo;
    private Icon? _appIcon;

    // The footer credit is a link, so it needs a hit target and a hover state.
    private Rectangle _poweredRect;
    private bool _poweredHot;
    private const string BrandUrl = "https://www.cslonghorn.com";

    // In-app update check state
    private bool _updateAvailable;
    private string _latestVersion = "";
    private Rectangle _updateRect;
    private bool _updateHot;
    private const string DownloadUrl = "https://cslonghorn.com/acs/download.php";

    private readonly System.Windows.Forms.Timer _fx = new() { Interval = 40 };
    private double _t;                  // master animation clock, seconds
    private float _verdictFade = 1f;    // 0..1, eases in on every verdict change

    // Rotating hints. The app is used once in a while, so it explains itself instead of
    // assuming the player remembers.
    private static readonly string[] Hints =
    {
        "Counter-Strike must be running before you scan.",
        "Stay joined to your match server while scanning for admin verification.",
        "The report link opens in your browser and can be shared with an admin.",
        "A clean result is useful evidence you can hand to a server admin.",
        "Scanning reads your game's files and memory. Nothing is changed.",
        "Press ESC to cancel a scan in progress."
    };
    private int _hintIndex;
    private double _hintAt;

    // Title-bar hit targets, filled during paint and tested on click.
    private Rectangle _closeRect, _minRect;
    private bool _closeHot, _minHot;
    private Point _dragFrom;
    private bool _dragging;

    private Font _fTitle = null!, _fEyebrow = null!, _fVerdict = null!, _fNote = null!;
    private Font _fStatNum = null!, _fStatCap = null!, _fMono = null!, _fMonoSm = null!;
    private Font _fIrisNum = null!, _fIrisCap = null!, _fHint = null!, _fIrisPct = null!;
    private Font _fPowered = null!, _fBrand = null!;

    // Sized to the current mood word rather than fixed; rebuilt when the word or scale changes.
    private Font? _irisWordFont;
    private string _irisWordKey = "";

    public MainForm()
    {
        Text = "ACS — Anti-Cheat Scanner · Counter-Strike 1.6";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.None;   // custom chrome; no resize, no maximise
        MaximizeBox = false;
        MinimizeBox = true;
        AutoScaleMode = AutoScaleMode.None;   // the one scale factor below does this job
        ClientSize = new Size(BaseW, BaseH);  // provisional; ApplyScale sets the real size
        DoubleBuffered = true;
        BackColor = AcpTheme.Bg;
        ForeColor = AcpTheme.Ink;
        KeyPreview = true;

        _hero = LoadAsset("acs-hero.png");
        _logo = LoadAsset("acs-logo.png");
        _appIcon = BuildAppIcon();
        if (_appIcon is not null)
        {
            Icon = _appIcon;
            ShowIcon = true;
        }
        BuildButtons();
        ApplyScale();

        _tips.OwnerDraw = false;
        _tips.InitialDelay = 350;
        _tips.ReshowDelay = 120;
        _tips.SetToolTip(_scanButton, "Scan the running Counter-Strike process and upload the report");
        _tips.SetToolTip(_cancelButton, "Stop the scan in progress (ESC)");
        _tips.SetToolTip(_logButton, "Open the evidence log and copy the report link");

        AppendLog(LogLevel.Muted, "ACS evidence engine ready. Launch Counter-Strike 1.6 and join your match server, then press SCAN.");

        _fx.Tick += (_, _) =>
        {
            if (WindowState == FormWindowState.Minimized) return;
            _t += _fx.Interval / 1000.0;
            if (_verdictFade < 1f) _verdictFade = Math.Min(1f, _verdictFade + 0.08f);
            if (_t - _hintAt > 7.0) { _hintAt = _t; _hintIndex = (_hintIndex + 1) % Hints.Length; }
            Invalidate();
        };
        _fx.Start();
        _ = CheckForUpdatesAsync();
    }

    /// <summary>
    /// Recomputes the single scale factor and re-lays the window out.
    ///
    /// Two multipliers combine. The display's DPI keeps the window the same *physical* size
    /// on any monitor while drawing at that monitor's true pixel density - that is the whole
    /// reason the type is sharp instead of being bitmap-stretched by Windows, which is what
    /// a DPI-unaware window gets and why it looked soft. The fit factor then shrinks the
    /// window if the screen is genuinely too small to hold it.
    /// </summary>
    private bool _applyingScale;

    private void ApplyScale()
    {
        // Re-entrancy guard. Setting ClientSize under PerMonitorV2 can make WinForms
        // recreate the window handle, which fires OnHandleCreated, which lands back here.
        // Without this the two bounce off each other and the window never finishes opening.
        if (_applyingScale)
        {
            return;
        }

        var dpi = DeviceDpi / 96f;
        var screen = (IsHandleCreated ? Screen.FromControl(this) : Screen.PrimaryScreen);
        var work = screen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);

        var fit = Math.Min((work.Width - 60f) / (BaseW * dpi), (work.Height - 60f) / (BaseH * dpi));
        var next = dpi * MathUtils.Clamp(fit, 0.62f, 1.0f);
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
            LayoutButtons();
            RebuildBackdrop();
            Invalidate();
        }
        finally
        {
            _applyingScale = false;
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        ApplyScale();   // DeviceDpi only means anything once there is a window
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        ApplyScale();   // dragged to a monitor with a different density
    }

    private void DisposeFonts()
    {
        foreach (var f in new[] { _fTitle, _fEyebrow, _fVerdict, _fNote, _fStatNum,
                                  _fStatCap, _fMono, _fMonoSm, _fIrisNum, _fIrisCap, _fHint,
                                  _fIrisPct, _fPowered, _fBrand, _irisWordFont })
        {
            f?.Dispose();
        }

        // Forces the fitted word font to be measured again at the new scale.
        _irisWordFont = null;
        _irisWordKey = "";
    }

    /// <summary>Composites the unchanging layers into an off-screen bitmap.</summary>
    private void RebuildBackdrop()
    {
        _backdrop?.Dispose();
        _backdrop = null;

        var w = ClientSize.Width;
        var h = ClientSize.Height;
        if (w <= 0 || h <= 0)
        {
            return;
        }

        var bmp = new Bitmap(w, h);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
            g.CompositingQuality = CompositingQuality.HighQuality;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            DrawHero(g, w, h);
            DrawScrim(g, w, h);
        }
        _backdrop = bmp;
    }

    private void BuildFonts()
    {
        DisposeFonts();
        Txt.ResetMetrics();
        _fTitle   = AcpFonts.Mono(S(11), FontStyle.Bold);
        _fEyebrow = AcpFonts.Mono(S(10), FontStyle.Bold);
        _fVerdict = AcpFonts.Display(S(42), FontStyle.Bold);
        _fNote    = AcpFonts.Mono(S(10));
        _fStatNum = AcpFonts.Display(S(21), FontStyle.Bold);
        _fStatCap = AcpFonts.Mono(S(9), FontStyle.Bold);
        _fMono    = AcpFonts.Mono(S(11));
        _fMonoSm  = AcpFonts.Mono(S(10), FontStyle.Bold);
        _fIrisNum = AcpFonts.Display(S(32), FontStyle.Bold);
        _fIrisCap = AcpFonts.Mono(S(9), FontStyle.Bold);
        _fIrisPct = AcpFonts.Display(S(15), FontStyle.Bold);
        _fPowered = AcpFonts.Display(S(11));
        _fBrand   = AcpFonts.Display(S(12), FontStyle.Bold);
        _fHint    = AcpFonts.Display(S(12));
    }

    /// <summary>
    /// Artwork compiled into the executable, so the app ships as one file with no Assets
    /// folder to lose or forget to copy.
    /// </summary>
    private static Image? LoadAsset(string fileName)
    {
        try
        {
            using var stream = typeof(MainForm).Assembly.GetManifestResourceStream("ACS.Assets." + fileName);
            if (stream is not null)
            {
                // Copied to memory: GDI+ needs its source stream alive for the image's lifetime.
                var buffer = new MemoryStream();
                stream.CopyTo(buffer);
                buffer.Position = 0;
                return Image.FromStream(buffer);
            }
        }
        catch
        {
            // A missing or corrupt asset must never stop the scanner from running. Every
            // caller has a drawn fallback.
        }
        return null;
    }

    /// <summary>
    /// Draws a white-with-alpha image in a flat colour. The mark ships as coverage in the
    /// alpha channel, so one file serves the title bar, the window icon and any future
    /// placement without a separate export per colour.
    /// </summary>
    private static void DrawTinted(Graphics g, Image image, Rectangle dest, Color tint)
    {
        var matrix = new ColorMatrix(new[]
        {
            new[] { 0f, 0f, 0f, 0f, 0f },
            new[] { 0f, 0f, 0f, 0f, 0f },
            new[] { 0f, 0f, 0f, 0f, 0f },
            new[] { 0f, 0f, 0f, tint.A / 255f, 0f },
            new[] { tint.R / 255f, tint.G / 255f, tint.B / 255f, 0f, 1f }
        });

        using var attributes = new ImageAttributes();
        attributes.SetColorMatrix(matrix);
        g.DrawImage(image, dest, 0, 0, image.Width, image.Height, GraphicsUnit.Pixel, attributes);
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    /// <summary>Builds the taskbar / window icon from the mark.</summary>
    private Icon? BuildAppIcon()
    {
        if (_logo is null)
        {
            return null;
        }

        try
        {
            const int size = 256;
            using var square = new Bitmap(size, size, PixelFormat.Format32bppArgb);
            using (var g = Graphics.FromImage(square))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;

                var scale = Math.Min(size / (float)_logo.Width, size / (float)_logo.Height) * 0.88f;
                var dw = (int)(_logo.Width * scale);
                var dh = (int)(_logo.Height * scale);
                DrawTinted(g, _logo, new Rectangle((size - dw) / 2, (size - dh) / 2, dw, dh), AcpTheme.Gold);
            }

            // FromHandle does not own the handle, so it is cloned and the original freed.
            var handle = square.GetHicon();
            try
            {
                using var temp = Icon.FromHandle(handle);
                return (Icon)temp.Clone();
            }
            finally
            {
                DestroyIcon(handle);
            }
        }
        catch
        {
            return null;   // the stock window icon is a fine fallback
        }
    }

    private void BuildButtons()
    {
        _scanButton.Text = "START SCAN";
        _scanButton.Primary = true;
        _scanButton.Accent = AcpTheme.Gold;
        _scanButton.Glyph = HudGlyph.Scan;
        _scanButton.Pulse = true;   // the one action to take on an empty screen
        _scanButton.Click += async (_, _) => await RunScanAsync();

        _cancelButton.Text = "CANCEL";
        _cancelButton.Accent = AcpTheme.Muted;
        _cancelButton.Glyph = HudGlyph.Stop;
        _cancelButton.Enabled = false;
        _cancelButton.Click += (_, _) => _scanCancellation?.Cancel();

        // "Evidence log" named what the window contained. This names what pressing it does,
        // which is the same wording the other two buttons use.
        _logButton.Text = "VIEW EVIDENCE";
        _logButton.Accent = AcpTheme.Scan;
        _logButton.Glyph = HudGlyph.Log;
        _logButton.Click += (_, _) => OpenLogWindow();

        Controls.Add(_scanButton);
        Controls.Add(_cancelButton);
        Controls.Add(_logButton);
    }

    /// <summary>Positions and re-fonts the buttons for the current scale.</summary>
    private void LayoutButtons()
    {
        void Apply(HudButton b, int px, int x, int y, int w, int h)
        {
            var old = b.Font;
            b.VisualScale = _scale;
            b.Font = AcpFonts.Mono(S(px), FontStyle.Bold);
            b.Bounds = new Rectangle(S(x), S(y), S(w), S(h));
            if (old is not null && !ReferenceEquals(old, Font)) old.Dispose();
        }

        // The row has to stay clear of the iris viewfinder brackets, which reach further
        // left now that the window is narrower.
        Apply(_scanButton,   11,  36, 394, 142, 38);
        Apply(_cancelButton, 10, 186, 394,  88, 38);
        Apply(_logButton,    10, 282, 394, 128, 38);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Escape && _scanCancellation is not null)
        {
            _scanCancellation.Cancel();
            e.Handled = true;
        }
        base.OnKeyDown(e);
    }

    // ── Window chrome: drag, minimise, close ─────────────────────────────────

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            if (_closeRect.Contains(e.Location)) { Close(); return; }
            if (_minRect.Contains(e.Location)) { WindowState = FormWindowState.Minimized; return; }
            if (_updateAvailable && _updateRect.Contains(e.Location)) { BrowserLink.Open(DownloadUrl); return; }
            if (_poweredRect.Contains(e.Location)) { OpenBrandSite(); return; }
            if (e.Y <= S(42)) { _dragging = true; _dragFrom = e.Location; }
        }
        base.OnMouseDown(e);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_dragging)
        {
            Location = new Point(Location.X + e.X - _dragFrom.X, Location.Y + e.Y - _dragFrom.Y);
        }
        else
        {
            var c = _closeRect.Contains(e.Location);
            var m = _minRect.Contains(e.Location);
            var pw = _poweredRect.Contains(e.Location);
            var u = _updateAvailable && _updateRect.Contains(e.Location);
            if (c != _closeHot || m != _minHot || pw != _poweredHot || u != _updateHot)
            {
                _closeHot = c;
                _minHot = m;
                _poweredHot = pw;
                _updateHot = u;
                Cursor = (pw || u) ? Cursors.Hand : Cursors.Default;
                Invalidate();
            }
        }
        base.OnMouseMove(e);
    }

    protected override void OnMouseUp(MouseEventArgs e) { _dragging = false; base.OnMouseUp(e); }

    private static void OpenBrandSite()
    {
        // Not elevated: the app runs as administrator, the browser must not (see BrowserLink).
        BrowserLink.Open(BrandUrl);
    }

    // ── Painting ─────────────────────────────────────────────────────────────

    protected override void OnPaintBackground(PaintEventArgs e)
    {
        // Suppressed: OnPaint covers every pixel, and letting WinForms clear first
        // produces a visible flash behind the artwork.
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.CompositingQuality = CompositingQuality.HighQuality;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;

        var w = ClientSize.Width;
        var h = ClientSize.Height;

        if (_backdrop is not null)
        {
            g.DrawImageUnscaled(_backdrop, 0, 0);
        }
        else
        {
            DrawHero(g, w, h);
            DrawScrim(g, w, h);
        }

        DrawIris(g);
        DrawChrome(g, w, h);
        DrawLeftColumn(g);
        DrawHintBar(g, w, h);

        DrawBottomAccent(g, w, h);

        AcpTheme.DrawWindowEdge(g, w, h);
    }

    /// <summary>
    /// Paints the key art into the right-hand third only.
    ///
    /// The source file is a screenshot of the Counter-Strike site, so it carries the page's
    /// own typography - the CS2 wordmark, the About paragraph, the top nav. Cover-fitting
    /// the whole frame put all of that straight underneath this window's copy, two sets of
    /// headlines fighting in the same space.
    ///
    /// So the artwork is cropped to the figure alone (x >= 469 clears the wordmark, y >= 55
    /// clears the nav) and drawn only where there is no interface. The crop keeps the source
    /// aspect ratio, so nothing is stretched, and its left edge is feathered into the base
    /// gradient so there is no seam.
    /// </summary>
    private void DrawHero(Graphics g, int w, int h)
    {
        using (var baseFill = new LinearGradientBrush(new Rectangle(0, 0, w, h),
                   Color.FromArgb(20, 17, 15), Color.FromArgb(5, 7, 11), 55f))
        {
            g.FillRectangle(baseFill, 0, 0, w, h);
        }

        if (_hero is null)
        {
            return;     // the gradient alone is a complete, if plainer, background
        }

        var artX = (int)(w * 0.34f);
        var artW = w - artX;
        var dest = new Rectangle(artX, 0, artW, h);

        // The whole frame is usable. The earlier version cropped to the right-hand third
        // because the source was a screenshot of the Counter-Strike site and the left of it
        // carried the page's own headline and body copy; the artwork proper has no such
        // problem, so nothing has to be thrown away to keep the type legible.
        var availX = 0f;
        var availY = 0f;
        var availW = (float)_hero.Width;
        var availH = (float)_hero.Height;

        // Fit the destination's aspect ratio inside that region without stretching. Width is
        // usually the binding constraint, so try it first and fall back to height.
        var destRatio = (float)artW / h;
        var srcW = availW;
        var srcH = srcW / destRatio;
        if (srcH > availH)
        {
            srcH = availH;
            srcW = srcH * destRatio;
        }

        // Anchor toward the figure, who stands right of centre, and bias upward so his head
        // stays in frame rather than the crop settling on his chest.
        var srcX = availX + (availW - srcW) * 0.80f;
        var srcY = availY + (availH - srcH) * 0.30f;

        g.DrawImage(_hero, dest, srcX, srcY, srcW, srcH, GraphicsUnit.Pixel);

        // Feather the inner edge so the art dissolves into the panel rather than butting it.
        var feather = (int)(artW * 0.12f);
        using var blend = new LinearGradientBrush(
            new Rectangle(artX, 0, feather, h),
            Color.FromArgb(255, 8, 9, 13), Color.FromArgb(0, 8, 9, 13), 0f);
        g.FillRectangle(blend, artX, 0, feather, h);
    }

    /// <summary>Darkening so painted type stays legible on a busy photograph.</summary>
    private void DrawScrim(Graphics g, int w, int h)
    {
        // DrawHero already feathers the art into the panel, so this only has to take the
        // last of the contrast out from under the copy column.
        using (var left = new LinearGradientBrush(new Rectangle(0, 0, (int)(w * 0.52f), h),
                   Color.FromArgb(185, 5, 7, 11), Color.FromArgb(0, 5, 7, 11), 0f))
        {
            g.FillRectangle(left, 0, 0, (int)(w * 0.52f), h);
        }

        // Global knock-down keeps the art from competing with the iris.
        using (var flat = new SolidBrush(Color.FromArgb(48, 4, 6, 10)))
        {
            g.FillRectangle(flat, 0, 0, w, h);
        }

        // Vignette.
        using (var path = new GraphicsPath())
        {
            path.AddEllipse(-w * 0.25f, -h * 0.35f, w * 1.5f, h * 1.7f);
            using var vig = new PathGradientBrush(path)
            {
                CenterColor = Color.FromArgb(0, 0, 0, 0),
                SurroundColors = new[] { Color.FromArgb(190, 2, 3, 6) }
            };
            g.FillRectangle(vig, 0, 0, w, h);
        }

        // Top and bottom bands anchor the chrome.
        using (var topBand = new LinearGradientBrush(new Rectangle(0, 0, w, S(72)),
                   Color.FromArgb(225, 4, 6, 10), Color.FromArgb(0, 4, 6, 10), 90f))
        {
            g.FillRectangle(topBand, 0, 0, w, S(72));
        }
        using (var botBand = new LinearGradientBrush(new Rectangle(0, h - S(70), w, S(70)),
                   Color.FromArgb(0, 4, 6, 10), Color.FromArgb(232, 4, 6, 10), 90f))
        {
            g.FillRectangle(botBand, 0, h - S(70), w, S(70));
        }
    }

    private Color MoodColor => _mood switch
    {
        ScanMood.Detected => AcpTheme.RedBright,
        ScanMood.Warning  => AcpTheme.Amber,
        ScanMood.Clean    => AcpTheme.Green,
        ScanMood.Scanning => AcpTheme.Scan,
        _                 => AcpTheme.Gold
    };

    /// <summary>
    /// The iris. Concentric rings that rotate at different rates and directions, a
    /// progress arc on the outside, and a sweep line that crosses the pupil while work is
    /// happening. It is the one place motion is allowed, and every moving part reports
    /// something: the arc is progress, the sweep means busy, the colour is the verdict.
    /// </summary>
    private void DrawIris(Graphics g)
    {
        // Held at the same fraction of the width as before, and the radius trimmed with it -
        // a narrower window with the same iris in it reads as a crowded one.
        var cx = (float)S(578);
        var cy = (float)S(262);
        var r  = (float)S(118);
        var accent = MoodColor;
        var busy = _mood == ScanMood.Scanning;
        var spin = busy ? 1.0 : 0.22;          // idle still breathes, just slowly

        var old = g.Clip;

        // Soft bloom behind the whole assembly so it sits on the art rather than over it.
        using (var glowPath = new GraphicsPath())
        {
            glowPath.AddEllipse(cx - r * 1.35f, cy - r * 1.35f, r * 2.7f, r * 2.7f);
            using var glow = new PathGradientBrush(glowPath)
            {
                CenterColor = AcpTheme.Fade(accent, busy ? 46 : 26),
                SurroundColors = new[] { Color.FromArgb(0, accent) }
            };
            g.FillPath(glow, glowPath);
        }

        // Outer hairline + tick ring.
        using (var pen = new Pen(AcpTheme.Fade(accent, 60), 1f))
        {
            g.DrawEllipse(pen, cx - r, cy - r, r * 2, r * 2);
        }

        using (var majorTick = new Pen(AcpTheme.Fade(accent, 150), 1.6f))
        using (var minorTick = new Pen(AcpTheme.Fade(accent, 60), 1f))
        {
            for (var i = 0; i < 72; i++)
            {
                var a = i * (Math.PI * 2 / 72);
                var major = i % 6 == 0;
                var inner = major ? r * 0.90f : r * 0.955f;
                var cos = (float)Math.Cos(a);
                var sin = (float)Math.Sin(a);
                g.DrawLine(major ? majorTick : minorTick,
                    cx + cos * inner, cy + sin * inner,
                    cx + cos * r * 0.99f, cy + sin * r * 0.99f);
            }
        }

        // Rotating dashed ring (clockwise) and a counter-rotating inner ring.
        DrawArcRing(g, cx, cy, r * 0.845f, accent, 120, 2.2f, _t * 42 * spin, new[] { 0f, 90f, 180f, 270f }, 54f);
        DrawArcRing(g, cx, cy, r * 0.70f, accent, 80, 1.4f, -_t * 28 * spin, new[] { 30f, 210f }, 88f);

        // Progress arc: the outermost bright element, so completion reads at a glance.
        if (_progress > 0)
        {
            var sweep = 360f * MathUtils.Clamp(_progress, 0, 100) / 100f;
            var rect = new RectangleF(cx - r * 0.925f, cy - r * 0.925f, r * 1.85f, r * 1.85f);
            using (var halo = new Pen(AcpTheme.Fade(accent, 55), S(7f)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawArc(halo, rect, -90f, sweep);
            }
            using var arc = new Pen(AcpTheme.Fade(accent, 245), S(2.6f)) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            g.DrawArc(arc, rect, -90f, sweep);
        }

        // Pupil: a dark well with a radial lift, so the number sits on something.
        var pupil = r * 0.56f;
        using (var pupilPath = new GraphicsPath())
        {
            pupilPath.AddEllipse(cx - pupil, cy - pupil, pupil * 2, pupil * 2);
            using var fill = new PathGradientBrush(pupilPath)
            {
                CenterColor = Color.FromArgb(205, 6, 9, 14),
                SurroundColors = new[] { Color.FromArgb(120, 6, 9, 14) }
            };
            g.FillPath(fill, pupilPath);

            // Sweep line, clipped to the pupil. Travels top to bottom on a loop.
            if (busy)
            {
                g.SetClip(pupilPath);
                var phase = (float)((_t * 0.55) % 1.0);
                var y = cy - pupil + phase * pupil * 2;
                using (var band = new LinearGradientBrush(
                           new RectangleF(cx - pupil, y - S(20), pupil * 2, S(40)),
                           Color.FromArgb(0, accent), AcpTheme.Fade(accent, 70), 90f))
                {
                    g.FillRectangle(band, cx - pupil, y - S(20), pupil * 2, S(20));
                }
                using (var line = new Pen(AcpTheme.Fade(accent, 210), 1.4f))
                {
                    g.DrawLine(line, cx - pupil, y, cx + pupil, y);
                }
                g.Clip = old;
            }

            using var ring = new Pen(AcpTheme.Fade(accent, 90), 1f);
            g.DrawEllipse(ring, cx - pupil, cy - pupil, pupil * 2, pupil * 2);
        }

        // Readout.
        using var centred = new StringFormat
        {
            Alignment = StringAlignment.Center,
            LineAlignment = StringAlignment.Center,
            // The pupil is a circle: a second line has nowhere to go and gets clipped by
            // it. Anything too wide is shrunk to fit instead (see IrisWordFont).
            FormatFlags = StringFormatFlags.NoWrap
        };

        var showPercent = busy || _progress is > 0 and < 100;
        var headline = showPercent ? $"{_progress}" : _moodState;
        var headlineFont = showPercent ? _fIrisNum : IrisWordFont(g, headline, pupil * 1.62f);

        using (var brush = new SolidBrush(AcpTheme.Fade(accent, 250)))
        {
            g.DrawString(headline, headlineFont, brush,
                new RectangleF(cx - pupil, cy - S(26), pupil * 2, S(46)), centred);
        }
        if (showPercent)
        {
            using var pct = new SolidBrush(AcpTheme.Fade(accent, 150));
            g.DrawString("%", _fIrisPct, pct,
                new RectangleF(cx - pupil, cy + S(12), pupil * 2, S(20)), centred);
        }

        using (var cap = new SolidBrush(AcpTheme.Fade(AcpTheme.Ink, 120)))
        {
            g.DrawString(showPercent ? _moodState : "INTEGRITY SCAN", _fIrisCap, cap,
                new RectangleF(cx - pupil, cy + S(34), pupil * 2, S(16)), centred);
        }

        // Corner brackets frame the assembly like a viewfinder.
        DrawBrackets(g, cx, cy, r * 1.16f, accent);
    }

    /// <summary>
    /// The mood word, sized to fit across the pupil.
    ///
    /// The states vary in length and the longest of them overflowed a fixed 26px: it wrapped
    /// onto a second line, which a circular pupil then clipped in half. Shrinking to fit
    /// keeps one line whatever the word. Cached, because it only changes when the word does
    /// and this is called on every frame.
    /// </summary>
    private Font IrisWordFont(Graphics g, string text, float maxWidth)
    {
        if (_irisWordFont is not null && _irisWordKey == text)
        {
            return _irisWordFont;
        }

        _irisWordFont?.Dispose();

        var basePx = (float)S(26);
        var probe = AcpFonts.Display(basePx, FontStyle.Bold);
        var width = Txt.Width(g, text, probe);

        if (width <= maxWidth)
        {
            _irisWordFont = probe;
        }
        else
        {
            probe.Dispose();
            _irisWordFont = AcpFonts.Display(Math.Max(S(10), basePx * maxWidth / width), FontStyle.Bold);
        }

        _irisWordKey = text;
        return _irisWordFont;
    }

    private void DrawArcRing(Graphics g, float cx, float cy, float radius, Color accent,
                             int alpha, float width, double rotation, float[] starts, float sweep)
    {
        var rect = new RectangleF(cx - radius, cy - radius, radius * 2, radius * 2);
        using var pen = new Pen(AcpTheme.Fade(accent, alpha), S(width)) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        foreach (var start in starts)
        {
            g.DrawArc(pen, rect, (float)(start + rotation), sweep);
        }
    }

    private void DrawBrackets(Graphics g, float cx, float cy, float d, Color accent)
    {
        var len = S(16f);
        using var pen = new Pen(AcpTheme.Fade(accent, 130), 1.5f);
        foreach (var (sx, sy) in new[] { (-1, -1), (1, -1), (-1, 1), (1, 1) })
        {
            var x = cx + sx * d;
            var y = cy + sy * d;
            g.DrawLine(pen, x, y, x - sx * len, y);
            g.DrawLine(pen, x, y, x, y - sy * len);
        }
    }

    /// <summary>Custom title bar: mark, wordmark, and the two window buttons.</summary>
    private void DrawChrome(Graphics g, int w, int h)
    {
        var barH = S(42);

        // The LongHorn mark, same silhouette as the site.
        var mx = S(26f);
        var my = barH / 2f;
        if (_logo is not null)
        {
            var mh = S(26);
            var mw = (int)Math.Round(mh * (_logo.Width / (float)_logo.Height));
            DrawTinted(g, _logo, new Rectangle((int)(mx - mw / 2f), (int)(my - mh / 2f), mw, mh), AcpTheme.Gold);
        }
        else
        {
            var rad = S(10f);
            using var pen = new Pen(AcpTheme.Gold, 1.6f);
            g.DrawEllipse(pen, mx - rad, my - rad, rad * 2, rad * 2);
            g.DrawLine(pen, mx - rad - S(4), my, mx - rad + S(3), my);
            g.DrawLine(pen, mx + rad - S(3), my, mx + rad + S(4), my);
        }

        var wordX = (float)S(50);
        var track = S(1.0f);
        Txt.DrawTracked(g, "ACS", _fTitle, wordX, my - S(12), AcpTheme.Ink, track);
        var acsW = Txt.TrackedWidth(g, "ACS", _fTitle, track);
        Txt.DrawTracked(g, "ANTI-CHEAT SCANNER", _fEyebrow, wordX + acsW + S(8), my - S(11),
            AcpTheme.Faint, S(1f));
        Txt.DrawTracked(g, "COUNTER-STRIKE 1.6", _fEyebrow, wordX, my + S(2),
            AcpTheme.Fade(AcpTheme.Gold, 180), S(1f));

        // Live state pill, right of the wordmark.
        var pill = new Rectangle(S(214), (int)(my - S(9)), S(116), S(19));
        using (var path = AcpTheme.RoundedRect(pill, S(10)))
        using (var fill = new SolidBrush(Color.FromArgb(120, 8, 11, 16)))
        using (var pen = new Pen(AcpTheme.Fade(MoodColor, 90), 1f))
        {
            g.FillPath(fill, path);
            g.DrawPath(pen, path);
        }
        var pulse = (float)(0.55 + 0.45 * Math.Sin(_t * (_mood == ScanMood.Scanning ? 6.0 : 1.6)));
        using (var dot = new SolidBrush(AcpTheme.Fade(MoodColor, (int)(120 + 135 * pulse))))
        {
            g.FillEllipse(dot, pill.X + S(9), pill.Y + S(7), S(6), S(6));
        }
        var pillText = _scanCancellation is null ? _moodState : $"SCANNING {_elapsed.Elapsed:mm\\:ss}";
        Txt.DrawCentered(g, pillText, _fMonoSm,
            new RectangleF(pill.X + S(15), pill.Y, pill.Width - S(19), pill.Height),
            AcpTheme.Fade(MoodColor, 235));

        if (_updateAvailable)
        {
            var badgeX = pill.Right + S(10);
            var badgeW = S(135);
            var badgeH = S(19);
            _updateRect = new Rectangle(badgeX, (int)(my - S(9)), badgeW, badgeH);

            using (var path = AcpTheme.RoundedRect(_updateRect, S(10)))
            using (var fill = new SolidBrush(_updateHot ? Color.FromArgb(200, 48, 36, 12) : Color.FromArgb(140, 30, 22, 10)))
            using (var pen = new Pen(_updateHot ? AcpTheme.GoldBright : AcpTheme.GoldDim, 1f))
            {
                g.FillPath(fill, path);
                g.DrawPath(pen, path);
            }

            var upPulse = (float)(0.6 + 0.4 * Math.Sin(_t * 3.5));
            using (var dot = new SolidBrush(AcpTheme.Fade(AcpTheme.GoldBright, (int)(150 + 105 * upPulse))))
            {
                g.FillEllipse(dot, _updateRect.X + S(8), _updateRect.Y + S(6), S(6), S(6));
            }

            Txt.DrawCentered(g, $"UPDATE: v{_latestVersion}", _fMonoSm,
                new RectangleF(_updateRect.X + S(15), _updateRect.Y, _updateRect.Width - S(17), _updateRect.Height),
                _updateHot ? AcpTheme.GoldBright : AcpTheme.Gold);
        }
        else
        {
            _updateRect = Rectangle.Empty;
        }

        // Window buttons.
        var btn = S(30);
        _closeRect = new Rectangle(w - btn - S(6), S(6), btn, btn);
        _minRect   = new Rectangle(w - btn * 2 - S(8), S(6), btn, btn);

        if (_minHot)
        {
            using var hb = new SolidBrush(Color.FromArgb(40, 255, 255, 255));
            g.FillRectangle(hb, _minRect);
        }
        if (_closeHot)
        {
            using var hb = new SolidBrush(Color.FromArgb(180, 200, 50, 45));
            g.FillRectangle(hb, _closeRect);
        }

        using (var pen = new Pen(_minHot ? AcpTheme.Ink : AcpTheme.Muted, 1.4f))
        {
            var c = new Point(_minRect.X + _minRect.Width / 2, _minRect.Y + _minRect.Height / 2);
            g.DrawLine(pen, c.X - S(6), c.Y + S(4), c.X + S(6), c.Y + S(4));
        }
        using (var pen = new Pen(_closeHot ? Color.White : AcpTheme.Muted, 1.4f))
        {
            var c = new Point(_closeRect.X + _closeRect.Width / 2, _closeRect.Y + _closeRect.Height / 2);
            g.DrawLine(pen, c.X - S(6), c.Y - S(6), c.X + S(6), c.Y + S(6));
            g.DrawLine(pen, c.X + S(6), c.Y - S(6), c.X - S(6), c.Y + S(6));
        }

        // Separator under the title bar. Neutral white at very low alpha rather than gold:
        // it has to divide the bar from the body, not colour the window.
        using var rule = new LinearGradientBrush(new Rectangle(0, barH, w, 1),
            Color.FromArgb(30, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), 0f);
        g.FillRectangle(rule, 0, barH, w, 1);
    }

    private void DrawLeftColumn(Graphics g)
    {
        var x = (float)S(36);

        Txt.DrawTracked(g, "EVIDENCE SCANNER", _fEyebrow, x, S(84),
            AcpTheme.Fade(AcpTheme.Gold, 210), S(1.1f));

        // Verdict, eased in on change so a result never just snaps into place.
        var vc = AcpTheme.Fade(_verdictColor, (int)(255 * _verdictFade));
        var lift = (int)((1f - _verdictFade) * S(8));
        g.TextRenderingHint = TextRenderingHint.AntiAlias;
        Txt.Draw(g, _verdict, _fVerdict, x, S(98) + lift, vc);
        g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;

        Txt.DrawTracked(g, _verdictNote, _fNote, x, S(150),
            AcpTheme.Fade(_verdictColor, (int)(155 * _verdictFade)), S(0.5f));

        // Counters.
        DrawStat(g, x,          S(180), _detected.ToString(), "CHEATS",   _detected > 0 ? AcpTheme.RedBright : AcpTheme.Ink);
        DrawStat(g, x + S(100), S(180), _warnings.ToString(), "WARNINGS", _warnings > 0 ? AcpTheme.Amber : AcpTheme.Ink);
        DrawStat(g, x + S(200), S(180), _elapsed.Elapsed.ToString(@"mm\:ss"), "ELAPSED", AcpTheme.Ink);

        // Stage + progress.
        Txt.DrawTracked(g, _stage, _fMonoSm, x, S(250), AcpTheme.Fade(MoodColor, 215), S(0.8f));

        var bar = new Rectangle((int)x, S(272), S(250), S(4));
        using (var track = new SolidBrush(Color.FromArgb(120, 255, 255, 255)))
        {
            g.FillRectangle(track, bar.X, bar.Y, bar.Width, 1);
        }
        var fillW = (int)(bar.Width * MathUtils.Clamp(_progress, 0, 100) / 100f);
        if (fillW > 0)
        {
            using var fill = new LinearGradientBrush(
                new Rectangle(bar.X, bar.Y - S(1), Math.Max(1, fillW), bar.Height + S(2)),
                AcpTheme.Fade(MoodColor, 230), AcpTheme.Fade(MoodColor, 120), 0f);
            g.FillRectangle(fill, bar.X, bar.Y - S(1), fillW, S(3));

            // Travelling highlight while busy.
            if (_mood == ScanMood.Scanning)
            {
                var p = (float)((_t * 0.5) % 1.0);
                var hx = bar.X + p * fillW;
                using var spark = new LinearGradientBrush(
                    new RectangleF(hx - S(26), bar.Y - S(2), S(52), S(5)),
                    Color.FromArgb(0, MoodColor), AcpTheme.Fade(MoodColor, 190), 0f);
                g.FillRectangle(spark, hx - S(26), bar.Y - S(1), S(26), S(3));
            }
        }

        Txt.Draw(g, _status, _fMono, x, S(288), AcpTheme.Muted);
    }

    private void DrawStat(Graphics g, float x, int y, string value, string caption, Color color)
    {
        Txt.Draw(g, value, _fStatNum, x, y, color);
        using (var rule = new SolidBrush(Color.FromArgb(52, 255, 255, 255)))
        {
            g.FillRectangle(rule, x, y + S(25), S(18), 1);
        }
        Txt.DrawTracked(g, caption, _fStatCap, x, y + S(29), AcpTheme.Faint, S(0.8f));
    }

    /// <summary>A single rotating line of guidance along the bottom edge.</summary>
    private void DrawHintBar(Graphics g, int w, int h)
    {
        var y = h - S(34);
        var x = (float)S(36);

        using (var pen = new Pen(AcpTheme.Fade(AcpTheme.Scan, 150), 1.3f))
        {
            var r = S(6f);
            g.DrawEllipse(pen, x, y + S(3), r * 2, r * 2);
            g.DrawLine(pen, x + r, y + S(6), x + r, y + S(7));
            g.DrawLine(pen, x + r, y + S(9), x + r, y + S(13));
        }

        Txt.Draw(g, Hints[_hintIndex], _fHint, x + S(22), y + S(2), AcpTheme.Muted);

        DrawPoweredBy(g, w - S(18), y + S(2));
    }

    /// <summary>
    /// "Powered By LONGHORN", right-aligned, matching the web footer: muted lead-in, then
    /// the wordmark as a red chip on a translucent red plate (#d32f2f at 15%), wide-tracked.
    /// </summary>
    private void DrawPoweredBy(Graphics g, float rightX, float y)
    {
        const string lead = "Powered By";
        const string brand = "LONGHORN";
        var brandTrack = S(2f);
        var padX = S(7);

        var leadW = Txt.Width(g, lead, _fPowered);
        var brandW = Txt.TrackedWidth(g, brand, _fBrand, brandTrack);
        var chipW = brandW + padX * 2;

        var chipX = rightX - chipW;
        var leadX = chipX - S(8) - leadW;

        var leadH = _fPowered.GetHeight(g);
        var brandH = _fBrand.GetHeight(g);
        var chipH = brandH + S(6);
        var chipY = y + (leadH - chipH) / 2f;

        // Both halves are drawn in solid colour. Fading text with alpha over a photograph
        // lets the picture show through the letterforms and is what made this look washed.
        Txt.Draw(g, lead, _fPowered, leadX, y, _poweredHot ? AcpTheme.Ink : AcpTheme.Muted);

        var chip = new Rectangle((int)chipX, (int)chipY, (int)chipW, (int)chipH);
        using (var path = AcpTheme.RoundedRect(chip, S(3)))
        using (var plate = new SolidBrush(_poweredHot
                   ? Color.FromArgb(90, 211, 47, 47)
                   : Color.FromArgb(38, 211, 47, 47)))
        {
            g.FillPath(plate, path);
        }

        Txt.DrawTracked(g, brand, _fBrand, chipX + padX, chipY + S(3),
            _poweredHot ? Color.FromArgb(255, 255, 120, 112) : Color.FromArgb(255, 211, 47, 47),
            brandTrack);

        // Whole credit is the link target, lead-in included.
        _poweredRect = Rectangle.FromLTRB((int)leadX, (int)Math.Min(chipY, y),
            (int)rightX, (int)Math.Max(chipY + chipH, y + leadH));
    }

    /// <summary>
    /// A hairline along the bottom edge carrying the current verdict colour: a hint of the
    /// state at the very edge of vision, with a slow highlight drifting along it while a
    /// scan runs. Kept at low alpha on purpose - it should register only once noticed.
    /// </summary>
    private void DrawBottomAccent(Graphics g, int w, int h)
    {
        var red = Color.FromArgb(211, 47, 47);

        // One pixel above the window's own border, unscaled: this is a hairline effect, and
        // multiplying it by the DPI factor is precisely what made it look thick.
        var yy = h - 2;

        // Shadow. Half the reach and half the density of the first version: enough to lift
        // the rail off the edge, not enough to read as a red band along the bottom.
        using (var bloom = new LinearGradientBrush(
                   new Rectangle(0, yy - S(6), w, S(7)),
                   Color.FromArgb(0, red), Color.FromArgb(20, red), 90f))
        {
            g.FillRectangle(bloom, 0, yy - S(6), w, S(6));
        }

        // The rail itself stays one device pixel at any scale - S() would thicken it on a
        // high-DPI screen, which is exactly what made it look heavy. It is the highlight
        // travelling along it that carries the effect, so the resting line can be faint.
        using (var rail = new SolidBrush(Color.FromArgb(40, red)))
        {
            g.FillRectangle(rail, 0, yy, w, 1);
        }

        // One highlight crossing the entire window, continuously. Entering and leaving off
        // both edges means it never appears to start or stop anywhere.
        var halo = (float)S(115);
        var travel = w + halo * 2f;
        var hx = -halo + (float)((_t * 0.11) % 1.0) * travel;

        using (var sweep = new LinearGradientBrush(
                   new RectangleF(hx - halo, yy - 1, halo * 2, 3),
                   Color.FromArgb(0, red), Color.FromArgb(210, 255, 96, 86), 0f))
        {
            sweep.SetBlendTriangularShape(0.5f);
            g.FillRectangle(sweep, hx - halo, yy, halo * 2, 1);
        }

        using (var trail = new LinearGradientBrush(
                   new RectangleF(hx - halo, yy - S(4), halo * 2, S(5)),
                   Color.FromArgb(0, red), Color.FromArgb(44, 255, 96, 86), 0f))
        {
            trail.SetBlendTriangularShape(0.5f);
            g.FillRectangle(trail, hx - halo, yy - S(4), halo * 2, S(4));
        }
    }

    // ── Scan orchestration ───────────────────────────────────────────────────

    private async Task RunScanAsync()
    {
        if (_scanCancellation is not null) return;
        (string Url, string Token) apiSettings;
        try { apiSettings = GetApiSettings(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "ACS settings", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        if (!ScanPrivacy.ConfirmScan(this, apiSettings.Url)) return;
        using var cancellation = new CancellationTokenSource();
        _scanCancellation = cancellation;
        _cancelButton.Enabled = true;
        _elapsed.Restart();
        SetReportLink("");
        _scanButton.Enabled = false;
        SetVerdict("SCANNING", AcpTheme.Scan, "EVIDENCE COLLECTION IN PROGRESS");
        SetMood(ScanMood.Scanning, "SWEEPING");
        _status = "Starting evidence scan...";
        ResetSummary();
        SetProgress(2);
        ClearLog();
        AppendLog(LogLevel.Stage, "Starting ACS evidence scan");

        try
        {
            var progress = new Progress<string>(message =>
            {
                if (IsDisposed || cancellation.IsCancellationRequested) return;
                _status = message;
                _stage = message.ToUpperInvariant();
                SetProgress(MapProgress(message));
                AppendLog(LogLevel.Stage, message);
            });

            // The player agreed on the privacy screen that the report is uploaded when the scan
            // finishes, so it is - no second prompt.
            var result = await Task.Run(() => ScannerEngine.ScanAndUploadAsync(apiSettings.Url, apiSettings.Token, progress, cancellation.Token,
                uploadConsented: true), cancellation.Token);
            if (IsDisposed) return;

            SetProgress(100);
            _status = result.Uploaded ? "Report uploaded to server" : result.UploadDeclined ? "Scan completed — report was not uploaded" : "Scan completed (upload failed)";
            _stage = "SCAN COMPLETE";

            var (text, color, note, mood, state) = result.Status switch
            {
                "DETECTED" => ("DETECTED", AcpTheme.RedBright, "REVIEW THE MATCHED EVIDENCE IN YOUR REPORT", ScanMood.Detected, "CONTACT"),
                "WARNING"  => ("REVIEW", AcpTheme.Amber, "EVIDENCE NEEDS MANUAL REVIEW", ScanMood.Warning, "SUSPICIOUS"),
                _          => ("CLEAN", AcpTheme.Green, "NO CHEAT EVIDENCE FOUND", ScanMood.Clean, "CLEAR")
            };

            SetVerdict(text, color, note);
            SetMood(mood, state);
            UpdateSummary(result.Detected, result.Warnings);

            AppendLog(LogLevel.Muted, new string('-', 52));
            AppendLog(result.Status == "DETECTED" ? LogLevel.Detected : result.Status == "WARNING" ? LogLevel.Warn : LogLevel.Ok, $"VERDICT: {result.Status}");
            AppendLog(LogLevel.Info, $"Cheats {result.Detected}  ·  Warnings {result.Warnings}");

            // The server exactly as the engine reported it when the scan started - the same
            // wording the report page uses for the same scan.
            AppendLog(LogLevel.Info, result.ServerStatus switch
            {
                "connected" => $"Server: {(string.IsNullOrWhiteSpace(result.ServerName) ? "(name not reported by server)" : result.ServerName)}  ·  {result.ServerAddress}"
                               + (string.IsNullOrWhiteSpace(result.ServerMap) ? "" : $"  ·  {result.ServerMap}"),
                "not-connected" => "Server: No Server Detected",
                _ => "Server: not verified"
            });

            if (result.Uploaded)
            {
                SetReportLink(result.ReportUrl ?? "");
                AppendLog(LogLevel.Ok, $"Report: {result.ReportUrl}");
                TryOpenReport(result.ReportUrl);
            }
            else if (result.UploadDeclined)
            {
                AppendLog(LogLevel.Info, "Report upload declined. No scan report was sent to the server.");
            }
            else
            {
                AppendLog(LogLevel.Error, $"Upload failed: {result.Error}");
            }
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            if (IsDisposed) return;
            SetVerdict("CANCELLED", AcpTheme.Muted, "SCAN STOPPED / NO COMPLETE VERDICT");
            SetMood(ScanMood.Idle, "STOPPED");
            _status = "Scan cancelled";
            _stage = "CANCELLED";
            AppendLog(LogLevel.Warn, "Scan cancelled by player.");
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Counter-Strike", StringComparison.OrdinalIgnoreCase))
        {
            SetProgress(0);
            SetVerdict("NO GAME", AcpTheme.Amber, "COUNTER-STRIKE IS NOT RUNNING");
            SetMood(ScanMood.Idle, "NO TARGET");
            _status = "Open Counter-Strike, then press SCAN";
            _stage = "WAITING FOR THE GAME";
            AppendLog(LogLevel.Warn, ex.Message);
            MessageBox.Show(
                this,
                "Counter-Strike is not running.\n\nOpen the game (hl.exe or cstrike.exe) and get into it, then press SCAN again to finish the scan.",
                "Open Counter-Strike to finish the scan",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        catch (Exception ex)
        {
            SetProgress(0);
            SetVerdict("FAILED", AcpTheme.RedBright, "THE SCAN COULD NOT COMPLETE");
            SetMood(ScanMood.Idle, "ERROR");
            _status = "Scan failed";
            _stage = "SCAN FAILED";
            AppendLog(LogLevel.Error, "Error: " + ex.Message);
        }
        finally
        {
            _elapsed.Stop();
            _scanCancellation = null;
            if (!IsDisposed)
            {
                _scanButton.Enabled = true;
                _cancelButton.Enabled = false;
            }
            Invalidate();
        }
    }

    private void SetVerdict(string text, Color color, string note)
    {
        _verdict = text;
        _verdictColor = color;
        _verdictNote = note;
        _verdictFade = 0f;      // re-run the ease-in
        Invalidate();
    }

    private void SetMood(ScanMood mood, string state)
    {
        _mood = mood;
        _moodState = state;
        if (_logForm is { IsDisposed: false })
        {
            _logForm.SetState(mood);   // lights the matching explanation card
        }
        Invalidate();
    }

    private static int MapProgress(string message)
    {
        var m = message.ToLowerInvariant();
        if (m.Contains("finding running")) return 5;
        if (m.Contains("downloading")) return 10;
        if (m.Contains("hl.exe process")) return 20;
        if (m.Contains("running processes")) return 30;
        if (m.Contains("driver")) return 38;
        if (m.Contains("memory evidence")) return 46;
        if (m.Contains("inline hook")) return 54;
        if (m.Contains("module code")) return 60;
        if (m.Contains("cvar")) return 65;
        if (m.Contains("external readers")) return 70;
        if (m.Contains("live hl.exe directory")) return 76;
        if (m.Contains("configs")) return 80;
        if (m.Contains("input")) return 84;
        if (m.Contains("evidence engine")) return 88;
        if (m.Contains("cheat/debug")) return 90;
        if (m.Contains("artifacts")) return 92;
        if (m.Contains("launch and download")) return 94;
        if (m.Contains("change journal")) return 96;
        if (m.Contains("server")) return 97;
        if (m.Contains("upload")) return 99;
        return _lastProgress;
    }

    private static int _lastProgress;

    private void SetProgress(int value)
    {
        _lastProgress = MathUtils.Clamp(value, 0, 100);
        _progress = _lastProgress;
        Invalidate();
    }

    private void ResetSummary() => UpdateSummary(0, 0);

    private void UpdateSummary(int detected, int warnings)
    {
        _detected = detected;
        _warnings = warnings;
        Invalidate();
    }

    // ── Evidence log ─────────────────────────────────────────────────────────

    private void AppendLog(LogLevel level, string message)
    {
        var entry = new LogEntry(DateTime.Now, level, message);
        _logEntries.Add(entry);
        if (_logForm is { IsDisposed: false })
        {
            _logForm.AppendEntry(entry);
        }
    }

    private void ClearLog()
    {
        _logEntries.Clear();
        if (_logForm is { IsDisposed: false })
        {
            _logForm.SetEntries(_logEntries);
        }
    }

    private void SetReportLink(string url)
    {
        _lastReportUrl = url;
        if (_logForm is { IsDisposed: false })
        {
            _logForm.SetReportLink(url);
        }
    }

    private void OpenLogWindow()
    {
        if (_logForm is { IsDisposed: false })
        {
            _logForm.Activate();
            return;
        }

        _logForm = new LogForm();
        _logForm.SetEntries(_logEntries);
        _logForm.SetReportLink(_lastReportUrl);
        _logForm.SetState(_mood);
        _logForm.Owner = this;
        _logForm.Show(this);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _scanCancellation?.Cancel();
            _fx.Dispose();
            _tips.Dispose();
            _hero?.Dispose();
            _logo?.Dispose();
            _appIcon?.Dispose();
            _backdrop?.Dispose();
            DisposeFonts();
        }

        base.Dispose(disposing);
    }

    private static (string Url, string Token) GetApiSettings()
    {
        var url = (Environment.GetEnvironmentVariable("ACS_API_URL")
            ?? Environment.GetEnvironmentVariable("ACP_API_URL"))?.Trim() ?? "";
        var token = (Environment.GetEnvironmentVariable("ACS_API_TOKEN")
            ?? Environment.GetEnvironmentVariable("ACP_API_TOKEN"))?.Trim() ?? "";
        // The app is a single executable and is published without a settings file. Environment
        // variables and an operator/user settings file override the public deployment defaults;
        // the latter also keeps local test configuration out of the published folder.
        var settingsPath = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "acp-settings.json"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "LongHorn ACS", "acp-settings.json")
        }.FirstOrDefault(File.Exists) ?? "";

        if (settingsPath != "")
        {
            try
            {
                using var document = JsonDocument.Parse(File.ReadAllText(settingsPath));
                var root = document.RootElement;
                if (url == "" && root.TryGetProperty("apiUrl", out var urlElement))
                {
                    url = urlElement.GetString()?.Trim() ?? "";
                }
                if (token == "" && root.TryGetProperty("apiToken", out var tokenElement))
                {
                    token = tokenElement.GetString()?.Trim() ?? "";
                }
            }
            catch (JsonException ex)
            {
                throw new InvalidOperationException("acp-settings.json is invalid: " + ex.Message, ex);
            }
        }

        if (url == "")
        {
            url = "https://cslonghorn.com/acs/api.php";
        }
        if (token == "")
        {
            token = typeof(MainForm).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(a => a.Key == "AcsApiToken")?.Value?.Trim() ?? "";
        }
        if (token == "")
        {
            token = "a676018307afb5ac8570ae564cc62a25cd668b15933d2122";
        }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException("ACS API URL must be an absolute http:// or https:// URL.");
        }

        return (url, token);
    }

    private static void TryOpenReport(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            return;
        }

        // Opened with the player's normal rights, never elevated; if it fails, the report URL
        // is still in the evidence log.
        BrowserLink.Open(url);
    }

    /// <summary>
    /// Non-blocking check for desktop scanner updates from the web release directory.
    /// Runs silently in the background on startup; never interferes with offline scanning.
    /// </summary>
    private async Task CheckForUpdatesAsync()
    {
        try
        {
            var (apiUrl, _) = GetApiSettings();
            var versionUrl = "https://cslonghorn.com/acs/windows/release/version.txt";
            if (Uri.TryCreate(apiUrl, UriKind.Absolute, out var uri))
            {
                var basePath = uri.GetLeftPart(UriPartial.Path);
                var lastSlash = basePath.LastIndexOf('/');
                if (lastSlash > 0)
                {
                    versionUrl = basePath.Substring(0, lastSlash) + "/windows/release/version.txt";
                }
            }

            using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            client.DefaultRequestHeaders.Add("User-Agent", "ACS-Scanner/" + ScannerEngine.Version);
            var remoteText = await client.GetStringAsync(versionUrl).ConfigureAwait(false);
            var remoteVerStr = remoteText.Trim().Split('-', '+')[0];

            if (System.Version.TryParse(remoteVerStr, out var remoteVer) &&
                System.Version.TryParse(ScannerEngine.Version, out var localVer))
            {
                if (remoteVer > localVer)
                {
                    if (IsHandleCreated && !IsDisposed)
                    {
                        BeginInvoke(new Action(() =>
                        {
                            _updateAvailable = true;
                            _latestVersion = remoteVerStr;
                            AppendLog(LogLevel.Stage, $"UPDATE AVAILABLE: v{_latestVersion} is out! Click the update badge to download.");
                            Invalidate();
                        }));
                    }
                }
            }
        }
        catch
        {
            // Fail silently: offline, DNS error, or timeout must never hinder startup
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence log
//
// The previous version was a scrolling box of timestamps and a copy button. That is a
// developer's console, and the person reading it is usually not a developer: it is a
// player who has just been accused of cheating, or the admin deciding what to do about
// them. Neither knows what "x" in front of a line means, or what the difference is
// between a detection and a warning - and that difference is the whole product.
//
// So the window explains itself before it shows anything. The three verdicts are stated
// in plain language at the top, with the one that actually happened lit; the report link
// is a field you click to copy rather than a button you have to find; and the timeline
// keeps the machine detail underneath, for the reader who wants it.
//
// Same custom chrome as the main window, same one-scale-factor approach.
// ─────────────────────────────────────────────────────────────────────────────
internal sealed class LogForm : Form
{
    private const int BaseW = 780;
    private const int BaseH = 606;

    private float _scale = 1f;
    private int S(float v) => (int)Math.Round(v * _scale);

    private readonly RichTextBox _log = new();
    private readonly HudButton _copy = new();
    private readonly HudButton _open = new();
    private readonly HudButton _dismiss = new();

    private string _reportLink = "";
    private int _entryCount;
    private ScanMood _mood = ScanMood.Idle;

    // Click-to-copy on the link field, plus the confirmation that follows it.
    private Rectangle _linkRect;
    private bool _linkHot;
    private DateTime _copiedAt = DateTime.MinValue;
    private readonly System.Windows.Forms.Timer _fade = new() { Interval = 200 };

    private Rectangle _closeRect;
    private bool _closeHot;
    private Point _dragFrom;
    private bool _dragging;

    private Font _fTitle = null!, _fEyebrow = null!, _fCardTitle = null!, _fBody = null!;
    private Font _fMonoSm = null!, _fLink = null!, _fChip = null!, _fCount = null!;

    /// <summary>The three outcomes, in the words a player and an admin both need.</summary>
    private readonly record struct Verdict(
        string Symbol, string Title, Color Color, ScanMood Mood, string Body);

    private static readonly Verdict[] Verdicts =
    {
        new("x", "DETECTED CHEAT", AcpTheme.RedBright, ScanMood.Detected,
            "Evidence matched a known cheat: an injected module, a patched game function, or a file fingerprint already in the database. This is a match, not a guess."),
        new("!", "SUSPICIOUS", AcpTheme.Amber, ScanMood.Warning,
            "Something here is unusual but not proof: an unrecognised module, a modified game file, or a config the scanner has not seen before. A human decides this one."),
        new("+", "CLEAN", AcpTheme.Green, ScanMood.Clean,
            "Nothing matched and nothing looked wrong. The report link below is evidence of that, and can be handed to a server admin as it stands.")
    };

    public LogForm()
    {
        Text = "ACS — Evidence Log";
        StartPosition = FormStartPosition.CenterParent;
        FormBorderStyle = FormBorderStyle.None;
        MaximizeBox = false;
        MinimizeBox = false;
        AutoScaleMode = AutoScaleMode.None;
        DoubleBuffered = true;
        BackColor = AcpTheme.Bg;
        ForeColor = AcpTheme.Ink;
        KeyPreview = true;

        _log.Multiline = true;
        _log.ReadOnly = true;
        _log.BorderStyle = BorderStyle.None;
        _log.ScrollBars = RichTextBoxScrollBars.Vertical;
        _log.BackColor = AcpTheme.PanelInner;
        _log.ForeColor = AcpTheme.Ink;
        _log.WordWrap = true;
        _log.TabStop = false;

        _copy.Text = "COPY LINK";
        _copy.Accent = AcpTheme.Gold;
        _copy.Primary = true;
        _copy.Glyph = HudGlyph.Copy;
        _copy.Click += (_, _) => CopyReportLink();

        _open.Text = "OPEN REPORT";
        _open.Accent = AcpTheme.Scan;
        _open.Glyph = HudGlyph.Link;
        _open.Click += (_, _) => OpenReport();

        _dismiss.Text = "CLOSE";
        _dismiss.Accent = AcpTheme.Muted;
        _dismiss.Glyph = HudGlyph.Close;
        _dismiss.Click += (_, _) => Close();

        _copy.Enabled = false;
        _open.Enabled = false;

        Controls.Add(_log);
        Controls.Add(_copy);
        Controls.Add(_open);
        Controls.Add(_dismiss);

        // Drives the "COPIED" confirmation back out again. Idle the rest of the time.
        _fade.Tick += (_, _) =>
        {
            if ((DateTime.UtcNow - _copiedAt).TotalSeconds > 2.4)
            {
                _fade.Stop();
            }
            Invalidate(_linkRect);
        };

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
        var next = dpi * MathUtils.Clamp(fit, 0.60f, 1.0f);
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
            LayoutChildren();
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
        _fTitle     = AcpFonts.Mono(S(12), FontStyle.Bold);
        _fEyebrow   = AcpFonts.Mono(S(9), FontStyle.Bold);
        _fCardTitle = AcpFonts.Mono(S(10), FontStyle.Bold);
        _fBody      = AcpFonts.Display(S(12));
        _fMonoSm    = AcpFonts.Mono(S(9), FontStyle.Bold);
        _fLink      = AcpFonts.Mono(S(11));
        _fChip      = AcpFonts.Mono(S(11), FontStyle.Bold);
        _fCount     = AcpFonts.Mono(S(9));
        _log.Font   = AcpFonts.Mono(S(11));
    }

    private void DisposeFonts()
    {
        foreach (var f in new[] { _fTitle, _fEyebrow, _fCardTitle, _fBody, _fMonoSm, _fLink, _fChip, _fCount })
        {
            f?.Dispose();
        }
    }

    // Layout constants, in the 780x606 authoring canvas.
    private const int LayoutMargin = 26;
    private const int CardsY = 124;
    private const int CardH = 108;
    private const int LinkY = 264;      // leaves room for the label above it, clear of the cards
    private const int LinkH = 44;
    private const int PanelY = 324;
    private const int PanelH = 212;
    private const int ButtonsY = 552;
    private const int ButtonH = 38;

    private void LayoutChildren()
    {
        var pad = S(12);
        _log.Bounds = new Rectangle(
            S(LayoutMargin) + pad, S(PanelY) + pad + S(22),
            S(BaseW - LayoutMargin * 2) - pad * 2, S(PanelH) - pad * 2 - S(22));

        void Place(HudButton b, int px, int x, int w)
        {
            var old = b.Font;
            b.VisualScale = _scale;
            b.Font = AcpFonts.Mono(S(px), FontStyle.Bold);
            b.Bounds = new Rectangle(S(x), S(ButtonsY), S(w), S(ButtonH));
            old?.Dispose();
        }

        Place(_copy, 10, LayoutMargin, 126);
        Place(_open, 10, LayoutMargin + 134, 142);
        Place(_dismiss, 10, BaseW - LayoutMargin - 96, 96);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Escape) { Close(); e.Handled = true; }
        base.OnKeyDown(e);
    }

    // ── Chrome ───────────────────────────────────────────────────────────────

    protected override void OnMouseDown(MouseEventArgs e)
    {
        if (e.Button == MouseButtons.Left)
        {
            if (_closeRect.Contains(e.Location)) { Close(); return; }
            if (_linkRect.Contains(e.Location)) { CopyReportLink(); return; }
            if (e.Y <= S(46)) { _dragging = true; _dragFrom = e.Location; }
        }
        base.OnMouseDown(e);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        if (_dragging)
        {
            Location = new Point(Location.X + e.X - _dragFrom.X, Location.Y + e.Y - _dragFrom.Y);
        }
        else
        {
            var c = _closeRect.Contains(e.Location);
            var l = _linkRect.Contains(e.Location) && _reportLink != "";
            if (c != _closeHot || l != _linkHot)
            {
                _closeHot = c;
                _linkHot = l;
                Cursor = l ? Cursors.Hand : Cursors.Default;
                Invalidate();
            }
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

        // Ground: the same gunmetal as the main window, lifted under the header so the
        // explanation reads as a separate band from the timeline below it.
        using (var back = new LinearGradientBrush(new Rectangle(0, 0, w, h),
                   Color.FromArgb(16, 19, 26), Color.FromArgb(7, 9, 13), 68f))
        {
            g.FillRectangle(back, 0, 0, w, h);
        }
        using (var band = new LinearGradientBrush(new Rectangle(0, 0, w, S(CardsY + CardH)),
                   Color.FromArgb(90, 30, 38, 52), Color.FromArgb(0, 30, 38, 52), 90f))
        {
            g.FillRectangle(band, 0, 0, w, S(CardsY + CardH));
        }

        DrawHeader(g, w);
        DrawIntro(g);
        DrawCards(g, w);
        DrawLinkField(g, w);
        DrawTimelinePanel(g, w);

        AcpTheme.DrawWindowEdge(g, w, h);
    }

    private void DrawHeader(Graphics g, int w)
    {
        var barH = S(46);
        var x = (float)S(LayoutMargin);
        var mid = barH / 2f;

        // Accent block in the current verdict's colour, so the window is identifiable
        // at a glance from the taskbar preview alone.
        var accent = MoodColor;
        using (var mark = new SolidBrush(AcpTheme.Fade(accent, 235)))
        {
            g.FillRectangle(mark, x, mid - S(9), S(3), S(18));
        }

        Txt.DrawTracked(g, "EVIDENCE LOG", _fTitle, x + S(12), mid - S(12), AcpTheme.Ink, S(1.2f));
        var titleW = Txt.TrackedWidth(g, "EVIDENCE LOG", _fTitle, S(1.2f));
        Txt.DrawTracked(g, "ACS · ANTI-CHEAT SCANNER", _fEyebrow, x + S(12), mid + S(3),
            AcpTheme.Faint, S(1f));

        // Entry counter, right of the title.
        var count = _entryCount == 1 ? "1 ENTRY" : $"{_entryCount} ENTRIES";
        Txt.Draw(g, count, _fCount, x + S(20) + titleW, mid - S(5), AcpTheme.Fade(AcpTheme.Muted, 170));

        var btn = S(30);
        _closeRect = new Rectangle(w - btn - S(8), S(8), btn, btn);
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

    private Color MoodColor => _mood switch
    {
        ScanMood.Detected => AcpTheme.RedBright,
        ScanMood.Warning  => AcpTheme.Amber,
        ScanMood.Clean    => AcpTheme.Green,
        ScanMood.Scanning => AcpTheme.Scan,
        _                 => AcpTheme.Gold
    };

    private void DrawIntro(Graphics g)
    {
        var x = (float)S(LayoutMargin);
        Txt.DrawTracked(g, "WHAT THIS WINDOW SHOWS", _fEyebrow, x, S(66),
            AcpTheme.Fade(AcpTheme.Gold, 210), S(1.1f));

        DrawWrapped(g,
            "Every step of the scan is recorded below, in order, with the time it happened. " +
            "Each line is marked with what it found. A scan ends in one of three verdicts:",
            _fBody, new RectangleF(x, S(84), S(BaseW - LayoutMargin * 2 - 40), S(40)),
            AcpTheme.Fade(AcpTheme.Ink, 195));
    }

    private void DrawCards(Graphics g, int w)
    {
        var gap = S(11);
        var total = S(BaseW - LayoutMargin * 2);
        var cardW = (total - gap * 2) / 3;
        var y = S(CardsY);
        var h = S(CardH);

        for (var i = 0; i < Verdicts.Length; i++)
        {
            var v = Verdicts[i];
            var active = _mood == v.Mood;
            var x = S(LayoutMargin) + i * (cardW + gap);
            var card = new Rectangle(x, y, cardW, h);

            using (var path = AcpTheme.RoundedRect(card, S(4)))
            {
                // The verdict that actually happened is filled in its own colour; the other
                // two stay neutral. Without that this is three paragraphs of theory.
                using (var fill = new LinearGradientBrush(card,
                           active ? AcpTheme.Fade(v.Color, 34) : Color.FromArgb(150, 14, 18, 25),
                           active ? AcpTheme.Fade(v.Color, 12) : Color.FromArgb(170, 10, 13, 19), 90f))
                {
                    g.FillPath(fill, path);
                }
                using var pen = new Pen(active ? AcpTheme.Fade(v.Color, 190) : Color.FromArgb(46, 255, 255, 255), 1f);
                g.DrawPath(pen, path);
            }

            // Symbol chip: the same character the timeline prints in front of its lines,
            // which is what connects the explanation to the log.
            var chip = new Rectangle(x + S(12), y + S(12), S(20), S(20));
            using (var chipPath = AcpTheme.RoundedRect(chip, S(3)))
            using (var chipFill = new SolidBrush(AcpTheme.Fade(v.Color, active ? 70 : 38)))
            {
                g.FillPath(chipFill, chipPath);
            }
            Txt.DrawCentered(g, v.Symbol, _fChip, chip, AcpTheme.Fade(v.Color, active ? 255 : 215));

            Txt.DrawTracked(g, v.Title, _fCardTitle, x + S(40), y + S(17),
                AcpTheme.Fade(v.Color, active ? 255 : 225), S(0.9f));

            if (active)
            {
                var tag = new Rectangle(x + cardW - S(64), y + S(14), S(52), S(16));
                using (var tagPath = AcpTheme.RoundedRect(tag, S(8)))
                using (var tagFill = new SolidBrush(AcpTheme.Fade(v.Color, 60)))
                {
                    g.FillPath(tagFill, tagPath);
                }
                Txt.DrawCentered(g, "RESULT", _fCount, tag, AcpTheme.Fade(v.Color, 255));
            }

            DrawWrapped(g, v.Body, _fBody,
                new RectangleF(x + S(13), y + S(42), cardW - S(26), h - S(50)),
                AcpTheme.Fade(AcpTheme.Ink, active ? 210 : 165));
        }
    }

    /// <summary>
    /// The report link as a field, not a label: the whole row is the copy target, it says
    /// so, and it confirms in place when clicked. Before a scan has run it explains why it
    /// is empty instead of sitting there blank.
    /// </summary>
    private void DrawLinkField(Graphics g, int w)
    {
        var x = S(LayoutMargin);
        var fieldW = S(BaseW - LayoutMargin * 2);
        _linkRect = new Rectangle(x, S(LinkY), fieldW, S(LinkH));

        var has = _reportLink != "";
        var copied = (DateTime.UtcNow - _copiedAt).TotalSeconds < 2.4;
        var accent = copied ? AcpTheme.Green : has ? AcpTheme.Scan : AcpTheme.Faint;

        Txt.DrawTracked(g, "REPORT LINK", _fEyebrow, x, S(LinkY - 18),
            AcpTheme.Fade(AcpTheme.Gold, 200), S(1.1f));

        using (var path = AcpTheme.RoundedRect(_linkRect, S(4)))
        {
            using (var fill = new SolidBrush(_linkHot
                       ? Color.FromArgb(210, 17, 23, 32)
                       : Color.FromArgb(190, 11, 15, 21)))
            {
                g.FillPath(fill, path);
            }
            using var pen = new Pen(AcpTheme.Fade(accent, _linkHot ? 190 : has ? 110 : 60), 1f);
            g.DrawPath(pen, path);
        }

        // Left rail in the field's state colour.
        using (var rail = new SolidBrush(AcpTheme.Fade(accent, has ? 220 : 90)))
        {
            g.FillRectangle(rail, x + 1, _linkRect.Y + S(7), Math.Max(2f, 2.5f * _scale), _linkRect.Height - S(14));
        }

        var hint = copied ? "COPIED" : has ? "CLICK TO COPY" : "";
        var hintW = hint == "" ? 0f : Txt.TrackedWidth(g, hint, _fMonoSm, S(1f)) + S(26);

        var text = has ? _reportLink : "No report yet — run a scan and the link appears here.";
        var textColor = has ? AcpTheme.Fade(AcpTheme.Ink, 235) : AcpTheme.Fade(AcpTheme.Muted, 180);
        var textFont = has ? _fLink : _fBody;

        // Long URLs are clipped from the left of the path, keeping the host and the report
        // id - the two halves anyone reads - rather than trailing off mid-domain.
        var available = fieldW - S(28) - hintW;
        var shown = Elide(g, text, textFont, available);
        Txt.Draw(g, shown, textFont, x + S(16), _linkRect.Y + (_linkRect.Height - textFont.GetHeight(g)) / 2f, textColor);

        if (hint != "")
        {
            Txt.DrawTracked(g, hint, _fMonoSm, x + fieldW - hintW + S(10),
                _linkRect.Y + (_linkRect.Height - _fMonoSm.GetHeight(g)) / 2f,
                AcpTheme.Fade(accent, copied ? 255 : _linkHot ? 235 : 150), S(1f));
        }
    }

    private static string Elide(Graphics g, string text, Font font, float maxWidth)
    {
        if (maxWidth <= 0 || Txt.Width(g, text, font) <= maxWidth)
        {
            return text;
        }

        var head = text;
        while (head.Length > 8 && Txt.Width(g, head + "…", font) > maxWidth)
        {
            head = head[..^1];
        }
        return head + "…";
    }

    private void DrawTimelinePanel(Graphics g, int w)
    {
        var panel = new Rectangle(S(LayoutMargin), S(PanelY), S(BaseW - LayoutMargin * 2), S(PanelH));

        using (var path = AcpTheme.RoundedRect(panel, S(4)))
        using (var fill = new SolidBrush(Color.FromArgb(215, 11, 15, 21)))
        using (var pen = new Pen(Color.FromArgb(52, 255, 255, 255), 1f))
        {
            g.FillPath(fill, path);
            g.DrawPath(pen, path);
        }

        Txt.DrawTracked(g, "SCAN TIMELINE", _fEyebrow, panel.X + S(13), panel.Y + S(11),
            AcpTheme.Fade(AcpTheme.Ink, 190), S(1.1f));

        var legend = "TIME  ·  MARK  ·  EVENT";
        var legendW = Txt.TrackedWidth(g, legend, _fCount, S(0.6f));
        Txt.DrawTracked(g, legend, _fCount, panel.Right - S(13) - legendW, panel.Y + S(12),
            AcpTheme.Fade(AcpTheme.Faint, 190), S(0.6f));

        using var rule = new SolidBrush(Color.FromArgb(40, 255, 255, 255));
        g.FillRectangle(rule, panel.X + S(12), panel.Y + S(27), panel.Width - S(24), 1);
    }

    private static void DrawWrapped(Graphics g, string text, Font font, RectangleF box, Color color)
    {
        using var format = (StringFormat)StringFormat.GenericTypographic.Clone();
        format.Trimming = StringTrimming.EllipsisWord;
        using var brush = new SolidBrush(color);
        g.DrawString(text, font, brush, box, format);
    }

    // ── State in ─────────────────────────────────────────────────────────────

    public void SetEntries(IReadOnlyList<LogEntry> entries)
    {
        _log.Clear();
        foreach (var entry in entries)
        {
            AcpTheme.Append(_log, entry);
        }
        _entryCount = entries.Count;
        Invalidate();
    }

    public void AppendEntry(LogEntry entry)
    {
        AcpTheme.Append(_log, entry);
        _entryCount++;
        Invalidate();
    }

    public void SetReportLink(string url)
    {
        _reportLink = url ?? "";
        _copiedAt = DateTime.MinValue;

        // Nothing to copy and nowhere to open until a scan has uploaded one. The field
        // above says why; the buttons should not look like they would do something.
        _copy.Enabled = _open.Enabled = _reportLink != "";
        Invalidate();
    }

    /// <summary>Lights the card for the verdict this scan actually produced.</summary>
    public void SetState(ScanMood mood)
    {
        _mood = mood;
        Invalidate();
    }

    private void CopyReportLink()
    {
        if (string.IsNullOrWhiteSpace(_reportLink))
        {
            return;     // the field already says why there is nothing to copy
        }

        try
        {
            Clipboard.SetText(_reportLink);
            _copiedAt = DateTime.UtcNow;
            if (!_fade.Enabled) _fade.Start();
        }
        catch
        {
            // Another process had the clipboard open. Nothing here is worth a dialog.
        }

        Invalidate();
    }

    private void OpenReport()
    {
        if (string.IsNullOrWhiteSpace(_reportLink))
        {
            return;
        }

        // Opened with the player's normal rights, never elevated; the link stays copyable.
        BrowserLink.Open(_reportLink);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _fade.Dispose();
            DisposeFonts();
        }
        base.Dispose(disposing);
    }
}
