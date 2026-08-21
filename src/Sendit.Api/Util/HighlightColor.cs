using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SkiaSharp;
using Svg.Skia;

namespace Sendit.Api.Util;

/// <summary>
/// Parses and derives UI highlight colors from SENDIT_HIGHLIGHT (#RRGGBB / #RGB).
/// Default matches the built-in gold theme. Branding SVGs (wordmark + rocket favicon)
/// are generated in-process — no logo.svg on disk.
/// Special token <c>#random</c> (or <c>random</c>) is resolved once at API startup
/// to a concrete accent hex (see <see cref="RandomAccent"/>).
/// </summary>
public static partial class HighlightColor
{
    public const string DefaultHex = "#c8ab37";

    /// <summary>
    /// True for <c>#random</c> / <c>random</c> (case-insensitive, optional surrounding whitespace).
    /// </summary>
    public static bool IsRandomToken(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;
        var s = input.Trim();
        if (s.StartsWith('#'))
            s = s[1..];
        return s.Equals("random", StringComparison.OrdinalIgnoreCase);
    }

    // Random accent bounds — high saturation (not grey); mid-bright L for dark UI.
    private const double RandomSatMin = 0.70;
    private const double RandomSatMax = 0.95;
    private const double RandomLightMin = 0.50;
    private const double RandomLightMax = 0.68;
    /// <summary>Reject max−min channel span below this (near-grey), 0–1.</summary>
    private const double MinAccentChroma = 0.28;
    /// <summary>WCAG relative luminance above this reads as near-white on dark UI.</summary>
    private const double MaxWcagLuminance = 0.72;
    /// <summary>Min WCAG contrast of accent vs page --bg (#121212).</summary>
    private const double MinContrastVsPageBg = 4.5;
    /// <summary>Min WCAG contrast of dark button label (#0a0a0a) on accent fill.</summary>
    private const double MinContrastVsButtonLabel = 4.5;

    /// <summary>Page background from style.css <c>--bg</c>.</summary>
    private static readonly RgbColor DarkUiBg = new(0x12, 0x12, 0x12);
    /// <summary>Primary button label colour (dark text on gold fill).</summary>
    private static readonly RgbColor ButtonLabelDark = new(0x0a, 0x0a, 0x0a);

    /// <summary>
    /// A vivid accent for the dark UI (random hue; high S, mid-bright L).
    /// Used when SENDIT_HIGHLIGHT is <c>#random</c>; call once at process start.
    /// Never returns black, white, grey, or low-contrast colours on the dark theme.
    /// </summary>
    public static RgbColor RandomAccent(Random? rng = null)
    {
        rng ??= Random.Shared;
        for (var attempt = 0; attempt < 64; attempt++)
        {
            var h = rng.NextDouble() * 360.0;
            var s = RandomSatMin + rng.NextDouble() * (RandomSatMax - RandomSatMin);
            var l = RandomLightMin + rng.NextDouble() * (RandomLightMax - RandomLightMin);
            var c = FromHsl(h, s, l);
            if (IsDistinctAccent(c))
                return c;
        }

        // Deterministic safe fallback (default-gold-like mid gold).
        return FromHsl(48, 0.78, 0.56);
    }

    /// <summary>
    /// WCAG 2.x relative luminance (0–1) for sRGB bytes.
    /// </summary>
    public static double RelativeLuminance(RgbColor c)
    {
        static double Lin(int channel)
        {
            var s = channel / 255.0;
            return s <= 0.04045 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return 0.2126 * Lin(c.R) + 0.7152 * Lin(c.G) + 0.0722 * Lin(c.B);
    }

    /// <summary>WCAG contrast ratio between two sRGB colours (≥ 1).</summary>
    public static double ContrastRatio(RgbColor a, RgbColor b)
    {
        var l1 = RelativeLuminance(a);
        var l2 = RelativeLuminance(b);
        var lighter = Math.Max(l1, l2);
        var darker = Math.Min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
    }

    /// <summary>
    /// True when the colour is clearly distinct from black, white, and grey,
    /// has enough contrast on the dark page background, and supports dark
    /// primary-button label text (suitable as a UI highlight accent).
    /// </summary>
    public static bool IsDistinctAccent(RgbColor c)
    {
        var max = Math.Max(c.R, Math.Max(c.G, c.B));
        var min = Math.Min(c.R, Math.Min(c.G, c.B));
        var chroma = (max - min) / 255.0;
        if (chroma < MinAccentChroma)
            return false;

        var y = RelativeLuminance(c);
        // Near-white washes out on dark UI (and looks like “white” accents).
        if (y > MaxWcagLuminance)
            return false;

        // Must stand out on --bg #121212 (links, chips, logo, gold fills).
        if (ContrastRatio(c, DarkUiBg) < MinContrastVsPageBg)
            return false;

        // Primary buttons use #0a0a0a labels on the accent fill.
        if (ContrastRatio(c, ButtonLabelDark) < MinContrastVsButtonLabel)
            return false;

        return true;
    }

    /// <summary>
    /// Parse a color string. Accepts #RGB, #RRGGBB, or RRGGBB (case-insensitive).
    /// On failure returns the default gold. Does not treat <c>#random</c> as a color —
    /// resolve that at startup via <see cref="IsRandomToken"/> + <see cref="RandomAccent"/>.
    /// </summary>
    public static RgbColor ParseOrDefault(string? input)
    {
        if (TryParse(input, out var c))
            return c;
        TryParse(DefaultHex, out c);
        return c;
    }

    public static bool TryParse(string? input, out RgbColor color)
    {
        color = default;
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var s = input.Trim();
        if (s.StartsWith('#'))
            s = s[1..];

        // #random is not a hex color — reject so callers can handle it separately.
        if (s.Equals("random", StringComparison.OrdinalIgnoreCase))
            return false;

        if (s.Length == 3 && Hex3().IsMatch(s))
        {
            var r = int.Parse(new string(s[0], 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var g = int.Parse(new string(s[1], 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var b = int.Parse(new string(s[2], 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            color = new RgbColor(r, g, b);
            return true;
        }

        if (s.Length == 6 && Hex6().IsMatch(s))
        {
            var r = int.Parse(s[..2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var g = int.Parse(s[2..4], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var b = int.Parse(s[4..6], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            color = new RgbColor(r, g, b);
            return true;
        }

        return false;
    }

    /// <summary>HSL → sRGB (H in degrees 0–360, S/L in 0–1).</summary>
    public static RgbColor FromHsl(double h, double saturation, double lightness)
    {
        h = ((h % 360.0) + 360.0) % 360.0;
        saturation = Math.Clamp(saturation, 0, 1);
        lightness = Math.Clamp(lightness, 0, 1);

        if (saturation <= 0)
        {
            var grey = (int)Math.Round(lightness * 255.0);
            return new RgbColor(grey, grey, grey);
        }

        double q = lightness < 0.5
            ? lightness * (1 + saturation)
            : lightness + saturation - lightness * saturation;
        double p = 2 * lightness - q;
        double hk = h / 360.0;

        static double HueToRgb(double p, double q, double t)
        {
            if (t < 0) t += 1;
            if (t > 1) t -= 1;
            if (t < 1.0 / 6) return p + (q - p) * 6 * t;
            if (t < 1.0 / 2) return q;
            if (t < 2.0 / 3) return p + (q - p) * (2.0 / 3 - t) * 6;
            return p;
        }

        static int ToByte(double v) => Math.Clamp((int)Math.Round(v * 255.0), 0, 255);

        return new RgbColor(
            ToByte(HueToRgb(p, q, hk + 1.0 / 3)),
            ToByte(HueToRgb(p, q, hk)),
            ToByte(HueToRgb(p, q, hk - 1.0 / 3)));
    }

    /// <summary>Theme CSS for a solid highlight color.</summary>
    public static string ToCssVars(RgbColor c)
    {
        var hex = c.ToHex();
        var light = c.Adjust(1.12f).ToHex();
        var dark = c.Adjust(0.84f).ToHex();
        var soft = $"rgba({c.R}, {c.G}, {c.B}, 0.14)";
        var infoSoft = $"rgba({c.R}, {c.G}, {c.B}, 0.12)";
        var hexEnc = Uri.EscapeDataString(hex);
        var fill = hexEnc.StartsWith("%23", StringComparison.Ordinal)
            ? hexEnc
            : "%23" + hex.TrimStart('#');

        return
            "/* Generated from SENDIT_HIGHLIGHT — do not edit */\n" +
            ":root {\n" +
            $"  --primary: {hex};\n" +
            $"  --primary-dark: {dark};\n" +
            $"  --primary-light: {light};\n" +
            $"  --primary-soft: {soft};\n" +
            $"  --accent: {hex};\n" +
            $"  --accent-hover: {light};\n" +
            $"  --accent-active: {dark};\n" +
            $"  --accent-soft: {soft};\n" +
            $"  --accent-rgb: {c.R}, {c.G}, {c.B};\n" +
            $"  --info: {hex};\n" +
            $"  --info-soft: {infoSoft};\n" +
            "}\n" +
            "select:focus {\n" +
            $"  background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath fill='{fill}' d='M1.4 0.6L6 5.2 10.6 0.6 12 2 6 8 0 2z'/%3E%3C/svg%3E\");\n" +
            "}\n";
    }

    /// <summary>CSS for the configured highlight color.</summary>
    public static string ToThemeCss(string? highlight) =>
        ToCssVars(ParseOrDefault(highlight));

    // Stock "Sendit!" wordmark path data (visioncortex trace of the original logo).
    private const string RocketPlumeD = "m 232,461 5,5 3,3 v 2 l 4,2 9,8 18,12 21,11 11,8 10,9 9,12 4,10 -5,-2 -15,-8 -24,-10 -19,-8 -11,-6 -13,-13 -7,-14 -2,-9 1,-10 z";
    private const string RocketWindowD = "m 163,123 h 21 l 16,5 11,7 11,11 7,12 4,13 1,7 v 9 l -2,12 -5,12 -7,11 -7,7 -14,9 -12,4 -6,1 h -15 l -15,-4 -10,-5 -10,-8 -9,-11 -6,-13 -2,-8 -1,-13 2,-14 5,-12 6,-10 10,-10 14,-8 z m 5,22 -10,3 -9,6 -8,9 -4,9 -1,4 v 13 l 3,10 7,10 9,7 10,4 h 17 l 12,-5 9,-8 5,-8 3,-10 v -13 l -4,-11 -6,-8 -8,-7 -10,-4 -4,-1 z";
    private const string RocketBodyD = "M 96.999997,0 H 107 l 15,3 20,8 29,14 22,13 16,11 12,9 13,11 7,6 7,-1 13,-3 h 19 l 17,4 16,7 15,10 14,12 11,14 12,19 14,26 17,37 13,32 13,35 5,14 -1,2 -57,-21 -41,-15 v 21 l -2,12 25,9 20,10 12,9 7,8 4,9 v 12 l -4,9 -3,5 8,8 9,13 8,15 7,21 3,17 v 35 l -4,22 -5,17 -10,24 -4,16 -3,27 -1,27 -5,-2 -18,-13 -8,-6 -2,26 -4,31 -3,8 -7,3 -7,-1 -5,-6 -4,-10 -10,-14 -12,-14 -9,-9 -11,-9 -14,-10 -16,-9 -19,-8 -18,-8 -15,-9 -11,-9 -11,-11 -10,-15 -5,-10 -2,-14 v -11 l 1,-7 h -15 l -8,-3 -5,-6 -2,-8 v -21 l 4,-20 9,-26 2,-6 -6,-2 -11,-8 -9,-7 -2,9 -23,73 -6.000003,19 -2,1 L 84,434 70,414 55,391 42,370 30,349 18,326 9.9999997,309 l -7,-21 -2,-8 L 0,271 v -20 l 2.9999997,-18 5,-15 L 15,205 l 8,-10 9,-9 7,-5 h 2 L 39,171 38,160 V 110 L 41,83 47,51 51,36 58,22 67,12 75,6 90.999997,1 Z m -1,23 L 86,26 l -6,4 -6,10 -4,11 -6,30 -3,24 -1,13 v 33 l 2,22 2,9 3,14 5,21 7,21 11,24 11,19 10,14 9,11 11,12 10,11 8,7 11,8 10,4 h 16 l 19,-5 33,-13 19,-10 19,-12 10,-8 5,-4 9,-12 5,-15 1,-15 -2,-19 -5,-23 -9,-27 -13,-27 -11,-18 -12,-17 -12,-14 -8,-8 -7,-8 L 215,82 201,71 184,59 162,46 146,38 129,30 113,24 109,23 Z M 261,94 l 1,4.000004 8,8.999996 13,18 11,18 11,21 11,28 8,25 2,5 52,19 8,3 3,-1 L 375,209 360,176 346,149 334,130 323,117 307,105 291,97.000004 281,94 Z m -217,112 -7,7 -8,13 -4,11 -2,10 v 28 l 4,15 10,24 14,27 17,28 15,24 5,7 h 2 l 21,-66 -1,-4 -8,-9 -13,-18 -14,-23 -12,-23 -9,-23 -7,-24 -1,-4 z m 271,95 -11,13 -14,11 -21,13 -22,12 -31,12 -20,6 -18,3 -9,23 -5,18 -2,13 v 8 l 1,1 16,-1 28,-5 29,-8 23,-8 21,-9 16,-8 18,-10 12,-8 13,-10 10,-9 6,-5 7,-8 8,-10 2,-5 -5,-6 -14,-9 -21,-9 -15,-5 z m 70,51 -12,13 -6,7 -8,7 -16,13 -20,13 -18,10 -25,12 -29,11 -27,8 -26,6 -19,3 1,5 8,16 10,18 11,13 10,8 13,8 15,7 20,8 17,9 17,12 13,11 9,8 7,8 9,11 2,-1 3,-21 3,-13 1,-5 12,-48 1,7 2,48 15,7 h 3 l -1,-14 v -19 l 3,-19 5,-15 7,-19 6,-25 2,-13 1,-14 v -13 l -2,-20 -5,-22 -6,-16 -5,-10 z";

    // Letter glyphs (remaining paths in draw order).
    private const string WordmarkGlyph1D = "m 2261,430 h 87 v 96 h -87 z";
    private const string WordmarkGlyph2D = "m 1885,227 h 81 v 299 h -81 z";
    private const string WordmarkGlyph3D = "m 1373,219 h 17 l 18,2 15,4 12,5 11,7 10,9 8,10 8,15 6,18 4,19 3,29 v 189 h -80 l -1,-173 -2,-22 -4,-16 -5,-9 -5,-6 -12,-6 -9,-2 h -16 l -20,3 -19,5 -6,1 v 225 h -81 V 227 h 80 l 1,15 25,-12 21,-7 13,-3 z";
    private const string WordmarkGlyph4D = "m 1027,219 h 21 l 21,2 19,4 19,7 14,8 11,9 8,8 9,13 8,16 6,19 4,24 1,14 v 15 l -5,46 -1,6 H 986 l 2,17 3.99997,12 7,10 11.00003,7 13,4 17,2 h 19 l 50,-2 43,-3 h 5 l 1,19 v 41 l -33,7 -39,6 -31,3 h -40 L 992.99997,530 975,525 l -19,-9 -13,-10 -8,-8 -9,-13 -8,-16 -6,-18 -5,-25 -2,-20 v -49 l 3,-26 5,-22 5,-15 9,-19 9,-13 9,-10 11,-10 13,-8 13,-6 15.99997,-5 L 1015,220 Z m 2,66 -12,2 -12,5 -7.00003,6 -7,11 -3.99997,14 -2,16 v 10 h 104 l -1,-20 -3,-15 -4,-10 -7,-9 -10,-6 -10,-3 -8,-1 z";
    private const string WordmarkGlyph5D = "m 2052,143 h 80 v 84 h 74 v 68 h -74 l 1,144 2,10 4,7 5,3 4,1 h 55 l 3,49 v 15 l -5,2 -35,6 -8,1 h -32 l -19,-3 -15,-5 -12,-7 -11,-11 -6,-10 -5,-13 -5,-25 -1,-11 V 295 h -36 v -68 l 35,-1 z";
    private const string WordmarkGlyph6D = "m 2261,119 h 87 v 16 l -7,222 -1,19 h -71 l -3,-87 -5,-159 z";
    private const string WordmarkGlyph7D = "m 713,111 32,1 39,4 46,7 21,4 1,1 -1,16 -5,49 -15,-1 -63,-6 -33,-2 h -16 l -18,2 -16,5 -10,6 -8,9 -4,10 -1,6 v 9 l 2,9 5,8 9,8 16,8 20,8 60,20 26,11 18,10 12,9 13,13 8,13 5,13 4,20 1,14 v 15 l -2,20 -4,18 -6,16 -7,13 -9,12 -9,10 -16,12 -19,10 -21,7 -21,4 -9,1 h -39 l -38,-4 -43,-7 -34,-7 1,-13 7,-51 15,1 57,6 26,2 h 40 l 17,-4 12,-6 8,-7 6,-10 4,-13 v -21 l -4,-10 -7,-8 -11,-7 -15,-7 -27,-9 -33,-10 -28,-11 -20,-10 -12,-8 -11,-9 -9,-9 -10,-15 -6,-15 -4,-18 -1,-9 v -23 l 3,-22 5,-17 8,-16 6,-9 9,-10 7,-7 15,-10 17,-8 20,-6 17,-3 z";
    private const string WordmarkGlyph8D = "m 1885,107 h 81 v 81 h -81 z";
    private const string WordmarkGlyph9D = "m 1731,107 h 80 v 419 h -80 v -12 l -19,8 -26,8 -16,3 h -29 l -19,-3 -17,-5 -14,-7 -13,-10 -9,-10 -7,-11 -8,-17 -6,-21 -4,-25 -2,-26 v -42 l 2,-23 4,-23 6,-20 7,-16 10,-16 11,-12 12,-9 17,-9 16,-5 17,-3 11,-1 h 19 l 33,4 22,4 2,1 z m -66,182 -10,3 -10,6 -7,8 -8,16 -5,21 -2,23 v 20 l 2,27 4,18 8,16 7,7 10,5 8,2 h 27 l 25,-4 16,-4 1,-1 V 295 l -16,-3 -29,-3 z";

    /// <summary>Paths in original logo.svg order (plume → glyphs → window → … → rocket body).</summary>
    private static readonly string[] WordmarkPathOrder =
    [
        RocketPlumeD,
        WordmarkGlyph1D,
        WordmarkGlyph2D,
        WordmarkGlyph3D,
        WordmarkGlyph4D,
        WordmarkGlyph5D,
        RocketWindowD,
        WordmarkGlyph6D,
        WordmarkGlyph7D,
        WordmarkGlyph8D,
        WordmarkGlyph9D,
        RocketBodyD,
    ];

    /// <summary>
    /// Full Sendit! wordmark (rocket + letters), filled with highlight.
    /// Served at /api/v1/branding/logo.svg — same in-process model as the rocket favicon.
    /// </summary>
    public static string ThemeWordmarkLogoSvg(string? highlight)
    {
        var hex = ParseOrDefault(highlight).ToHex();
        var sb = new StringBuilder(4096);
        sb.Append("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 2350 646\" width=\"2350\" height=\"646\" style=\"display:block\">");
        foreach (var d in WordmarkPathOrder)
        {
            sb.Append("<path fill=\"");
            sb.Append(hex);
            sb.Append("\" d=\"");
            sb.Append(d);
            sb.Append("\"/>");
        }
        sb.Append("</svg>");
        return sb.ToString();
    }

    /// <summary>Email header size (CSS max ~200×50 at 2× retina).</summary>
    public const int EmailLogoMaxWidth = 400;
    public const int EmailLogoMaxHeight = 100;

    /// <summary>Process-local cache of rendered wordmark PNGs keyed by highlight hex + size.</summary>
    private static readonly ConcurrentDictionary<string, byte[]> WordmarkPngCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Process-local cache of CTA button PNGs keyed by highlight + label + scale.</summary>
    private static readonly ConcurrentDictionary<string, (byte[] Png, int CssW, int CssH)> CtaButtonPngCache =
        new(StringComparer.Ordinal);

    /// <summary>CSS-pixel height of the email primary CTA (matches ~web primary button).</summary>
    public const int EmailCtaHeightCss = 40;

    /// <summary>
    /// Rasterize the themed wordmark to PNG (transparent background) from the same SVG paths
    /// as <see cref="ThemeWordmarkLogoSvg"/>. Used for email headers and
    /// <c>/api/v1/branding/logo.png</c>. Regenerates when <paramref name="highlight"/> changes.
    /// </summary>
    /// <param name="maxWidth">Output max width in pixels (default email header 2×).</param>
    /// <param name="maxHeight">Output max height in pixels.</param>
    public static byte[] ThemeWordmarkLogoPng(
        string? highlight,
        int maxWidth = EmailLogoMaxWidth,
        int maxHeight = EmailLogoMaxHeight)
    {
        maxWidth = Math.Clamp(maxWidth, 32, 2400);
        maxHeight = Math.Clamp(maxHeight, 16, 1200);
        var hex = ParseOrDefault(highlight).ToHex();
        var cacheKey = $"{hex}|{maxWidth}x{maxHeight}";
        return WordmarkPngCache.GetOrAdd(cacheKey, _ => RenderWordmarkPng(hex, maxWidth, maxHeight));
    }

    /// <summary>
    /// Raster primary CTA for email (highlight fill + dark uppercase label).
    /// Baked pixels so Outlook dark mode cannot recolour the control (HTML/CSS fills get inverted).
    /// </summary>
    public static byte[] ThemeCtaButtonPng(
        string label,
        string? highlight,
        out int cssWidth,
        out int cssHeight,
        int scale = 2)
    {
        scale = Math.Clamp(scale, 1, 3);
        var text = (label ?? "").Trim().ToUpperInvariant();
        if (text.Length == 0) text = "CONTINUE";
        var hex = ParseOrDefault(highlight).ToHex();
        var cacheKey = $"{hex}|{text}|s{scale}";
        var entry = CtaButtonPngCache.GetOrAdd(cacheKey, _ =>
        {
            var png = RenderCtaButtonPng(text, hex, scale, out var w, out var h);
            return (png, w, h);
        });
        cssWidth = entry.CssW;
        cssHeight = entry.CssH;
        return entry.Png;
    }

    private static byte[] RenderCtaButtonPng(
        string text,
        string hex,
        int scale,
        out int cssWidth,
        out int cssHeight)
    {
        // Parse #rrggbb
        var r = Convert.ToByte(hex.Substring(1, 2), 16);
        var g = Convert.ToByte(hex.Substring(3, 2), 16);
        var b = Convert.ToByte(hex.Substring(5, 2), 16);
        var fill = new SKColor(r, g, b);
        var labelColor = new SKColor(0x0a, 0x0a, 0x0a);

        var typeface =
            SKTypeface.FromFamilyName("DejaVu Sans", SKFontStyleWeight.Bold, SKFontStyleWidth.Normal, SKFontStyleSlant.Upright)
            ?? SKTypeface.FromFamilyName("Arial", SKFontStyleWeight.Bold, SKFontStyleWidth.Normal, SKFontStyleSlant.Upright)
            ?? SKTypeface.FromFamilyName("Helvetica", SKFontStyleWeight.Bold, SKFontStyleWidth.Normal, SKFontStyleSlant.Upright)
            ?? SKTypeface.Default;

        var fontSize = 13f * scale;
        using var font = new SKFont(typeface, fontSize);
        font.Edging = SKFontEdging.Antialias;
        font.Subpixel = true;

        // Tight ink bounds (includes side bearings) for true visual centring.
        font.MeasureText(text, out SKRect textBounds);
        var padX = 22f * scale;
        var cssH = EmailCtaHeightCss;
        var pixelH = cssH * scale;
        var pixelW = (int)Math.Ceiling(textBounds.Width + padX * 2);
        pixelW = Math.Clamp(pixelW, 140 * scale, 360 * scale);

        cssHeight = cssH;
        cssWidth = (int)Math.Round(pixelW / (double)scale);

        var info = new SKImageInfo(pixelW, pixelH, SKColorType.Rgba8888, SKAlphaType.Premul);
        using var surface = SKSurface.Create(info)
            ?? throw new InvalidOperationException("Skia surface create failed (native assets missing?).");
        var canvas = surface.Canvas;
        canvas.Clear(SKColors.Transparent);

        var radius = 6f * scale;
        using (var paint = new SKPaint { Color = fill, IsAntialias = true, Style = SKPaintStyle.Fill })
        {
            canvas.DrawRoundRect(new SKRect(0, 0, pixelW, pixelH), radius, radius, paint);
        }

        using (var paint = new SKPaint { Color = labelColor, IsAntialias = true })
        {
            // DrawText (x,y) is the baseline origin; bounds are relative to that origin.
            // Shift so the ink rectangle is centred in the pill both axes.
            var originX = (pixelW - textBounds.Width) / 2f - textBounds.Left;
            var originY = (pixelH - textBounds.Height) / 2f - textBounds.Top;
            canvas.DrawText(text, originX, originY, font, paint);
        }

        canvas.Flush();
        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 92)
            ?? throw new InvalidOperationException("CTA PNG encode failed.");
        return data.ToArray();
    }

    private static byte[] RenderWordmarkPng(string hex, int maxWidth, int maxHeight)
    {
        var svgXml = ThemeWordmarkLogoSvg(hex);
        using var svg = new SKSvg();
        if (svg.FromSvg(svgXml) is null || svg.Picture is null)
            throw new InvalidOperationException("Failed to parse themed wordmark SVG for PNG export.");

        var bounds = svg.Picture.CullRect;
        if (bounds.Width <= 0 || bounds.Height <= 0)
            throw new InvalidOperationException("Themed wordmark SVG has empty bounds.");

        var scale = Math.Min(maxWidth / bounds.Width, maxHeight / bounds.Height);
        if (scale <= 0 || float.IsNaN(scale) || float.IsInfinity(scale))
            scale = 1f;

        var w = Math.Max(1, (int)Math.Ceiling(bounds.Width * scale));
        var h = Math.Max(1, (int)Math.Ceiling(bounds.Height * scale));

        var info = new SKImageInfo(w, h, SKColorType.Rgba8888, SKAlphaType.Premul);
        using var surface = SKSurface.Create(info)
            ?? throw new InvalidOperationException("Skia surface create failed (native assets missing?).");
        var canvas = surface.Canvas;
        canvas.Clear(SKColors.Transparent);
        canvas.Scale(scale);
        canvas.Translate(-bounds.Left, -bounds.Top);
        canvas.DrawPicture(svg.Picture);
        canvas.Flush();

        using var image = surface.Snapshot();
        using var data = image.Encode(SKEncodedImageFormat.Png, 90)
            ?? throw new InvalidOperationException("PNG encode failed.");
        return data.ToArray();
    }

    /// <summary>
    /// Compact favicon: rocket mark only from the stock wordmark, filled with highlight.
    /// Drawn in a square viewBox with padding so the flame is not clipped in browser tab icons.
    /// </summary>
    public static string ThemeRocketFaviconSvg(string? highlight)
    {
        var hex = ParseOrDefault(highlight).ToHex();
        return
            $"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 512 512\" width=\"64\" height=\"64\">" +
            // 2px lower on a 64×64 favicon ⇒ +16 in 512 viewBox space (512/64).
            // scale 0.68 × 1.05² ≈ 0.75
            $"<g transform=\"translate(256 216) scale(0.75) translate(-200 -265)\">" +
            $"<path fill=\"{hex}\" d=\"{RocketBodyD}\"/>" +
            $"<path fill=\"{hex}\" d=\"{RocketWindowD}\"/>" +
            $"<path fill=\"{hex}\" d=\"{RocketPlumeD}\"/>" +
            "</g></svg>";
    }

    [GeneratedRegex("^[0-9A-Fa-f]{3}$")]
    private static partial Regex Hex3();

    [GeneratedRegex("^[0-9A-Fa-f]{6}$")]
    private static partial Regex Hex6();
}

public readonly record struct RgbColor(int R, int G, int B)
{
    public string ToHex() =>
        $"#{R:x2}{G:x2}{B:x2}";

    /// <summary>Multiply RGB by factor and clamp (factor &gt; 1 lightens, &lt; 1 darkens).</summary>
    public RgbColor Adjust(float factor)
    {
        static int Clamp(float v) => Math.Clamp((int)Math.Round(v), 0, 255);
        return new RgbColor(Clamp(R * factor), Clamp(G * factor), Clamp(B * factor));
    }
}
