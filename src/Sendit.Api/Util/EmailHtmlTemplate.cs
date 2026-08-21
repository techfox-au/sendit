using System.Globalization;
using System.Net;
using System.Text;
using Sendit.Api.Configuration;

namespace Sendit.Api.Util;

/// <summary>
/// Shared HTML shell for transactional email (OTP, password reset, notifications).
/// Forced dark theme matching the app (#121212 page, #1e1e1e card). Logo is
/// <c>cid:sendit-logo.png</c> (MIME-inlined by <see cref="Services.EmailSender"/>).
/// Top/bottom gutters are table spacers with real &amp;nbsp; content — not images
/// (clients that block images collapse spacer PNGs to zero height).
/// </summary>
public static class EmailHtmlTemplate
{
    public const string LogoContentId = "sendit-logo.png";
    public static string LogoCidSrc => "cid:" + LogoContentId;

    /// <summary>
    /// Primary CTA as a baked PNG (Outlook dark mode cannot recolour pixels).
    /// </summary>
    public const string CtaButtonContentId = "cta-button.png";
    public static string CtaButtonCidSrc => "cid:" + CtaButtonContentId;

    public const string PageBg = "#121212";
    public const string CardBg = "#1e1e1e";
    public const string TextColor = "#e0e0e0";
    public const string HeadingColor = "#ffffff";
    public const string MutedColor = "#b0b0b0";
    public const string CodeBg = "#2a2a2a";
    public const string CodeBorder = "#3a3a3a";
    public const string CtaText = "#0a0a0a";

    /// <summary>Dark gutter above the logo and below the card (must match).</summary>
    public const int OuterPadPx = 40;

    public const int LogoToCardGapPx = 16;

    public static string Render(
        string heading,
        string bodyHtml,
        SenditOptions? options = null,
        string? preheader = null)
    {
        var h = WebUtility.HtmlEncode(heading ?? "");
        var pre = string.IsNullOrWhiteSpace(preheader)
            ? ""
            : WebUtility.HtmlEncode(preheader.Trim());
        var highlight = HighlightColor.ParseOrDefault(options?.Highlight).ToHex();
        var gap = LogoToCardGapPx.ToString(CultureInfo.InvariantCulture);

        var sb = new StringBuilder(4096);
        sb.Append("<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\" ");
        sb.Append("\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n");
        sb.Append("<html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\" ");
        sb.Append("xmlns:v=\"urn:schemas-microsoft-com:vml\" ");
        sb.Append("xmlns:o=\"urn:schemas-microsoft-com:office:office\" ");
        sb.Append("style=\"background-color:").Append(PageBg).Append(" !important;margin:0;padding:0;\">");
        sb.Append("<head>");
        sb.Append("<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        sb.Append("<meta name=\"color-scheme\" content=\"dark only\">");
        sb.Append("<meta name=\"supported-color-schemes\" content=\"dark only\">");
        sb.Append("<meta name=\"x-apple-disable-message-reformatting\">");
        sb.Append("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">");
        sb.Append("<!--[if mso]><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch>");
        sb.Append("<o:AllowPNG/></o:OfficeDocumentSettings></xml><![endif]-->");
        sb.Append("<title>").Append(h).Append("</title>");
        sb.Append("<style type=\"text/css\">");
        sb.Append(":root{color-scheme:dark only;}");
        sb.Append("html,body{margin:0 !important;padding:0 !important;width:100% !important;");
        sb.Append("background-color:").Append(PageBg).Append(" !important;}");
        sb.Append("body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;}");
        sb.Append("img{border:0;outline:none;text-decoration:none;-ms-interpolation-mode:bicubic;}");
        sb.Append("body{font-size:16px;color:").Append(TextColor)
            .Append(";font-family:Arial,Helvetica,sans-serif;}");
        sb.Append("a{color:").Append(highlight).Append(";}");
        sb.Append("table,td{border-collapse:collapse;mso-table-lspace:0pt;mso-table-rspace:0pt;}");
        // Primary CTA: lock highlight + label in Outlook light/dark (data-ogsc/ogsb + media).
        sb.Append(PrimaryCtaForceCss(highlight));
        sb.Append("@media (prefers-color-scheme: light){");
        sb.Append("html,body,table.page-wrap,td.page-cell,td.gutter-cell{background-color:")
            .Append(PageBg).Append(" !important;}");
        sb.Append("td.card-cell,table.card-table{background-color:")
            .Append(CardBg).Append(" !important;}");
        sb.Append(PrimaryCtaForceCssRules(highlight));
        sb.Append("}");
        sb.Append("@media (prefers-color-scheme: dark){");
        sb.Append(PrimaryCtaForceCssRules(highlight));
        sb.Append("}");
        sb.Append("</style>");
        // MSO text-fill lock must sit outside the main <style> (conditional comments).
        sb.Append(PrimaryCtaMsoTextFillCss());
        sb.Append("</head>");

        sb.Append("<body bgcolor=\"").Append(PageBg).Append("\" ");
        sb.Append("style=\"margin:0;padding:0;width:100%;");
        sb.Append("font-size:16px;color:").Append(TextColor);
        sb.Append(";background-color:").Append(PageBg).Append(" !important;\">");

        if (pre.Length > 0)
        {
            sb.Append("<div style=\"display:none;font-size:1px;color:")
                .Append(PageBg).Append(";line-height:1px;");
            sb.Append("max-height:0;max-width:0;opacity:0;overflow:hidden;\">");
            sb.Append(pre).Append("</div>");
        }

        // Full-width dark page.
        sb.Append("<table role=\"presentation\" class=\"page-wrap\" width=\"100%\" ");
        sb.Append("border=\"0\" cellspacing=\"0\" cellpadding=\"0\" bgcolor=\"")
            .Append(PageBg).Append("\" ");
        sb.Append("style=\"width:100%;border-collapse:collapse;background-color:")
            .Append(PageBg).Append(" !important;\">");

        // TOP gutter (no image — works with images blocked).
        sb.Append(GutterRowHtml(OuterPadPx));

        // Content: logo + card
        sb.Append("<tr><td class=\"page-cell\" align=\"center\" valign=\"top\" bgcolor=\"")
            .Append(PageBg).Append("\" ");
        sb.Append("style=\"padding:0 16px;background-color:")
            .Append(PageBg).Append(" !important;\">");

        sb.Append("<img src=\"").Append(LogoCidSrc).Append("\" ");
        sb.Append("alt=\"Sendit!\" width=\"200\" style=\"max-width:200px;max-height:50px;");
        sb.Append("width:200px;height:auto;border:0;outline:none;text-decoration:none;");
        sb.Append("display:block;margin:0 auto ").Append(gap).Append("px;\"/>");

        sb.Append("<table role=\"presentation\" class=\"card-table\" width=\"600\" border=\"0\" ");
        sb.Append("cellspacing=\"0\" cellpadding=\"0\" bgcolor=\"").Append(CardBg).Append("\" ");
        sb.Append("style=\"width:100%;max-width:600px;border-collapse:collapse;");
        sb.Append("background-color:").Append(CardBg).Append(" !important;border-radius:8px;\">");
        sb.Append("<tr><td class=\"card-cell\" bgcolor=\"").Append(CardBg).Append("\" ");
        sb.Append("style=\"padding:36px 36px 48px;background-color:")
            .Append(CardBg).Append(" !important;border-radius:8px;\">");
        sb.Append("<h1 style=\"font-size:24px;font-weight:bold;margin:0 0 24px;color:")
            .Append(HeadingColor).Append(";\" align=\"center\">");
        sb.Append(h).Append("</h1>");
        sb.Append("<div style=\"color:").Append(TextColor)
            .Append(";font-size:16px;line-height:1.5;\">");
        sb.Append(bodyHtml);
        sb.Append("</div></td></tr></table>");

        sb.Append("</td></tr>");

        // BOTTOM gutter — same non-image spacer as top.
        sb.Append(GutterRowHtml(OuterPadPx));

        // Anti-clip sentinel: some clients (Gmail) strip purely decorative trailing space;
        // a final dark cell with a zero-width character keeps the gutter row in the layout.
        sb.Append("<tr><td bgcolor=\"").Append(PageBg).Append("\" ");
        sb.Append("style=\"padding:0;margin:0;background-color:").Append(PageBg)
            .Append(" !important;font-size:1px;line-height:1px;color:")
            .Append(PageBg).Append(";\">&#8203;</td></tr>");

        sb.Append("</table>");
        sb.Append("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Fixed-height dark gutter that does <b>not</b> use images.
    /// Single technique only (table cell + &amp;nbsp;) so WebKit does not stack an
    /// extra div and double the header/footer space.
    /// </summary>
    public static string GutterRowHtml(int heightPx)
    {
        if (heightPx < 8) heightPx = 8;
        var h = heightPx.ToString(CultureInfo.InvariantCulture);

        var sb = new StringBuilder(480);
        sb.Append("<tr><td class=\"gutter-cell\" align=\"center\" valign=\"top\" ");
        sb.Append("height=\"").Append(h).Append("\" bgcolor=\"").Append(PageBg).Append("\" ");
        sb.Append("style=\"height:").Append(h).Append("px;min-height:").Append(h).Append("px;");
        sb.Append("line-height:").Append(h).Append("px;font-size:").Append(h).Append("px;");
        sb.Append("mso-line-height-rule:exactly;padding:0;margin:0;");
        sb.Append("background-color:").Append(PageBg).Append(" !important;color:")
            .Append(PageBg).Append(";\">");
        // Real content so the cell is not empty (empty cells are collapsed).
        sb.Append("&nbsp;");
        sb.Append("</td></tr>");
        return sb.ToString();
    }

    public static string ParagraphsFromPlain(string plain)
    {
        if (string.IsNullOrEmpty(plain))
            return "";
        var parts = plain.Replace("\r\n", "\n").Split('\n');
        var sb = new StringBuilder();
        var buf = new StringBuilder();
        void Flush()
        {
            if (buf.Length == 0) return;
            sb.Append("<p style=\"margin:0 0 1em 0;color:")
                .Append(TextColor)
                .Append(";font-size:16px;line-height:1.5;\">");
            sb.Append(buf);
            sb.Append("</p>");
            buf.Clear();
        }
        foreach (var line in parts)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                Flush();
                continue;
            }
            if (buf.Length > 0)
                buf.Append("<br>");
            buf.Append(WebUtility.HtmlEncode(line));
        }
        Flush();
        return sb.ToString();
    }

    /// <summary>
    /// Resource id line: bold label + value in highlight colour.
    /// </summary>
    public static string BoldLabelLine(string label, string value, string? highlight = null)
    {
        var lab = (label ?? "").Trim();
        if (lab.Length > 0 && !lab.EndsWith(':'))
            lab += ":";
        var idColor = HighlightColor.ParseOrDefault(highlight).ToHex();
        return
            "<p style=\"margin:0 0 1em 0;color:" + TextColor +
            ";font-size:16px;line-height:1.5;\">" +
            "<strong style=\"font-weight:bold;color:" + HeadingColor + ";\">" +
            WebUtility.HtmlEncode(lab) +
            "</strong> " +
            "<span style=\"color:" + idColor + ";font-weight:bold;font-family:Consolas,Monaco,monospace;\">" +
            WebUtility.HtmlEncode(value ?? "") +
            "</span></p>";
    }

    /// <summary>
    /// CSS that pins primary CTA colours so Outlook light/dark mode does not invert them.
    /// Uses linear-gradient + data-ogsc/ogsb (goes inside the main &lt;style&gt; block).
    /// </summary>
    public static string PrimaryCtaForceCss(string highlightHex)
    {
        var bg = HighlightColor.ParseOrDefault(highlightHex).ToHex();
        var sb = new StringBuilder(700);
        sb.Append(PrimaryCtaForceCssRules(bg));
        // Outlook.com / Office 365 dark-mode recolour hooks (both original-style attrs).
        sb.Append("[data-ogsc] .cta-primary,[data-ogsb] .cta-primary,");
        sb.Append("[data-ogsc] .cta-primary a,[data-ogsb] .cta-primary a,");
        sb.Append("[data-ogsc] a.cta-primary,[data-ogsb] a.cta-primary,");
        sb.Append("[data-ogsc] .cta-primary-label,[data-ogsb] .cta-primary-label{");
        sb.Append("background-color:").Append(bg).Append(" !important;");
        sb.Append("background-image:linear-gradient(").Append(bg).Append(",").Append(bg)
            .Append(") !important;");
        sb.Append("background:").Append(bg).Append(" !important;");
        sb.Append("color:").Append(CtaText).Append(" !important;");
        sb.Append("-webkit-text-fill-color:").Append(CtaText).Append(" !important;}");
        return sb.ToString();
    }

    /// <summary>
    /// Desktop Outlook (Word) dark mode: lock CTA label colour via MSO text-fill gradient.
    /// Must be emitted as a conditional comment outside the main style element.
    /// </summary>
    public static string PrimaryCtaMsoTextFillCss()
    {
        return
            "<!--[if gte mso 16]><style type=\"text/css\">" +
            ".cta-primary-label{" +
            "mso-style-textfill-type:gradient;" +
            "mso-style-textfill-fill-two-color-stop-list:\"0 " + CtaText +
            " 0 100000,0 " + CtaText + " 0 100000\";" +
            "color:" + CtaText + " !important;}" +
            "</style><![endif]-->";
    }

    /// <summary>Shared .cta-primary colour rules (also nested under prefers-color-scheme).</summary>
    public static string PrimaryCtaForceCssRules(string highlightHex)
    {
        var bg = HighlightColor.ParseOrDefault(highlightHex).ToHex();
        return
            ".cta-primary,.cta-primary a,a.cta-primary,.cta-primary-label{" +
            "background-color:" + bg + " !important;" +
            "background-image:linear-gradient(" + bg + "," + bg + ") !important;" +
            "background:" + bg + " !important;" +
            "color:" + CtaText + " !important;" +
            "-webkit-text-fill-color:" + CtaText + " !important;" +
            "border-color:" + bg + " !important;" +
            "forced-color-adjust:none;-ms-high-contrast-adjust:none;}";
    }

    /// <summary>
    /// CTA button matching web UI (uppercase). Primary is a CID PNG so Outlook dark mode
    /// cannot recolour the fill (HTML/CSS fills are still rewritten by Outlook).
    /// Secondary remains an outlined HTML control.
    /// </summary>
    public static string CtaButton(
        string href,
        string label,
        string? highlight = null,
        bool secondary = false)
    {
        var h = WebUtility.HtmlEncode(href);
        var plainLabel = (label ?? "").Trim().ToUpperInvariant();
        if (plainLabel.Length == 0) plainLabel = "CONTINUE";
        var l = WebUtility.HtmlEncode(plainLabel);
        const string secondaryBorder = "#555555";
        const string secondaryText = "#b3b3b3";

        if (secondary)
        {
            return
                "<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" " +
                "style=\"margin:20px 0;\">" +
                "<tr><td style=\"border-radius:6px;background:transparent;" +
                "border:1px solid " + secondaryBorder + ";\">" +
                "<a href=\"" + h + "\" target=\"_blank\" style=\"display:inline-block;padding:11px 21px;" +
                "font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;" +
                "letter-spacing:0.04em;text-transform:uppercase;color:" + secondaryText + ";" +
                "text-decoration:none;border-radius:6px;background:transparent;\">" + l + "</a>" +
                "</td></tr></table>";
        }

        // Bake pixels (2× retina). EmailSender inlines the same CID from alt text + highlight.
        int cssW;
        int cssH;
        try
        {
            _ = HighlightColor.ThemeCtaButtonPng(plainLabel, highlight, out cssW, out cssH);
        }
        catch
        {
            // Skia/fonts unavailable at render-time tests without natives: size estimate.
            cssW = Math.Clamp(plainLabel.Length * 9 + 44, 140, 320);
            cssH = HighlightColor.EmailCtaHeightCss;
        }

        var w = cssW.ToString(CultureInfo.InvariantCulture);
        var ht = cssH.ToString(CultureInfo.InvariantCulture);
        return
            "<table role=\"presentation\" cellspacing=\"0\" cellpadding=\"0\" border=\"0\" " +
            "style=\"margin:20px 0;border-collapse:collapse;\">" +
            "<tr><td>" +
            "<a href=\"" + h + "\" target=\"_blank\" style=\"display:inline-block;border:0;" +
            "text-decoration:none;line-height:0;font-size:0;\">" +
            "<img src=\"" + CtaButtonCidSrc + "\" width=\"" + w + "\" height=\"" + ht + "\" " +
            "alt=\"" + l + "\" border=\"0\" " +
            "style=\"display:block;width:" + w + "px;height:" + ht + "px;border:0;outline:none;" +
            "text-decoration:none;-ms-interpolation-mode:bicubic;\"/>" +
            "</a></td></tr></table>";
    }

    /// <summary>Read uppercase label from a primary CTA &lt;img alt&gt; in HTML (for CID attach).</summary>
    public static string? TryParseCtaButtonAlt(string? html)
    {
        if (string.IsNullOrEmpty(html) || !html.Contains(CtaButtonContentId, StringComparison.Ordinal))
            return null;
        // Prefer alt before or after src=cid:cta-button.png
        var m = System.Text.RegularExpressions.Regex.Match(
            html,
            @"src=[""']cid:cta-button\.png[""'][^>]*\balt=[""']([^""']+)[""']",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (m.Success) return m.Groups[1].Value.Trim();
        m = System.Text.RegularExpressions.Regex.Match(
            html,
            @"\balt=[""']([^""']+)[""'][^>]*src=[""']cid:cta-button\.png[""']",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : null;
    }

    public static string CodeBlock(string code)
    {
        return
            "<p style=\"margin:16px 0;text-align:center;\">" +
            "<span style=\"display:inline-block;padding:12px 20px;font-size:28px;letter-spacing:0.2em;" +
            "font-family:Consolas,Monaco,monospace;font-weight:bold;color:" + HeadingColor +
            ";background:" + CodeBg + ";" +
            "border-radius:6px;border:1px solid " + CodeBorder + ";\">" +
            WebUtility.HtmlEncode(code) +
            "</span></p>";
    }
}
