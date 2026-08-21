using Sendit.Api.Configuration;
using Sendit.Api.Util;

namespace Sendit.Api.Tests;

public class EmailHtmlTemplateTests
{
    [Fact]
    public void Render_logo_is_cid_only_never_remote_url()
    {
        var opts = new SenditOptions { PublicBaseUrl = "https://sendit.example.com" };
        var html = EmailHtmlTemplate.Render(
            "Email verification",
            "<p>Hello</p>",
            opts,
            preheader: "Your code");

        Assert.Contains("src=\"cid:sendit-logo.png\"", html);
        Assert.Contains(EmailHtmlTemplate.LogoCidSrc, html);
        Assert.DoesNotContain("/api/v1/branding/logo", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=\"http", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LogoContentId_matches_cid_src()
    {
        Assert.Equal("sendit-logo.png", EmailHtmlTemplate.LogoContentId);
        Assert.Equal("cid:sendit-logo.png", EmailHtmlTemplate.LogoCidSrc);
    }

    [Fact]
    public void Render_uses_non_image_gutters_top_and_bottom()
    {
        var html = EmailHtmlTemplate.Render("Title", "<p>Body</p>");

        Assert.DoesNotContain("email-gutter.png", html);
        var gutter = EmailHtmlTemplate.GutterRowHtml(EmailHtmlTemplate.OuterPadPx);
        var first = html.IndexOf(gutter, StringComparison.Ordinal);
        Assert.True(first >= 0, "expected top gutter");
        var second = html.IndexOf(gutter, first + gutter.Length, StringComparison.Ordinal);
        Assert.True(second > first, "expected bottom gutter matching top");
        Assert.Contains("&nbsp;", html);
        Assert.Contains("&#8203;", html);
    }

    [Fact]
    public void CtaButton_primary_is_cid_png_not_html_fill()
    {
        var html = EmailHtmlTemplate.CtaButton(
            "https://sendit.example.com/dashboard",
            "Open dashboard",
            "#0080ff");

        Assert.Contains("cid:cta-button.png", html);
        Assert.Contains("alt=\"OPEN DASHBOARD\"", html);
        Assert.Contains("OPEN DASHBOARD", html);
        // No solid HTML button that Outlook can recolour
        Assert.DoesNotContain("v:roundrect", html);
        Assert.DoesNotContain("linear-gradient(#0080ff", html);
    }

    [Fact]
    public void TryParseCtaButtonAlt_reads_label()
    {
        var html = EmailHtmlTemplate.CtaButton("https://x/y", "Reset password", "#c8ab37");
        var alt = EmailHtmlTemplate.TryParseCtaButtonAlt(html);
        Assert.Equal("RESET PASSWORD", alt);
    }

    [Fact]
    public void BoldLabelLine_highlights_id_value()
    {
        var send = EmailHtmlTemplate.BoldLabelLine("Send id:", "abc123", "#00ff88");
        Assert.Contains("Send id:", send);
        Assert.Contains("abc123", send);
        Assert.Contains("color:#00ff88", send);
    }

    [Fact]
    public void ThemeCtaButtonPng_is_png_and_varies_by_highlight()
    {
        var gold = HighlightColor.ThemeCtaButtonPng("OPEN DASHBOARD", "#c8ab37", out var w1, out var h1);
        var blue = HighlightColor.ThemeCtaButtonPng("OPEN DASHBOARD", "#0080ff", out var w2, out var h2);
        Assert.True(gold.Length > 100);
        Assert.True(blue.Length > 100);
        Assert.Equal(0x89, gold[0]);
        Assert.Equal((byte)'P', gold[1]);
        Assert.True(w1 > 80 && h1 == HighlightColor.EmailCtaHeightCss);
        Assert.Equal(h1, h2);
        Assert.False(gold.SequenceEqual(blue));
    }
}
