using Sendit.Api.Configuration;
using Sendit.Api.Util;

namespace Sendit.Api.Endpoints;

/// <summary>
/// Public branding assets driven by SENDIT_HIGHLIGHT (theme CSS, wordmark logo, rocket favicon).
/// All SVGs are generated in-process — no logo.svg on disk.
/// </summary>
public static class BrandingEndpoints
{
    public static void MapBrandingEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/v1/branding");

        g.MapGet("/theme.css", (HttpContext http, SenditOptions options) =>
        {
            // Highlight rarely changes; cache so multi-page navigations do not re-paint the nav/theme.
            SetBrandingCacheHeaders(http, options.Highlight);
            var css = HighlightColor.ToThemeCss(options.Highlight);
            return Results.Text(css, "text/css; charset=utf-8");
        });

        // Full wordmark — same in-process model as /favicon.ico.
        g.MapGet("/logo.svg", (HttpContext http, SenditOptions options) =>
        {
            SetBrandingCacheHeaders(http, options.Highlight);
            var svg = HighlightColor.ThemeWordmarkLogoSvg(options.Highlight);
            return Results.Text(svg, "image/svg+xml; charset=utf-8");
        });

        // Raster wordmark for email clients / places that need PNG (SENDIT_HIGHLIGHT).
        g.MapGet("/logo.png", (HttpContext http, SenditOptions options) =>
        {
            SetBrandingCacheHeaders(http, options.Highlight);
            var png = HighlightColor.ThemeWordmarkLogoPng(options.Highlight);
            return Results.File(png, "image/png");
        });

        // Rocket-only mark (same graphic as /favicon.ico), for explicit branding use.
        g.MapGet("/favicon.svg", (HttpContext http, SenditOptions options) =>
        {
            SetBrandingCacheHeaders(http, options.Highlight);
            var svg = HighlightColor.ThemeRocketFaviconSvg(options.Highlight);
            return Results.Text(svg, "image/svg+xml; charset=utf-8");
        });

        // Public crypto params: UDK wrap + optional send/collect link-password sk wrap match password KDF cost.
        app.MapGet("/api/v1/crypto/params", (SenditOptions options) =>
        {
            var iters = options.PasswordHashIterations > 0
                ? options.PasswordHashIterations
                : Services.PasswordHasher.DefaultIterations;
            return Results.Ok(new
            {
                passwordHashIterations = iters,
                udkWrapIterations = iters,
                udkWrapHash = "SHA-512",
                udkWrapAlg = "PBKDF2-SHA512-AES-256-GCM",
                // Same policy as UDK; used by crypto.js wrapSecretKeyWithPassword.
                skWrapIterations = iters,
                skWrapHash = "SHA-512",
                skWrapAlg = "PBKDF2-SHA512-AES-256-GCM"
            });
        });

        // Public UI config (no secrets). ipRestrictionsEnabled drives create-send Allowed IPs visibility.
        g.MapGet("/config", (SenditOptions options, Services.ClientIpCapability ipCap) =>
        {
            var color = HighlightColor.ParseOrDefault(options.Highlight);
            return Results.Ok(new
            {
                highlight = color.ToHex(),
                logoUrl = "/api/v1/branding/logo.svg",
                logoPngUrl = "/api/v1/branding/logo.png",
                faviconUrl = "/api/v1/branding/favicon.svg",
                themeCssUrl = "/api/v1/branding/theme.css",
                // Default true; false only after non-public canary or probe skip (see ClientIpCapability).
                ipRestrictionsEnabled = ipCap.IpRestrictionsEnabled,
                clientIpProbeFinished = ipCap.ProbeFinished,
                clientIpPublicVerified = ipCap.PublicClientIpVerified,
            });
        });
    }

    /// <summary>
    /// Browser cache for generated branding (logo/theme). Avoids logo/nav flicker on every
    /// multi-page click. Vary by highlight so color changes invalidate via ETag.
    /// </summary>
    private static void SetBrandingCacheHeaders(HttpContext http, string? highlight)
    {
        var hex = HighlightColor.ParseOrDefault(highlight).ToHex();
        http.Response.Headers.CacheControl = "public, max-age=86400, stale-while-revalidate=604800";
        http.Response.Headers.ETag = $"\"brand-{hex}\"";
    }

}
