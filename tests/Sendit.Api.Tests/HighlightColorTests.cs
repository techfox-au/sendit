using Sendit.Api.Util;

namespace Sendit.Api.Tests;

public class HighlightColorTests
{
    [Theory]
    [InlineData("#c8ab37", 200, 171, 55)]
    [InlineData("c8ab37", 200, 171, 55)]
    [InlineData("#C8AB37", 200, 171, 55)]
    [InlineData("#abc", 170, 187, 204)]
    public void Parses_hex(string input, int r, int g, int b)
    {
        Assert.True(HighlightColor.TryParse(input, out var c));
        Assert.Equal(r, c.R);
        Assert.Equal(g, c.G);
        Assert.Equal(b, c.B);
    }

    [Theory]
    [InlineData("")]
    [InlineData("red")]
    [InlineData("#gg0000")]
    [InlineData("#12")]
    public void Rejects_invalid(string input)
    {
        Assert.False(HighlightColor.TryParse(input, out _));
    }

    [Fact]
    public void ParseOrDefault_falls_back_to_gold()
    {
        var c = HighlightColor.ParseOrDefault("not-a-color");
        Assert.Equal("#c8ab37", c.ToHex());
    }

    [Fact]
    public void ToCssVars_contains_primary()
    {
        var css = HighlightColor.ToCssVars(new RgbColor(0, 128, 255));
        Assert.Contains("--primary: #0080ff", css);
        Assert.Contains("--accent-rgb: 0, 128, 255", css);
    }

    [Theory]
    [InlineData("#random")]
    [InlineData("random")]
    [InlineData("#RANDOM")]
    [InlineData("  #Random  ")]
    public void IsRandomToken_accepts_random(string input)
    {
        Assert.True(HighlightColor.IsRandomToken(input));
        Assert.False(HighlightColor.TryParse(input, out _));
    }

    [Theory]
    [InlineData("#c8ab37")]
    [InlineData("red")]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("#rand")]
    public void IsRandomToken_rejects_non_random(string? input)
    {
        Assert.False(HighlightColor.IsRandomToken(input));
    }

    [Fact]
    public void RandomAccent_is_deterministic_with_seeded_rng()
    {
        var a = HighlightColor.RandomAccent(new Random(42));
        var b = HighlightColor.RandomAccent(new Random(42));
        Assert.Equal(a.ToHex(), b.ToHex());
        Assert.Matches("^#[0-9a-f]{6}$", a.ToHex());
        Assert.True(HighlightColor.IsDistinctAccent(a));
    }

    [Fact]
    public void RandomAccent_never_near_black_grey_or_white()
    {
        var rng = new Random(12345);
        var darkBg = new RgbColor(0x12, 0x12, 0x12);
        var label = new RgbColor(0x0a, 0x0a, 0x0a);
        for (var i = 0; i < 500; i++)
        {
            var c = HighlightColor.RandomAccent(rng);
            Assert.True(
                HighlightColor.IsDistinctAccent(c),
                $"Sample #{i} {c.ToHex()} failed IsDistinctAccent");

            var y = HighlightColor.RelativeLuminance(c);
            Assert.True(y <= 0.72, $"{c.ToHex()} too light (Y={y:F3})");

            var vsBg = HighlightColor.ContrastRatio(c, darkBg);
            Assert.True(vsBg >= 4.5, $"{c.ToHex()} contrast vs bg {vsBg:F2} < 4.5");

            var vsLabel = HighlightColor.ContrastRatio(c, label);
            Assert.True(vsLabel >= 4.5, $"{c.ToHex()} contrast vs label {vsLabel:F2} < 4.5");

            var chroma = (Math.Max(c.R, Math.Max(c.G, c.B)) - Math.Min(c.R, Math.Min(c.G, c.B))) / 255.0;
            Assert.True(chroma >= 0.28, $"{c.ToHex()} chroma {chroma:F3} too low (grey)");
        }
    }

    [Theory]
    [InlineData(0, 0, 0)]       // black
    [InlineData(20, 20, 20)]    // near-black
    [InlineData(40, 40, 80)]    // dark navy — low contrast on #121212
    [InlineData(255, 255, 255)] // white
    [InlineData(240, 240, 240)] // near-white
    [InlineData(128, 128, 128)] // mid grey
    [InlineData(100, 105, 110)] // low-chroma grey
    public void IsDistinctAccent_rejects_black_grey_white(int r, int g, int b)
    {
        Assert.False(HighlightColor.IsDistinctAccent(new RgbColor(r, g, b)));
    }

    [Theory]
    [InlineData(200, 171, 55)]  // default gold
    [InlineData(0, 160, 255)]   // bright blue (passes bg + dark-label contrast)
    [InlineData(240, 90, 110)]  // bright coral
    public void IsDistinctAccent_accepts_vivid_accents(int r, int g, int b)
    {
        Assert.True(HighlightColor.IsDistinctAccent(new RgbColor(r, g, b)));
    }

    [Fact]
    public void ContrastRatio_white_on_black_is_21()
    {
        var ratio = HighlightColor.ContrastRatio(new RgbColor(255, 255, 255), new RgbColor(0, 0, 0));
        Assert.InRange(ratio, 20.9, 21.1);
    }

    [Fact]
    public void FromHsl_red_and_mid_grey()
    {
        var red = HighlightColor.FromHsl(0, 1, 0.5);
        Assert.Equal("#ff0000", red.ToHex());
        var grey = HighlightColor.FromHsl(0, 0, 0.5);
        Assert.Equal("#808080", grey.ToHex());
    }

    [Fact]
    public void ThemeWordmarkLogoSvg_uses_highlight()
    {
        var themed = HighlightColor.ThemeWordmarkLogoSvg("#0080ff");
        Assert.Contains("fill=\"#0080ff\"", themed);
        Assert.Contains("viewBox=\"0 0 2350 646\"", themed);
        Assert.DoesNotContain("c8ab37", themed, StringComparison.OrdinalIgnoreCase);
        // Rocket + letter paths
        Assert.True(themed.Split("<path ", StringSplitOptions.None).Length - 1 >= 12);
    }

    [Fact]
    public void ThemeRocketFaviconSvg_uses_highlight()
    {
        var themed = HighlightColor.ThemeRocketFaviconSvg("#0080ff");
        Assert.Contains("fill=\"#0080ff\"", themed);
        Assert.Contains("viewBox=\"0 0 512 512\"", themed);
    }

    [Fact]
    public void ThemeWordmarkLogoPng_is_png_and_varies_by_highlight()
    {
        var gold = HighlightColor.ThemeWordmarkLogoPng("#c8ab37");
        var blue = HighlightColor.ThemeWordmarkLogoPng("#0080ff");
        Assert.True(gold.Length > 200);
        Assert.True(blue.Length > 200);
        // PNG magic
        Assert.Equal(0x89, gold[0]);
        Assert.Equal((byte)'P', gold[1]);
        Assert.Equal((byte)'N', gold[2]);
        Assert.Equal((byte)'G', gold[3]);
        // Different fill colour should change the raster (usually).
        Assert.False(gold.SequenceEqual(blue));
    }
}
