#!/usr/bin/env python3
"""
Build production static assets from src/frontend/ into public/.

- Minifies first-party JS/CSS (comments + whitespace; no identifier mangling)
- Minifies HTML (comments + whitespace; inline script/style minified)
- Writes every built asset with a `.min.` name (e.g. app.min.js, style.min.css,
  login.min.html) and rewrites in-page references to those paths
- Minifies vendored third-party JS the same way into public/vendor/*.min.js
- Pins every external script tag (/js/*, /vendor/*) and the main stylesheet
  (/css/style.min.css) to Subresource Integrity (SRI) hashes of the built bytes

Does not pin /api/v1/branding/theme.css (generated at runtime from SENDIT_HIGHLIGHT).

Auditors should read src/frontend/ source, not public/ output.
Clean URLs (/login) map to *.min.html via nginx / Program.cs.
"""
from __future__ import annotations

import base64
import hashlib
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "frontend"
DST = ROOT / "public"

# First-party scripts emitted as public/js/<name>.min.js
_FIRST_PARTY_JS = (
    "vt-guard.js",  # earliest head load: view-transition AbortError guard
    "crypto.js",
    "user-data-key.js",
    "api.js",
    "app.js",
    "send.js",
    "view.js",
    "request.js",
    "pow.js",
    "dashboard.js",
    "audit.js",
    "auth-pages.js",
)

# Match classic <script src="...">…</script> (no module type required).
# Captures: attrs-before-src, quote, src value, attrs-after-src
_SCRIPT_SRC_RE = re.compile(
    r"<script(\s[^>]*?)\bsrc=(['\"])([^'\"]+)\2([^>]*)>\s*</script>",
    re.IGNORECASE,
)

# Match <link … href="…"> (stylesheet or other); self-closing optional.
_LINK_HREF_RE = re.compile(
    r"<link(\s[^>]*?)\bhref=(['\"])([^'\"]+)\2([^>]*)/?>",
    re.IGNORECASE,
)

_JS_WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$@")

# After `}`, a newline before these tokens triggers ASI (implicit `;`). Collapsing
# that newline without inserting `;` yields illegal `}return` / `}var` / etc.
# Do NOT include else/catch/finally/while — those continue the previous statement.
_JS_ASI_AFTER_BRACE = frozenset(
    {
        "return",
        "throw",
        "break",
        "continue",
        "var",
        "let",
        "const",
        "function",
        "class",
        "if",
        "for",
        "switch",
        "try",
        "debugger",
        "with",
        "import",
        "export",
        "async",
        "await",  # top-level / module; safe to force ASI after }
        "yield",
    }
)


def _js_leading_keyword(text: str, start: int) -> str:
    """Identifier/keyword at text[start:], or empty string."""
    if start >= len(text) or text[start] not in _JS_WORD:
        return ""
    j = start
    while j < len(text) and text[j] in _JS_WORD:
        j += 1
    return text[start:j]


def _js_asi_after_brace(out: list[str], text: str, pos: int) -> None:
    """
    If the last emitted char is `}` and the next non-ws code is an ASI-sensitive
    keyword, emit `;`. Needed when a newline (and/or comments) between them is removed.
    """
    if not out or out[-1] != "}":
        return
    j = pos
    n = len(text)
    while j < n and text[j] in " \t\r\n":
        j += 1
    kw = _js_leading_keyword(text, j)
    if kw in _JS_ASI_AFTER_BRACE:
        out.append(";")


def _could_be_regex(out: list[str]) -> bool:
    """
    Heuristic: '/' starts a regex if previous non-space token is not a value
    (identifier, number, ), ], }).
    """
    j = len(out) - 1
    while j >= 0 and out[j] in " \t\n\r":
        j -= 1
    if j < 0:
        return True
    prev = out[j]
    # After these, '/' is more likely division than regex.
    if prev.isalnum() or prev in ")_]$.":
        return False
    return True


def _js_need_space(left: str, right: str) -> bool:
    """True when collapsing whitespace would merge/break tokens."""
    if not left or not right:
        return False
    if left in _JS_WORD and right in _JS_WORD:
        return True
    # return /re/, case /re/, division after ident keeps a space before '/'
    if left in _JS_WORD and right == "/":
        return True
    # + +  ++  - -  -- ambiguity
    if left in "+-" and right in "+-=":
        return True
    # keep "in"/"of" readable after ] or ) is already word-boundary via punct
    return False


def minify_js(text: str) -> str:
    """
    Production JS minify without identifier mangling.

    Removes // and /* */ comments (regex-safe) and collapses unnecessary
    whitespace. String, regex, and template contents are preserved.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"  # code | squote | dquote | template | linecomment | blockcomment | regex

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "code":
            if c in " \t\r\n":
                j = i
                while j < n and text[j] in " \t\r\n":
                    j += 1
                left = out[-1] if out else ""
                right = text[j] if j < n else ""
                # Preserve ASI: `}\nreturn` must not become `}return`.
                before = len(out)
                _js_asi_after_brace(out, text, j)
                if len(out) != before:
                    i = j
                    continue
                # `)\n++x` / `]\n--x` similarly need a break (semicolon).
                if left in ")]" and right in "+-" and j + 1 < n and text[j + 1] == right:
                    out.append(";")
                    i = j
                    continue
                if _js_need_space(left, right):
                    out.append(" ")
                i = j
                continue
            if c == "'":
                state = "squote"
                out.append(c)
                i += 1
            elif c == '"':
                state = "dquote"
                out.append(c)
                i += 1
            elif c == "`":
                state = "template"
                out.append(c)
                i += 1
            elif c == "/" and nxt == "/":
                state = "linecomment"
                i += 2
            elif c == "/" and nxt == "*":
                state = "blockcomment"
                i += 2
            elif c == "/" and _could_be_regex(out):
                state = "regex"
                out.append(c)
                i += 1
            else:
                out.append(c)
                i += 1

        elif state == "squote":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == "'":
                state = "code"
                i += 1
            else:
                i += 1

        elif state == "dquote":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == '"':
                state = "code"
                i += 1
            else:
                i += 1

        elif state == "template":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == "`":
                state = "code"
                i += 1
            else:
                i += 1

        elif state == "linecomment":
            if c == "\n":
                state = "code"
                # `}\n//note\nfunction` — comment hid the ASI boundary from the whitespace path.
                _js_asi_after_brace(out, text, i + 1)
            i += 1

        elif state == "blockcomment":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
                _js_asi_after_brace(out, text, i)
            else:
                i += 1

        elif state == "regex":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == "/":
                # end of regex body; consume flags
                i += 1
                while i < n and text[i].isalpha():
                    out.append(text[i])
                    i += 1
                state = "code"
            else:
                i += 1

    return "".join(out).strip() + "\n"


# Back-compat name used by older call sites / docs
def strip_js_comments(text: str) -> str:
    return minify_js(text)


def minify_css(text: str) -> str:
    """
    Production CSS minify: strip comments and collapse whitespace.

    Conservative spacing rules so we never turn descendant selectors into
    compounds (``nav.links [data-nav-email]`` must keep its space) or glue
    multi-value properties (``calc(...) 24px``).
    """
    out: list[str] = []
    i = 0
    n = len(text)
    state = "code"  # code | squote | dquote | comment

    def last_sig() -> str:
        j = len(out) - 1
        while j >= 0 and out[j] in " \t\r\n":
            j -= 1
        return out[j] if j >= 0 else ""

    def is_ident_char(ch: str) -> bool:
        return ch.isalnum() or ch in "_-\\"

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if state == "code":
            if c == "/" and nxt == "*":
                state = "comment"
                i += 2
                continue
            if c == "'":
                state = "squote"
                out.append(c)
                i += 1
                continue
            if c == '"':
                state = "dquote"
                out.append(c)
                i += 1
                continue
            if c in " \t\r\n":
                j = i
                while j < n and text[j] in " \t\r\n":
                    j += 1
                left = last_sig()
                right = text[j] if j < n else ""
                if left and right:
                    # Drop space only around punctuation that never needs it.
                    drop = False
                    if left in "{};," or right in "{};,":
                        drop = True
                    elif left in ">~" or right in ">~":
                        drop = True  # sibling combinators (a>b is valid)
                    elif left == ":" and right not in "(":
                        # color:#fff or a:hover — no space after :
                        drop = True
                    elif right == ":" and left in ")}":
                        drop = True
                    elif left == "(" or right == ")":
                        drop = True  # inside fn( ... ) edges
                    # CSS calc(): + and - REQUIRE surrounding whitespace (CSS Values).
                    # Never strip spaces next to + / - (a+b sibling also stays valid).
                    if left in "+-" or right in "+-":
                        drop = False
                    # Descendant attribute selector: nav.links [data-…]
                    if right == "[" and is_ident_char(left):
                        drop = False
                    if left == ")" and (is_ident_char(right) or right in ".("):
                        drop = False
                    if is_ident_char(left) and is_ident_char(right):
                        drop = False
                    if is_ident_char(left) and right in ".#*":
                        drop = False
                    if not drop and out[-1:] != [" "]:
                        out.append(" ")
                i = j
                continue
            out.append(c)
            i += 1

        elif state == "squote":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == "'":
                state = "code"
                i += 1
            else:
                i += 1

        elif state == "dquote":
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
            elif c == '"':
                state = "code"
                i += 1
            else:
                i += 1

        elif state == "comment":
            if c == "*" and nxt == "/":
                state = "code"
                i += 2
            else:
                i += 1

    return "".join(out).strip() + "\n"


def strip_css_comments(text: str) -> str:
    return minify_css(text)


def _minify_html_tag(tag: str) -> str:
    """Collapse whitespace inside a single tag; preserve quoted attribute values."""
    out: list[str] = []
    i = 0
    n = len(tag)
    state = "code"  # code | squote | dquote
    while i < n:
        c = tag[i]
        if state == "code":
            if c in " \t\r\n":
                j = i
                while j < n and tag[j] in " \t\r\n":
                    j += 1
                left = out[-1] if out else ""
                right = tag[j] if j < n else ""
                # Keep a single space between attributes / before /> ; drop around = and after <
                if left and right and left not in "<=/" and right not in "=>/":
                    out.append(" ")
                i = j
                continue
            if c == "'":
                state = "squote"
            elif c == '"':
                state = "dquote"
            out.append(c)
            i += 1
        elif state == "squote":
            out.append(c)
            if c == "'":
                state = "code"
            i += 1
        else:  # dquote
            out.append(c)
            if c == '"':
                state = "code"
            i += 1
    return "".join(out)


def minify_html(text: str) -> str:
    """
    Production HTML minify:
    - strip comments (not <!--[if …]>)
    - collapse whitespace inside tags and between tags
    - minify inline <script> with minify_js and <style> with minify_css
    - leave <pre> / <textarea> body text untouched
    """
    out: list[str] = []
    i = 0
    n = len(text)

    def is_open_tag(pos: int, name: str) -> bool:
        """True if text[pos] is '<' starting an opening tag named `name`."""
        if text[pos] != "<":
            return False
        if text[pos : pos + 1 + len(name)].lower() != "<" + name.lower():
            return False
        after = pos + 1 + len(name)
        return after < n and text[after] in " \t\r\n/>"

    def read_open_tag_end(pos: int) -> int:
        """Index just after '>' of the tag starting at pos."""
        k = pos + 1
        state = "code"
        while k < n:
            c = text[k]
            if state == "code":
                if c == ">":
                    return k + 1
                if c == "'":
                    state = "squote"
                elif c == '"':
                    state = "dquote"
            elif state == "squote" and c == "'":
                state = "code"
            elif state == "dquote" and c == '"':
                state = "code"
            k += 1
        return n

    def read_until_close_tag(pos: int, name: str) -> tuple[str, int]:
        """Return (inner, index_after_closing_tag) for </name>."""
        close = re.compile(rf"</{name}\s*>", re.IGNORECASE)
        m = close.search(text, pos)
        if not m:
            return text[pos:], n
        return text[pos : m.start()], m.end()

    while i < n:
        # Comments
        if text.startswith("<!--", i):
            end = text.find("-->", i + 4)
            if end < 0:
                break
            # Keep IE conditionals if any
            if text.startswith("<!--[if", i):
                out.append(text[i : end + 3])
            i = end + 3
            continue

        if text[i] != "<":
            # Text node: collapse whitespace; keep edge spaces for inline layout
            j = i
            while j < n and text[j] != "<":
                j += 1
            chunk = text[i:j]
            stripped = chunk.strip()
            if stripped:
                lead = " " if chunk[0].isspace() else ""
                trail = " " if chunk[-1].isspace() else ""
                out.append(lead + re.sub(r"\s+", " ", stripped) + trail)
            elif chunk and "\n" not in chunk and "\r" not in chunk:
                # Same-line space between tags (e.g. </strong> <span>)
                out.append(" ")
            # else: formatting-only newlines/indent between tags — drop
            i = j
            continue

        # Special element bodies
        if is_open_tag(i, "script"):
            k = read_open_tag_end(i)
            open_tag = _minify_html_tag(text[i:k])
            inner, after = read_until_close_tag(k, "script")
            if inner.strip():
                body = minify_js(inner)
                out.append(open_tag + body.rstrip("\n") + "</script>")
            else:
                out.append(open_tag + "</script>")
            i = after
            continue

        if is_open_tag(i, "style"):
            k = read_open_tag_end(i)
            open_tag = _minify_html_tag(text[i:k])
            inner, after = read_until_close_tag(k, "style")
            body = minify_css(inner) if inner.strip() else ""
            out.append(open_tag + body.rstrip("\n") + "</style>")
            i = after
            continue

        if is_open_tag(i, "textarea") or is_open_tag(i, "pre"):
            name = "textarea" if is_open_tag(i, "textarea") else "pre"
            k = read_open_tag_end(i)
            open_tag = _minify_html_tag(text[i:k])
            inner, after = read_until_close_tag(k, name)
            out.append(open_tag + inner + f"</{name}>")
            i = after
            continue

        # Generic tag (opening, closing, or void)
        k = read_open_tag_end(i)
        out.append(_minify_html_tag(text[i:k]))
        i = k

    return "".join(out).strip() + "\n"


def sri_sha384(data: bytes) -> str:
    """W3C Subresource Integrity token for the given file bytes."""
    digest = hashlib.sha384(data).digest()
    return "sha384-" + base64.b64encode(digest).decode("ascii")


def write_text_lf(path: Path, text: str) -> None:
    """
    Write UTF-8 text with LF line endings only.

    Path.write_text() on Windows translates \\n → \\r\\n by default. SRI hashes
    are over exact bytes, so a CRLF build would pin hashes that fail after git
    stores LF (autocrlf) or on Linux deploys. Always emit LF for public assets.
    """
    data = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    path.write_bytes(data)


def _map_integrity(path: Path, dst: Path, out: dict[str, str]) -> None:
    rel = path.relative_to(dst).as_posix()
    raw = path.read_bytes()
    if b"\r" in raw:
        raise SystemExit(
            f"Build failed: {rel} contains CR bytes; SRI must use LF-only assets "
            f"(use write_text_lf)."
        )
    token = sri_sha384(raw)
    out["/" + rel] = token
    out[rel] = token


def with_min_name(path: str | Path) -> str:
    """
    Insert .min before the final extension: app.js → app.min.js,
    login.html → login.min.html. Leaves *.min.* unchanged.
    """
    p = Path(path)
    name = p.name
    if re.search(r"\.min\.[^.]+$", name):
        return p.as_posix() if isinstance(path, Path) or "/" in str(path) else name
    new_name = f"{p.stem}.min{p.suffix}"
    if str(p.parent) in ("", "."):
        return new_name
    return (p.parent / new_name).as_posix()


def rewrite_built_asset_refs(html: str) -> str:
    """Point script/link tags at .min asset paths used under public/."""

    def js_src(m: re.Match[str]) -> str:
        prefix, path, suffix = m.group(1), m.group(2), m.group(3)
        # path is like /js/app.js or /vendor/nacl-fast.js
        if re.search(r"\.min\.js$", path):
            return m.group(0)
        base = path.rsplit("/", 1)
        if len(base) == 2:
            dirpart, file = base
            return f"{prefix}{dirpart}/{with_min_name(file)}{suffix}"
        return f"{prefix}{with_min_name(path)}{suffix}"

    html = re.sub(
        r"""((?:src)=['"])((?:/)?(?:js|vendor)/[^'"]+\.js)(['"])""",
        js_src,
        html,
        flags=re.IGNORECASE,
    )
    html = html.replace("/css/style.css", "/css/style.min.css")
    html = html.replace("href=\"css/style.css\"", "href=\"css/style.min.css\"")
    html = html.replace("href='css/style.css'", "href='css/style.min.css'")
    return html


def collect_asset_integrity(dst: Path) -> dict[str, str]:
    """
    Map URL path → integrity=sha384-… for built /js/*, /vendor/* JS and
    /css/style.min.css (not branding theme.css).
    """
    out: dict[str, str] = {}
    for sub in ("js", "vendor"):
        root = dst / sub
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.js")):
            _map_integrity(path, dst, out)
    style = dst / "css" / "style.min.css"
    if style.is_file():
        _map_integrity(style, dst, out)
    return out


def _strip_sri_attrs(attrs: str) -> str:
    attrs = re.sub(r"\s*\bintegrity=(['\"])[^'\"]*\1", "", attrs, flags=re.I)
    attrs = re.sub(r"\s*\bcrossorigin=(['\"])[^'\"]*\1", "", attrs, flags=re.I)
    attrs = re.sub(r"\s*\bcrossorigin\b(?!=)", "", attrs, flags=re.I)
    return re.sub(r"\s+", " ", attrs).rstrip()


def pin_script_integrity(html: str, integrity_by_src: dict[str, str]) -> str:
    """
    Rewrite <script src="…"> tags that point at built /js or /vendor assets so
    they carry integrity + crossorigin (required for SRI checks).
    """

    def repl(m: re.Match[str]) -> str:
        before, quote, src, after = m.group(1), m.group(2), m.group(3), m.group(4)
        src_key = src.split("?", 1)[0].split("#", 1)[0]
        token = integrity_by_src.get(src_key)
        if token is None:
            return m.group(0)

        attrs = _strip_sri_attrs(before + after)
        return (
            f"<script{attrs} src={quote}{src}{quote} "
            f'integrity="{token}" crossorigin="anonymous"></script>'
        )

    return _SCRIPT_SRC_RE.sub(repl, html)


_HEAD_OPEN_RE = re.compile(r"(<head\b[^>]*>)", re.IGNORECASE)

# External (CSP script-src 'self'); path must match collect_asset_integrity keys.
_VT_GUARD_SRC = "/js/vt-guard.min.js"


def inject_view_transition_abort_guard(
    html: str, integrity_by_src: dict[str, str]
) -> str:
    """
    Insert early <head> script src for vt-guard (view-transition AbortError).
    Must be an external file: CSP is script-src 'self' (no unsafe-inline).
    """
    if _VT_GUARD_SRC in html or "vt-guard.min.js" in html:
        return html
    if not _HEAD_OPEN_RE.search(html):
        return html
    token = integrity_by_src.get(_VT_GUARD_SRC)
    if not token:
        raise SystemExit(
            f"Build failed: {_VT_GUARD_SRC} missing from integrity map "
            "(is vt-guard.js in _FIRST_PARTY_JS?)"
        )
    tag = (
        f'<script src="{_VT_GUARD_SRC}" '
        f'integrity="{token}" crossorigin="anonymous"></script>'
    )
    return _HEAD_OPEN_RE.sub(r"\1" + tag, html, count=1)


def pin_stylesheet_integrity(html: str, integrity_by_src: dict[str, str]) -> str:
    """
    Rewrite <link href="…"> for built /css/style.min.css so it carries integrity +
    crossorigin. Leaves /api/v1/branding/theme.css and other links alone.
    """

    def repl(m: re.Match[str]) -> str:
        before, quote, href, after = m.group(1), m.group(2), m.group(3), m.group(4)
        href_key = href.split("?", 1)[0].split("#", 1)[0]
        token = integrity_by_src.get(href_key)
        if token is None:
            return m.group(0)

        # after may include a trailing "/" from self-closing tags — drop it
        after = after.rstrip().rstrip("/").rstrip()
        attrs = _strip_sri_attrs(before + ((" " + after) if after else ""))
        closing = " />" if m.group(0).rstrip().endswith("/>") else ">"
        return (
            f"<link{attrs} href={quote}{href}{quote} "
            f'integrity="{token}" crossorigin="anonymous"{closing}'
        )

    return _LINK_HREF_RE.sub(repl, html)


def main() -> None:
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)

    css_dst = DST / "css"
    css_dst.mkdir(parents=True)
    write_text_lf(
        css_dst / "style.min.css",
        minify_css((SRC / "css" / "style.css").read_text(encoding="utf-8")),
    )

    js_dst = DST / "js"
    js_dst.mkdir(parents=True)
    for name in _FIRST_PARTY_JS:
        p = SRC / "js" / name
        if p.exists():
            out_name = with_min_name(name)
            write_text_lf(js_dst / out_name, minify_js(p.read_text(encoding="utf-8")))

    img_src = SRC / "img"
    if img_src.is_dir() and any(img_src.iterdir()):
        shutil.copytree(img_src, DST / "img")

    # Vendor: keep readable sources under src/frontend/vendor/; minify into public/
    vend_dst = DST / "vendor"
    vend_dst.mkdir(parents=True)
    for src_name in ("nacl-fast.js", "qrcode.js"):
        src_path = SRC / "vendor" / src_name
        if not src_path.is_file():
            raise SystemExit(f"Build failed: missing vendor source {src_path}")
        out_name = with_min_name(src_name)
        minified = minify_js(src_path.read_text(encoding="utf-8"))
        # Guard against ASI footguns (e.g. `}\nreturn` → `}return` SyntaxError).
        bad = re.search(
            r"\}(return|throw|break|continue|var|let|const|function|class|if|for)\b",
            minified,
        )
        if bad:
            raise SystemExit(
                f"Build failed: {out_name} has illegal '}}{bad.group(1)}' "
                f"(minifier dropped a required ASI semicolon). Fix minify_js."
            )
        write_text_lf(vend_dst / out_name, minified)

    # Hash built min assets once, then pin script/link tags in HTML.
    integrity_by_src = collect_asset_integrity(DST)
    if not any(k.startswith("/js/") for k in integrity_by_src):
        raise SystemExit("Build failed: no JS files to pin with SRI hashes")
    if "/css/style.min.css" not in integrity_by_src:
        raise SystemExit("Build failed: /css/style.min.css missing for SRI pin")
    for vend in ("/vendor/nacl-fast.min.js", "/vendor/qrcode.min.js"):
        if vend not in integrity_by_src:
            raise SystemExit(f"Build failed: {vend} missing for SRI pin")

    # Root + nested pages (e.g. collect/new.html → collect/new.min.html)
    for html in SRC.rglob("*.html"):
        rel = html.relative_to(SRC)
        # Skip anything under vendor (none expected) or other non-page dirs
        if rel.parts[0] in ("vendor", "js", "css", "img"):
            continue
        text = html.read_text(encoding="utf-8")
        text = rewrite_built_asset_refs(text)
        text = pin_script_integrity(text, integrity_by_src)
        text = pin_stylesheet_integrity(text, integrity_by_src)
        text = inject_view_transition_abort_guard(text, integrity_by_src)
        text = minify_html(text)
        out_rel = Path(with_min_name(rel.as_posix()))
        out = DST / out_rel
        out.parent.mkdir(parents=True, exist_ok=True)
        write_text_lf(out, text)

    # Sanity: every written page's first-party scripts + style.min.css must carry integrity
    missing_integrity = 0
    non_min_ref = 0
    for html_out in DST.rglob("*.html"):
        if not html_out.name.endswith(".min.html"):
            raise SystemExit(
                f"Build failed: HTML not named *.min.html: {html_out.relative_to(DST)}"
            )
        body = html_out.read_text(encoding="utf-8")
        for m in _SCRIPT_SRC_RE.finditer(body):
            src = m.group(3).split("?", 1)[0].split("#", 1)[0]
            if not (src.startswith("/js/") or src.startswith("/vendor/")
                    or src.startswith("js/") or src.startswith("vendor/")):
                continue
            if not re.search(r"\.min\.js$", src):
                non_min_ref += 1
                print(f"  non-min script ref: {html_out.relative_to(DST)} → {src}")
            tag = m.group(0)
            if "integrity=" not in tag or "crossorigin=" not in tag:
                missing_integrity += 1
                print(f"  missing SRI: {html_out.relative_to(DST)} → {src}")
        for m in _LINK_HREF_RE.finditer(body):
            href = m.group(3).split("?", 1)[0].split("#", 1)[0]
            if href not in ("/css/style.min.css", "css/style.min.css"):
                if href.endswith("style.css") and "branding" not in href:
                    non_min_ref += 1
                    print(f"  non-min css ref: {html_out.relative_to(DST)} → {href}")
                continue
            tag = m.group(0)
            if "integrity=" not in tag or "crossorigin=" not in tag:
                missing_integrity += 1
                print(f"  missing SRI: {html_out.relative_to(DST)} → {href}")
    if missing_integrity:
        raise SystemExit(
            f"Build failed: {missing_integrity} tag(s) missing integrity"
        )
    if non_min_ref:
        raise SystemExit(
            f"Build failed: {non_min_ref} reference(s) still point at non-.min assets"
        )

    # Sanity: crypto base64url line must survive minify
    crypto = (js_dst / "crypto.min.js").read_text(encoding="utf-8")
    if "replace(/\\//g" not in crypto and 'replace(/\\//g' not in crypto:
        # Accept either escaped form in file
        if r"replace(/\//g" not in crypto:
            raise SystemExit(
                "Build failed: crypto.min.js minify broke base64url regex. "
                "Check minify_js."
            )
    if "SenditCrypto" not in crypto:
        raise SystemExit("Build failed: SenditCrypto missing from crypto.min.js")

    # Verify integrity tokens match files on disk
    for sample_src, sample_path in (
        ("/js/api.min.js", DST / "js" / "api.min.js"),
        ("/css/style.min.css", DST / "css" / "style.min.css"),
    ):
        expected = integrity_by_src[sample_src]
        actual = sri_sha384(sample_path.read_bytes())
        if expected != actual:
            raise SystemExit(f"Build failed: SRI hash mismatch for {sample_src}")

    pinned = sorted({k for k in integrity_by_src if k.startswith("/")})
    js_bytes = sum(p.stat().st_size for p in (DST / "js").glob("*.js"))
    css_bytes = (DST / "css" / "style.min.css").stat().st_size
    html_count = sum(1 for _ in DST.rglob("*.min.html"))
    print(f"Built frontend → {DST}")
    print(
        f"  Minified assets: JS {js_bytes:,} B, CSS {css_bytes:,} B, "
        f"{html_count} HTML pages (all *.min.*)"
    )
    print(f"  SRI-pinned assets: {len(pinned)} ({', '.join(pinned[:3])}…)")


if __name__ == "__main__":
    main()

