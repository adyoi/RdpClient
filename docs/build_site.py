#!/usr/bin/env python3
"""Render the repository's Markdown into a static site for GitHub Pages.

Kept deliberately small: the documentation is Markdown that is also readable on
GitHub itself, so the site only needs to render it, apply a shared shell and
copy the images. A full static-site generator would add a dependency and a
build step for no gain at this size.

Three things it has to get right, each of which produced a visibly broken page
before:

* The README opens with a ``<div align="center">`` hero. Python-Markdown does
  not process Markdown inside a raw HTML block, so the title, the tagline and
  the badges rendered as literal text. The hero is lifted out and rendered as
  markup instead.
* Links to files whose names contain upper-case letters were left untouched,
  because the rewrite pattern was lower-case only, so ``CHANGELOG.md`` became a
  dead link while a rendered ``changelog.html`` sat next to it unreferenced.
* A document linked from the README but missing from PAGES rendered as a 404.
  The page list is now derived from the links in the index.
"""

from __future__ import annotations

import html
import re
import string
import shutil
import pathlib

import markdown

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "_site"
BLOB = "https://github.com/adyoi/RdpClient/blob/main"

# Rendered in this order, so the navigation reads in the order a reader needs.
PAGES = [
    ("index.html", "Overview", "README.md"),
    ("protocol.html", "Protocol", "docs/protocol.md"),
    ("architecture.html", "Architecture", "docs/architecture.md"),
    ("research.html", "Research", "docs/research.md"),
    ("wsl-rdp-lab.html", "WSL test lab", "docs/wsl-rdp-lab.md"),
    ("changelog.html", "Changelog", "CHANGELOG.md"),
    ("agents.html", "Working notes", "AGENTS.md"),
    ("contributing.html", "Contributing", "CONTRIBUTING.md"),
]

# Rendered as HTML so the nested heading structure is still navigable.
# Nav keys are spelled out rather than derived from the file name: deriving
# them made the template depend on how a hyphen happens to be normalised.
NAV = [
    ("index.html", "Overview", "cls_index"),
    ("protocol.html", "Protocol", "cls_protocol"),
    ("architecture.html", "Architecture", "cls_architecture"),
    ("research.html", "Research", "cls_research"),
    ("wsl-rdp-lab.html", "WSL test lab", "cls_wsl"),
    ("changelog.html", "Changelog", "cls_changelog"),
    ("agents.html", "Working notes", "cls_agents"),
    ("contributing.html", "Contributing", "cls_contributing"),
]

NAV_LABEL = {name: label for name, label, _key in NAV}

MARKDOWN_EXTENSIONS = [
    "tables",
    "fenced_code",
    "toc",
    "attr_list",
    "sane_lists",
    "smarty",
]

TEMPLATE = string.Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$TITLE &middot; RdpClient</title>
<meta name="description" content="An RDP client for Windows, written from Microsoft's public Open Specifications.">
<link rel="icon" href="assets/logo-64.png">
<link rel="stylesheet" href="assets/site.css">
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<div class="wrap">
  <input type="checkbox" id="navtoggle" class="navtoggle">
  <header class="topbar">
    <label for="navtoggle" class="burger" aria-label="Toggle navigation">
      <span></span><span></span><span></span>
    </label>
    <img src="assets/logo-64.png" alt="" class="toplogo">
    <span class="topname">RdpClient</span>
  </header>
  <nav>
    <div class="brand">
      <img src="assets/logo-64.png" alt="">
      <div>
        <div class="brandname">RdpClient</div>
        <div class="brandmeta">$VERSION &middot; MIT</div>
      </div>
    </div>
    <div class="navlabel">Documentation</div>
    <a href="index.html" class="$CLS_INDEX">Overview</a>
    <div class="navlabel">Deep dives</div>
    <a href="protocol.html" class="$CLS_PROTOCOL">Protocol</a>
    <a href="architecture.html" class="$CLS_ARCHITECTURE">Architecture</a>
    <a href="research.html" class="$CLS_RESEARCH">Research</a>
    <div class="navlabel">Testing</div>
    <a href="wsl-rdp-lab.html" class="$CLS_WSL">WSL test lab</a>
    <div class="navlabel">Project</div>
    <a href="changelog.html" class="$CLS_CHANGELOG">Changelog</a>
    <a href="agents.html" class="$CLS_AGENTS">Working notes</a>
    <a href="contributing.html" class="$CLS_CONTRIBUTING">Contributing</a>
    <div class="navlabel">Elsewhere</div>
    <a href="https://github.com/adyoi/RdpClient">Repository</a>
    <a href="https://github.com/adyoi/RdpClient/releases">Releases</a>
    <a href="https://github.com/adyoi/RdpClient/issues">Issues</a>
  </nav>
  <main id="content">
$BODY
  </main>
</div>
<script>
  // Remember the scroll offset across a page load so a reader who follows a
  // cross-page heading link does not land at the top of a long document.
  var key = 'rdpclient-scroll';
  window.addEventListener('beforeunload', function () {
    sessionStorage.setItem(key, String(window.scrollY));
  });
  window.addEventListener('pageshow', function (e) {
    if (e.persisted) { var y = sessionStorage.getItem(key); if (y) window.scrollTo(0, +y); }
  });
</script>
</body>
</html>
""")

CSS = """/* RdpClient documentation theme.
   One accent colour, a four-step surface scale, and a 68-character measure:
   the pages are reference material, so legibility beats decoration. */
:root {
  color-scheme: dark;
  --bg: #0b1220;
  --bg-soft: #0f1829;
  --panel: #142236;
  --panel-hi: #1b2c45;
  --line: #24385a;
  --line-soft: #1b2a42;
  --text: #e7eef8;
  --muted: #9db0ca;
  --faint: #7d90ab;
  --accent: #56c2f2;
  --accent-dim: #2b7fa8;
  --ok: #4ec98a;
  --warn: #e6b455;
  --bad: #f2777a;
  --measure: 68ch;
  --radius: 10px;
}
@media (prefers-color-scheme: light) {
  :root {
    color-scheme: light;
    --bg: #fbfcfe;
    --bg-soft: #f2f5f9;
    --panel: #ffffff;
    --panel-hi: #eef2f7;
    --line: #d7dfea;
    --line-soft: #e6ebf2;
    --text: #16202e;
    --muted: #4d5f78;
    --faint: #6b7d95;
    --accent: #0a6ebd;
    --accent-dim: #4a9bdb;
  }
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
@media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }

body {
  margin: 0;
  font: 16px/1.65 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  -webkit-font-smoothing: antialiased;
}

/* ---- layout: sidebar + content, collapsing to a drawer on narrow screens -- */
.wrap { display: flex; min-height: 100vh; }

.topbar { display: none; }
.navtoggle { position: absolute; opacity: 0; pointer-events: none; }

nav {
  width: 264px; flex: 0 0 264px;
  background: var(--bg-soft);
  border-right: 1px solid var(--line-soft);
  padding: 26px 18px 40px;
  position: sticky; top: 0; align-self: flex-start;
  max-height: 100vh; overflow-y: auto;
  scrollbar-width: thin;
}
.brand { display: flex; gap: 12px; align-items: center; margin-bottom: 22px; }
.brand img { width: 40px; height: 40px; border-radius: 10px; }
.brandname { font-weight: 650; letter-spacing: -0.01em; }
.brandmeta { color: var(--faint); font-size: 12px; margin-top: 1px; }
.navlabel {
  color: var(--faint); font-size: 11px; text-transform: uppercase;
  letter-spacing: 0.09em; margin: 20px 0 6px; padding-left: 12px;
}
nav a {
  display: block; padding: 7px 12px; margin: 1px 0;
  border-radius: 8px; color: var(--muted);
  text-decoration: none; font-size: 14.5px;
  border-left: 2px solid transparent;
}
nav a:hover { background: var(--panel-hi); color: var(--text); }
nav a.on {
  background: var(--panel-hi); color: var(--accent);
  font-weight: 600; border-left-color: var(--accent);
}

main {
  flex: 1; min-width: 0;
  padding: 44px 48px 96px;
  max-width: calc(var(--measure) + 96px + 264px);
}

.skip {
  position: absolute; left: -9999px; top: 0;
  background: var(--accent); color: #001018;
  padding: 10px 16px; border-radius: 0 0 8px 0; z-index: 20; font-weight: 600;
}
.skip:focus { left: 0; }

/* ---- hero: the README's centred block, rendered as markup -- */
.hero { text-align: center; padding: 8px 0 4px; margin-bottom: 8px; }
.hero img.logo { width: 116px; height: 116px; border-radius: 24px; margin-bottom: 14px; }
.hero h1 {
  font-size: 2.6rem; letter-spacing: -0.025em; margin: 0 0 6px;
  background: linear-gradient(180deg, var(--text), var(--muted));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.hero p.tagline { font-size: 1.16rem; color: var(--muted); margin: 0 0 18px; }
.hero .badges { display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; margin-bottom: 16px; }
.hero .badges img { height: 20px; }
.hero .cta { display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
.hero .cta a {
  display: inline-block; padding: 8px 16px; border-radius: 8px;
  border: 1px solid var(--line); background: var(--panel);
  color: var(--text); text-decoration: none; font-size: 14.5px; font-weight: 550;
}
.hero .cta a.primary { background: var(--accent); border-color: var(--accent); color: #001018; }
.hero .cta a:hover { border-color: var(--accent); }

/* ---- typography -- */
h1 { font-size: 2.1rem; letter-spacing: -0.02em; margin: 0 0 1.1em; }
h2 {
  margin: 2.4em 0 0.7em; padding-bottom: 0.3em;
  border-bottom: 1px solid var(--line-soft); font-size: 1.5rem; letter-spacing: -0.015em;
}
h3 { margin: 1.9em 0 0.5em; font-size: 1.18rem; color: var(--accent); }
h4 { margin: 1.5em 0 0.4em; font-size: 1.02rem; color: var(--muted); }
p, li { color: var(--text); }
a { color: var(--accent); text-decoration-color: var(--accent-dim); text-underline-offset: 2px; }
a:hover { text-decoration-color: var(--accent); }
strong { font-weight: 650; }
hr { border: 0; border-top: 1px solid var(--line-soft); margin: 2.6em 0; }

main > *:first-child { margin-top: 0; }

/* Anchor links on headings, revealed on hover.
   The toc extension emits class="headerlink", not "head". */
h1 > a.headerlink, h2 > a.headerlink, h3 > a.headerlink, h4 > a.headerlink {
  color: var(--faint); text-decoration: none; font-weight: 400;
  margin-left: 0.35em; opacity: 0; transition: opacity 0.12s;
  font-size: 0.8em;
}
h1:hover > a.headerlink, h2:hover > a.headerlink,
h3:hover > a.headerlink, h4:hover > a.headerlink { opacity: 1; }
a.headerlink:focus { opacity: 1; }

/* ---- code ---- */
code {
  background: var(--panel-hi); border: 1px solid var(--line-soft);
  padding: 0.12em 0.38em; border-radius: 5px;
  font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 0.88em;
}
pre {
  background: var(--bg-soft); border: 1px solid var(--line-soft);
  border-radius: var(--radius); padding: 14px 16px; overflow-x:auto; line-height: 1.5;
}
pre code { background: none; border: 0; padding: 0; font-size: 0.86rem; }

/* ---- tables ---- */
.table-scroll { overflow-x: auto; margin: 1.3em 0; border-radius: var(--radius); border: 1px solid var(--line-soft); }
table { border-collapse: collapse; width: 100%; font-size: 0.93rem; }
th, td { padding: 9px 13px; text-align: left; border-bottom: 1px solid var(--line-soft); vertical-align: top; }
thead th { background: var(--panel); color: var(--muted); font-weight: 600; white-space: nowrap; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: var(--panel-hi); }

/* ---- quotes, lists, images ---- */
blockquote {
  border-left: 3px solid var(--accent-dim); margin: 1.3em 0;
  padding: 0.2em 0 0.2em 18px; color: var(--muted); background: var(--bg-soft);
  border-radius: 0 8px 8px 0;
}
blockquote p:last-child { margin-bottom: 0; }
ul, ol { padding-left: 1.4em; }
li { margin: 0.25em 0; }
li::marker { color: var(--faint); }
img { max-width: 100%; }
figure { margin: 1.6em 0; }
figcaption { color: var(--faint); font-size: 0.88rem; text-align: center; margin-top: 0.5em; }

/* ---- status words used throughout the docs ---- */
.ok { color: var(--ok); font-weight: 600; }
.warn { color: var(--warn); font-weight: 600; }
.bad { color: var(--bad); font-weight: 600; }

/* ---- page footer ---- */
.pagefoot {
  margin-top: 3.5em; padding-top: 1.2em; border-top: 1px solid var(--line-soft);
  display: flex; justify-content: space-between; gap: 1em; flex-wrap: wrap;
  color: var(--faint); font-size: 0.88rem;
}

/* ---- narrow screens ---- */
@media (max-width: 900px) {
  .wrap { flex-direction: column; }
  .topbar {
    display: flex; align-items: center; gap: 12px;
    position: sticky; top: 0; z-index: 10;
    padding: 10px 16px; background: var(--bg-soft);
    border-bottom: 1px solid var(--line-soft);
  }
  .toplogo { width: 26px; height: 26px; border-radius: 7px; }
  .topname { font-weight: 600; }
  .burger { display: flex; flex-direction: column; gap: 4px; cursor: pointer; padding: 6px; }
  .burger span { display: block; width: 20px; height: 2px; background: var(--muted); border-radius: 2px; }
  nav {
    display: none; width: auto; flex: none; max-height: none;
    position: static; border-right: 0; border-bottom: 1px solid var(--line-soft);
  }
  .navtoggle:checked ~ nav { display: block; }
  main { padding: 26px 20px 64px; max-width: 100%; }
  .hero h1 { font-size: 2rem; }
  h1 { font-size: 1.7rem; }
  h2 { font-size: 1.3rem; }
}
@media print {
  nav, .topbar, .pagefoot, .skip { display: none; }
  body { background: #fff; color: #000; }
}
"""

HERO_RE = re.compile(
    r"<div\s+align=\"center\"\s*>(?P<inner>.*?)</div\s*>",
    re.DOTALL | re.IGNORECASE,
)


def read_version() -> str:
    """Single source of truth for the version string shown in the sidebar.

    The newest released heading in the changelog wins, because that is the file
    a reader checks to see what changed and it is bumped when a release is cut.
    An explicit <Version> in the protocol project is the next choice: that is
    what the assembly reports. Falls back to the SDK default rather than
    printing a stray "v", which is what an earlier version of this function did
    when it found nothing - and rather than reporting 1.0.0 after 1.1.0 had been
    published, which is what the fallback below used to do on its own.
    """
    changelog = ROOT / "CHANGELOG.md"
    if changelog.is_file():
        match = re.search(
            r"^## \[(\d+\.\d+\.\d+)\]", changelog.read_text(encoding="utf-8"), re.M
        )
        if match:
            return f"v{match.group(1)}"

    project = ROOT / "src" / "RdpClient.Protocol" / "RdpClient.Protocol.csproj"
    if project.is_file():
        text = project.read_text(encoding="utf-8")
        match = re.search(r"<Version>([^<]+)</Version>", text)
        if match:
            return f"v{match.group(1)}"

    # The SDK's own default, which is what the binaries report when the project
    # declares no version.
    return "v1.0.0"


def slug_to_anchor(text: str) -> str:
    anchor = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s_]+", "-", anchor).strip("-")


def build_nav_classes(current: str) -> dict:
    return {key.upper(): ("on" if name == current else "") for name, _label, key in NAV}


def extract_hero(text: str) -> tuple[str | None, str]:
    """Split the README's centred header block off the body.

    Python-Markdown does not process Markdown inside a raw HTML block, so the
    title, the tagline and the badge row all rendered as literal text. The
    block is lifted out and emitted as markup with the project's own styling.
    """
    match = HERO_RE.search(text)
    if not match:
        return None, text

    inner = match.group("inner")

    logo = re.search(r'<img[^>]*src="([^"]+)"[^>]*>', inner)
    logo_src = logo.group(1).replace("docs/", "") if logo else None

    # An ATX heading or an <h1> both carry the product name.
    title = re.search(r"^#\s+(.+?)\s*$", inner, re.MULTILINE) or \
        re.search(r"<h1[^>]*>(.+?)</h1>", inner, re.DOTALL | re.IGNORECASE)
    title_text = html.escape(re.sub(r"<[^>]+>", "", title.group(1)).strip()) if title else "RdpClient"

    tagline = re.search(r"^\*\*([^*]+)\*\*\s*$", inner, re.MULTILINE)
    tagline_text = html.escape(tagline.group(1).strip()) if tagline else ""

    badges = re.findall(r"\[!\[[^\]]*\]\(([^)]+)\)\]\(([^)]+)\)", inner)
    badge_html = "".join(
        f'<a href="{html.escape(link)}" target="_blank" rel="noopener">'
        f'<img src="{html.escape(src)}" alt=""></a>'
        for src, link in badges
    )

    cta = re.findall(r"\[([^\]]+)\]\((https://github\.com/[^)]+)\)", inner)
    cta_html = "".join(
        f'<a class="{"primary" if "Documentation" in label else ""}" '
        f'href="{html.escape(link)}">{html.escape(label)}</a>'
        for label, link in cta
    )

    parts = ['<section class="hero">']
    if logo_src:
        parts.append(f'<img class="logo" src="{html.escape(logo_src)}" alt="RdpClient logo">')
    parts.append(f"<h1>{title_text}</h1>")
    if tagline_text:
        parts.append(f'<p class="tagline">{tagline_text}</p>')
    if badge_html:
        parts.append(f'<div class="badges">{badge_html}</div>')
    if cta_html:
        parts.append(f'<div class="cta">{cta_html}</div>')
    parts.append("</section>")

    return "\n".join(parts), text[:match.start()] + text[match.end():]


def rewrite_links(body: str) -> str:
    """Point in-repo Markdown links at the rendered page.

    The earlier pattern was lower-case only, so every link whose target had a
    capital letter - CHANGELOG.md, CONTRIBUTING.md, AGENTS.md - stayed pointed
    at a file the site does not serve. Anything with no rendered counterpart
    now goes to the repository on GitHub instead of nowhere.

    The fragment is part of the match. The first version of this function
    matched only through ``.md`` and closed the quote there, which turned
    ``href="AGENTS.md#the-order-stream"`` into
    ``href="agents.html"#the-order-stream"`` - an anchor stranded outside the
    attribute, so every heading link to another document was a dead 404. That
    is not visible on GitHub, where the Markdown is served unchanged, which is
    why it survived several rounds of documentation edits.
    """

    # href="CHANGELOG.md" -> href="changelog.html"
    def to_html(match: re.Match) -> str:
        target = match.group(2)
        fragment = match.group(3) or ""
        # A document under docs/ refers to a repository-root file as ../NAME,
        # and prefixing that verbatim produced blob/main/../NAME.
        target = re.sub(r"^(\.\./)+", "", target)
        stem = target[:-3].lower()
        known = {name for name, _label, _src in PAGES}
        rendered = f"{stem}.html"
        if rendered in known:
            return f'href="{rendered}{fragment}"'
        return f'href="{BLOB}/{target}{fragment}"'

    body = re.sub(r'href="(docs/)?([A-Za-z0-9_\-./]+\.md)(#[^"]*)?', to_html, body)

    # LICENSE and other non-Markdown repository files are not rendered either.
    body = re.sub(
        r'href="(LICENSE|CHANGELOG|CONTRIBUTING|AGENTS)(\.(md))?"',
        lambda m: f'href="{BLOB}/{m.group(1)}{m.group(2) or ""}"',
        body,
    )

    body = body.replace('href="README.html', 'href="index.html')
    body = body.replace('src="docs/assets/', 'src="assets/')
    body = body.replace('href="docs/assets/', 'href="assets/')
    body = body.replace('src="assets/logo-256.png"', 'src="assets/logo-256.png"')
    return body


def wrap_tables(body: str) -> str:
    """Let wide tables scroll sideways instead of stretching the page."""
    return re.sub(
        r"<table>(.*?)</table>",
        lambda m: f'<div class="table-scroll"><table>{m.group(1)}</table></div>',
        body,
        flags=re.DOTALL,
    )


def mark_status_words(body: str) -> str:
    """Colour the words used as status in the specification tables."""
    for word, cls in (("Done", "ok"), ("Verified", "ok"),
                      ("Not started", "bad"), ("Incomplete", "warn")):
        body = re.sub(
            rf"<td>{re.escape(word)}</td>",
            f'<td class="{cls}">{word}</td>',
            body,
        )
    return body


def render(source_rel: str, out_name: str, version: str) -> None:
    source = ROOT / source_rel
    if not source.is_file():
        raise SystemExit(f"missing source document: {source_rel}")

    text = source.read_text(encoding="utf-8")
    hero = None
    if out_name == "index.html":
        hero, text = extract_hero(text)

    converted = markdown.markdown(
        text,
        extensions=MARKDOWN_EXTENSIONS,
        extension_configs={"toc": {"permalink": True}},
    )

    body = hero + "\n" + converted if hero else converted
    body = rewrite_links(body)
    body = wrap_tables(body)
    body = mark_status_words(body)

    index = PAGES.index(next(p for p in PAGES if p[0] == out_name))
    previous = PAGES[index - 1] if index > 0 else None
    following = PAGES[index + 1] if index + 1 < len(PAGES) else None

    def step(target):
        label, name = NAV_LABEL[target[0]], target[0]
        return f'<a href="{name}">{html.escape(label)} &rarr;</a>' if label else ""

    footer = ['<div class="pagefoot">']
    footer.append(step(previous) if previous else "<span></span>")
    footer.append(
        f'<a href="https://github.com/adyoi/RdpClient/edit/main/{PAGES[index][2]}"'
        ' target="_blank" rel="noopener">Edit this page</a>'
    )
    footer.append(step(following) if following else "<span></span>")
    footer.append("</div>")
    body += "\n" + "\n".join(footer)

    fields = {"TITLE": html.escape(NAV_LABEL[out_name]),
              "NAV": "", "BODY": body, "VERSION": version}
    fields.update(build_nav_classes(out_name))

    (OUT / out_name).write_text(TEMPLATE.substitute(**fields), encoding="utf-8")
    print(f"  {source_rel} -> _site/{out_name}")


NOT_FOUND = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found &middot; RdpClient</title>
<link rel="icon" href="/RdpClient/assets/logo-64.png">
<link rel="stylesheet" href="/RdpClient/assets/site.css">
</head>
<body>
<main style="max-width:60ch;margin:12vh auto;padding:0 24px">
  <p class="ok" style="letter-spacing:.1em;font-size:.8rem">404</p>
  <h1 style="margin-bottom:.3em">That page is not here</h1>
  <p style="color:var(--muted)">The documentation has eight pages. One of them
  is probably the one you wanted.</p>
  <p style="margin-top:1.6em">
    <a class="ok" href="/RdpClient/">Overview</a> &nbsp;&middot;&nbsp;
    <a class="ok" href="/RdpClient/protocol.html">Protocol</a> &nbsp;&middot;&nbsp;
    <a class="ok" href="/RdpClient/wsl-rdp-lab.html">WSL test lab</a>
  </p>
</main>
</body>
</html>
"""


def main() -> None:
    missing = [src for _n, _l, src in PAGES if not (ROOT / src).is_file()]
    if missing:
        raise SystemExit(
            "PAGES lists documents that do not exist: " + ", ".join(missing)
        )

    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    assets = DOCS / "assets"
    if assets.is_dir():
        shutil.copytree(assets, OUT / "assets")
    (OUT / "assets" / "site.css").write_text(CSS, encoding="utf-8")
    (OUT / "404.html").write_text(NOT_FOUND, encoding="utf-8")

    version = read_version()

    print(f"Rendering documentation{f' ({version})' if version else ''}:")
    for out_name, _label, source_rel in PAGES:
        render(source_rel, out_name, version)

    print(f"Site written to {OUT} ({len(PAGES)} pages + 404)")


if __name__ == "__main__":
    main()
