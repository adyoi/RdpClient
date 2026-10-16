#!/usr/bin/env python3
"""Render the repository's Markdown into a static site for GitHub Pages.

Kept deliberately small: the documentation is Markdown that is also readable on
GitHub itself, so the site only needs to render it, apply a shared shell and
copy the images. A full static-site generator would add a dependency and a
build step for no gain at this size.
"""

from __future__ import annotations

import html
import re
import shutil
import pathlib
import markdown

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "_site"

PAGES = [
    ("index.html", "Overview"),
    ("protocol.html", "Protocol"),
    ("architecture.html", "Architecture"),
    ("research.html", "Research"),
]

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} &middot; RdpClient</title>
<link rel="icon" href="assets/logo-64.png">
<style>
  :root {{ color-scheme: dark; --bg:#0d1522; --panel:#131f30; --line:#24354d;
           --text:#e6edf6; --muted:#9fb0c8; --accent:#4fc3f7; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:16px/1.65 "Segoe UI",system-ui,sans-serif;
          background:var(--bg); color:var(--text); }}
  .wrap {{ display:flex; min-height:100vh; }}
  nav {{ width:250px; flex:0 0 250px; background:var(--panel);
         border-right:1px solid var(--line); padding:28px 20px; }}
  nav img {{ width:56px; height:56px; border-radius:12px; }}
  nav h1 {{ font-size:17px; margin:14px 0 2px; }}
  nav .tag {{ color:var(--muted); font-size:12px; margin-bottom:24px; }}
  nav a {{ display:block; padding:9px 12px; margin:2px -12px; border-radius:8px;
           color:var(--muted); text-decoration:none; font-size:14px; }}
  nav a:hover {{ background:#1b2a40; color:var(--text); }}
  nav a.on {{ background:#1b2a40; color:var(--accent); font-weight:600; }}
  main {{ flex:1; padding:44px 56px; max-width:900px; }}
  h1 {{ font-size:2.1rem; margin-top:0; }}
  h2 {{ margin-top:2.2em; padding-bottom:.3em; border-bottom:1px solid var(--line); }}
  h3 {{ margin-top:1.8em; color:var(--accent); }}
  code {{ background:#1b2a40; padding:.15em .4em; border-radius:5px;
          font-family:Consolas,ui-monospace,monospace; font-size:.9em; }}
  pre {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
         padding:16px 18px; overflow-x:auto; }}
  pre code {{ background:none; padding:0; }}
  table {{ border-collapse:collapse; width:100%; margin:1.2em 0; font-size:.94em; }}
  th,td {{ border:1px solid var(--line); padding:9px 12px; text-align:left; }}
  th {{ background:var(--panel); }}
  blockquote {{ border-left:3px solid var(--accent); margin:1.2em 0;
                padding:.3em 0 .3em 18px; color:var(--muted); }}
  img {{ max-width:100%; }}
  a {{ color:var(--accent); }}
  hr {{ border:0; border-top:1px solid var(--line); margin:2.5em 0; }}
  @media (max-width:760px) {{
    .wrap {{ flex-direction:column; }}
    nav {{ width:auto; flex:none; border-right:0; border-bottom:1px solid var(--line); }}
    main {{ padding:28px 22px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <nav>
    <img src="assets/logo-64.png" alt="">
    <h1>RdpClient</h1>
    <div class="tag">v1.0.0 &middot; MIT</div>
    {nav}
  </nav>
  <main>{body}</main>
</div>
</body>
</html>
"""


def slug_to_anchor(text: str) -> str:
    anchor = re.sub(r"[^\w\s-]", "", text.lower())
    return re.sub(r"[\s_]+", "-", anchor).strip("-")


def build_nav(current: str) -> str:
    items = []
    for filename, label in PAGES:
        name = label if isinstance(label, str) else label[0]
        cls = " class=\"on\"" if filename == current else ""
        items.append(f'<a href="{filename}"{cls}>{html.escape(name)}</a>')
    items.append('<a href="https://github.com/adyoi/RdpClient">Repository</a>')
    items.append('<a href="https://github.com/adyoi/RdpClient/releases">Releases</a>')
    return "\n    ".join(items)


def render(source: pathlib.Path, title: str, out_name: str) -> None:
    body = markdown.markdown(
        source.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "toc", "attr_list"],
    )

    # Rewrite in-repo links so they stay inside the rendered site.
    body = re.sub(r'href="(docs/)?([a-z\-]+)\.md', r'href="\2.html', body)
    body = body.replace('href="README.html', 'href="index.html')
    body = body.replace('src="docs/assets/', 'src="assets/')
    body = body.replace('href="docs/assets/', 'href="assets/')

    (OUT / out_name).write_text(
        TEMPLATE.format(title=html.escape(title), nav=build_nav(out_name), body=body),
        encoding="utf-8",
    )
    print(f"  {source.name} -> _site/{out_name}")


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)

    assets = DOCS / "assets"
    if assets.is_dir():
        shutil.copytree(assets, OUT / "assets")

    print("Rendering documentation:")
    render(ROOT / "README.md", "Overview", "index.html")
    for name, label in PAGES[1:]:
        render(DOCS / name.replace(".html", ".md"), label, name)

    # Changelog and contributing live outside docs/ but belong on the site.
    if (ROOT / "CHANGELOG.md").is_file():
        render(ROOT / "CHANGELOG.md", "Changelog", "changelog.html")
    if (ROOT / "CONTRIBUTING.md").is_file():
        render(ROOT / "CONTRIBUTING.md", "Contributing", "contributing.html")

    print(f"Site written to {OUT}")


if __name__ == "__main__":
    main()