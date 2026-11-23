#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Build the static website in docs/ from the Markdown files. Use only the Python standard library.

Use:
    python3 -I scripts/build-site.py            write the pages
    python3 -I scripts/build-site.py --check    make no change; exit 1 when a page differs from its source

The Markdown files in docs/ and the file CHANGELOG.md are the source of the pages. The Overview page and the page 404 are
in this script. The pages need no build step to be read: they are plain HTML with relative links, and they work from
file:// and from GitHub Pages.
"""

from __future__ import annotations

import html
import posixpath
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SITE_URL = "https://procurauth.github.io/stowr/"
REPO_URL = "https://github.com/ProcurAuth/stowr"
BLOB = REPO_URL + "/blob/main/"
TREE = REPO_URL + "/tree/main/"


def version() -> str:
    """Return the version of the crate."""
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    if not match:
        raise SystemExit("Cargo.toml has no version")
    return match.group(1)


VERSION = version()

# name of the page, title, short title (navigation), source files (relative to the root), eyebrow, lede, in the navigation
PAGES = [
    ("index.html", "Stowr", "Overview", None,
     "Browser for S3, Google Cloud Storage and folders", "", True),
    ("getting-started.html", "Getting started", "Getting started", "docs/GETTING-STARTED.md",
     "A test in five minutes",
     "Run a local S3-compatible service, put two files in it, and open them in Stowr.", True),
    ("configuration.html", "Configuration", "Configuration", "docs/CONFIGURATION.md",
     "One HCL file, a closed schema",
     "The blocks, the keys and the rules of the configuration file. A mistake stops the start, and the message names the key.", True),
    ("architecture.html", "Architecture", "Architecture", "docs/ARCHITECTURE.md",
     "How the single binary works",
     "The runtime, the providers, the uploads, the jobs, the versions, the lifecycle rules, the lock, the encryption and the volumes.", True),
    ("access.html", "Access and ProcurAuth", "Access", "docs/ACCESS.md",
     "The mode authzen",
     "How Stowr checks the identity token, asks the PDP and applies the decision: the resource tree, the actions, the routes and the errors.", False),
    ("security.html", "Security model", "Security", "docs/SECURITY-MODEL.md",
     "What Stowr protects, and how",
     "The protections of the runtime, the access policy, the browser and the provider connections. To report a vulnerability, read the security policy.", True),
    ("operations.html", "Operations", "Operations", "docs/OPERATIONS.md",
     "Run it in production",
     "The service, the network, the logs, the limits, the upgrade and the steps to find a problem.", True),
    ("reference.html", "Configuration reference", "Reference", "docs/configuration-reference.md",
     "Generated from the code",
     "Each key with its type, its default, its range and its forms. The program makes this page from its table of keys.", True),
    ("changelog.html", "Changelog", "Changelog", "CHANGELOG.md",
     "The changes of each version", "The versions of Stowr, with the changes and the upgrade steps.", True),
    ("previews.html", "Previews", "Previews", "docs/PREVIEWS.md",
     "The formats and the rules of the previews",
     "Each preview reads bounded byte ranges. This page gives the rules for each format.", False),
    ("conformance.html", "Conformance", "Conformance", "docs/CONFORMANCE.md",
     "The test of the ProcurAuth runner",
     "How to run the conformance cases of ProcurAuth against Stowr, and what the result is.", False),
    ("development.html", "Development", "Development", "docs/DEVELOPMENT.md",
     "Build, test and release",
     "The scripts, the tests, the dependencies, the rules of the runtime and the steps of a release.", False),
]
PAGE_OF_SOURCE = {p[3]: p[0] for p in PAGES if p[3]}

# The main menu has the same eight entries as the menu of the portal site. A page that is not in the menu marks the
# entry of its section. The footer and the Overview page link to these pages.
SECTION = {
    "access.html": "security.html",
    "previews.html": "architecture.html",
    "conformance.html": "reference.html",
    "development.html": "operations.html",
}
FAMILY_HOME = "https://procurauth.github.io/"
FAMILY_LINKS = [
    ("Home", FAMILY_HOME),
    ("Specification", "https://procurauth.github.io/procurauth/"),
    ("portal", "https://procurauth.github.io/portal/"),
]


# ------------------------------------------------------------------ Markdown

def github_slug(heading: str) -> str:
    """Make the anchor that GitHub gives to a Markdown heading."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def map_link(url: str, source_dir: str) -> str:
    """Map the target of a link in a Markdown file to the target in the website."""
    if re.match(r"^[a-z][a-z0-9+.-]*:", url) or url.startswith("//"):
        return url
    if url.startswith("#"):
        return url
    path, _, fragment = url.partition("#")
    target = posixpath.normpath(posixpath.join(source_dir, path))
    suffix = "#" + fragment if fragment else ""
    if target in PAGE_OF_SOURCE:
        return PAGE_OF_SOURCE[target] + suffix
    if target.startswith("docs/") and target.endswith(".html"):
        return target[len("docs/"):] + suffix
    if (ROOT / target).is_dir():
        return TREE + target.rstrip("/") + suffix
    return BLOB + target + suffix


class Inline:
    """Render the inline Markdown of the documents: code, links, images, emphasis."""

    def __init__(self, source_dir: str) -> None:
        self.source_dir = source_dir

    def render(self, text: str) -> str:
        holders: list[str] = []

        def keep_code(match: re.Match[str]) -> str:
            holders.append("<code>" + html.escape(match.group(2), quote=False) + "</code>")
            return f"\x00{len(holders) - 1}\x00"

        text = re.sub(r"(`+)(.+?)\1", keep_code, text)
        text = html.escape(text, quote=False)
        text = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", lambda m: f'<img src="{html.escape(m.group(2))}" alt="{m.group(1)}" loading="lazy">', text)
        text = re.sub(
            r"\[([^\]]+)\]\(([^)\s]+)(?:\s+&quot;[^&]*&quot;)?\)",
            lambda m: f'<a href="{html.escape(map_link(html.unescape(m.group(2)), self.source_dir))}">{m.group(1)}</a>',
            text,
        )
        text = re.sub(r"&lt;(https?://[^\s&]+)&gt;", r'<a href="\1">\1</a>', text)
        text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
        text = re.sub(r"(?<![\w*])\*(?![\s*])(.+?)(?<![\s*])\*(?![\w*])", r"<em>\1</em>", text)
        return re.sub(r"\x00(\d+)\x00", lambda m: holders[int(m.group(1))], text)


def split_row(line: str) -> list[str]:
    """Split a table row at the pipes that are not in a code span."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells: list[str] = []
    current = ""
    in_code = False
    for char in line:
        if char == "`":
            in_code = not in_code
        if char == "|" and not in_code:
            cells.append(current.strip())
            current = ""
        else:
            current += char
    cells.append(current.strip())
    return cells


class Markdown:
    """A small Markdown renderer for the documents of this repository."""

    def __init__(self, source_dir: str) -> None:
        self.inline = Inline(source_dir)
        self.headings: list[tuple[int, str, str]] = []
        self.slugs: dict[str, int] = {}
        self.title = ""

    def heading_id(self, text: str) -> str:
        slug = github_slug(text)
        count = self.slugs.get(slug, 0)
        self.slugs[slug] = count + 1
        return slug if count == 0 else f"{slug}-{count}"

    def render(self, text: str) -> str:
        lines = text.split("\n")
        out: list[str] = []
        i = 0
        paragraph: list[str] = []

        def flush() -> None:
            if paragraph:
                out.append("<p>" + self.inline.render(" ".join(s.strip() for s in paragraph)) + "</p>")
                paragraph.clear()

        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            if not stripped:
                flush()
                i += 1
                continue
            fence = re.match(r"^```(\S*)\s*$", stripped)
            if fence:
                flush()
                language = fence.group(1)
                body: list[str] = []
                i += 1
                while i < len(lines) and not lines[i].strip().startswith("```"):
                    body.append(lines[i])
                    i += 1
                i += 1
                out.append(self.code_block(language, "\n".join(body)))
                continue
            heading = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
            if heading:
                flush()
                level = len(heading.group(1))
                content = heading.group(2)
                if level == 1 and not self.title:
                    self.title = re.sub(r"`", "", content)
                    i += 1
                    continue
                identifier = self.heading_id(content)
                self.headings.append((level, re.sub(r"`", "", content), identifier))
                rendered = self.inline.render(content)
                if level == 2:
                    out.append(f'<h2 id="{identifier}"><a class="self" href="#{identifier}">{rendered}</a></h2>')
                else:
                    out.append(f'<h{level} id="{identifier}">{rendered}</h{level}>')
                i += 1
                continue
            if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
                flush()
                rows: list[str] = []
                while i < len(lines) and lines[i].strip().startswith("|"):
                    rows.append(lines[i])
                    i += 1
                out.append(self.table(rows))
                continue
            if re.match(r"^\s*([-*]|\d+\.)\s+", line):
                flush()
                block, i = self.list_block(lines, i)
                out.append(block)
                continue
            if re.match(r"^-{3,}$", stripped):
                flush()
                out.append("<hr>")
                i += 1
                continue
            paragraph.append(line)
            i += 1
        flush()
        return "\n".join(out)

    def code_block(self, language: str, body: str) -> str:
        label = language or "text"
        escaped = html.escape(body, quote=False)
        return (
            f'<div class="code-wrap"><span class="label">{html.escape(label)}</span>'
            f'<pre data-copy tabindex="0" aria-label="Code example: {html.escape(label)}"><code>{escaped}</code></pre></div>'
        )

    def table(self, rows: list[str]) -> str:
        head = split_row(rows[0])
        body = [split_row(r) for r in rows[2:]]
        labels = [re.sub(r"<[^>]+>", "", self.inline.render(h)) for h in head]
        parts = ['<div class="tablewrap"><table><thead><tr>']
        for cell in head:
            parts.append(f'<th scope="col">{self.inline.render(cell)}</th>')
        parts.append("</tr></thead><tbody>")
        for cells in body:
            parts.append("<tr>")
            for index, cell in enumerate(cells):
                rendered = self.inline.render(cell)
                if index == 0:
                    parts.append(f'<th scope="row">{rendered}</th>')
                else:
                    label = html.escape(labels[index] if index < len(labels) else "", quote=True)
                    parts.append(f'<td data-label="{label}">{rendered}</td>')
            parts.append("</tr>")
        parts.append("</tbody></table></div>")
        return "".join(parts)

    def list_block(self, lines: list[str], i: int) -> tuple[str, int]:
        marker = re.match(r"^(\s*)([-*]|\d+\.)\s+", lines[i])
        assert marker
        indent = len(marker.group(1))
        ordered = marker.group(2)[0].isdigit()
        tag = "ol" if ordered else "ul"
        items: list[str] = []
        while i < len(lines):
            m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", lines[i])
            if not m or len(m.group(1)) != indent:
                break
            text_lines = [m.group(3)]
            children: list[str] = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                if not nxt.strip():
                    # A blank line ends the item unless an indented line continues it.
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and len(lines[j]) - len(lines[j].lstrip()) > indent and not re.match(r"^\s*([-*]|\d+\.)\s+", lines[j]):
                        i = j
                        text_lines.append("")
                        continue
                    break
                nm = re.match(r"^(\s*)([-*]|\d+\.)\s+", nxt)
                lead = len(nxt) - len(nxt.lstrip())
                if nm and len(nm.group(1)) > indent:
                    block, i = self.list_block(lines, i)
                    children.append(block)
                    continue
                if nm and len(nm.group(1)) <= indent:
                    break
                if lead > indent:
                    text_lines.append(nxt.strip())
                    i += 1
                    continue
                break
            paragraphs: list[list[str]] = [[]]
            for text_line in text_lines:
                if text_line == "":
                    paragraphs.append([])
                else:
                    paragraphs[-1].append(text_line)
            texts = [" ".join(p).strip() for p in paragraphs if p]
            if len(texts) > 1:
                body = "".join("<p>" + self.inline.render(t) + "</p>" for t in texts)
            else:
                body = self.inline.render(texts[0] if texts else "")
            items.append("<li>" + body + "".join(children) + "</li>")
            # a blank line between two items keeps the same list
            j = i
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and j != i:
                nm2 = re.match(r"^(\s*)([-*]|\d+\.)\s+", lines[j])
                if nm2 and len(nm2.group(1)) == indent:
                    i = j
        return f"<{tag}>" + "".join(items) + f"</{tag}>", i


# ----------------------------------------------------------------- templates

MARK = (
    '<svg class="mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false"><rect width="32" height="32" rx="8" fill="var(--accent)"/>'
    '<g transform="translate(6 5.6) scale(1.11)" fill="var(--accent-ink)"><rect x="1" y="1.5" width="16" height="2.6" rx="1.3"/>'
    '<path fill-rule="evenodd" d="M4 5.6h10a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2zM6.2 8.5h5.6a.7.7 0 0 1 0 1.4H6.2a.7.7 0 0 1 0-1.4zM6.2 12h5.6a.7.7 0 0 1 0 1.4H6.2a.7.7 0 0 1 0-1.4z"/></g></svg>'
)
GITHUB_ICON = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="currentColor" d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>'
)
THEME_ICON = (
    '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="8.5" fill="none" stroke="currentColor" stroke-width="2"/>'
    '<path d="M12 3.5a8.5 8.5 0 0 1 0 17z" fill="currentColor"/></svg>'
)
DEFAULT_DESCRIPTION = (
    "Stowr is a web application that browses S3-compatible storage, Google Cloud Storage and folders of the server. "
    "It is one static binary with one HCL file, and it keeps no state on disk."
)


def head(name: str, title: str, description: str) -> str:
    page_title = "Stowr: every bucket and folder, in one page" if name == "index.html" else f"{title} | Stowr"
    canonical = SITE_URL if name == "index.html" else SITE_URL + name
    e = html.escape
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="description" content="{e(description)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Stowr">
<meta property="og:title" content="{e(page_title)}">
<meta property="og:description" content="{e(description)}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{SITE_URL}assets/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Stowr: every bucket and folder, in one page. One static binary.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{e(page_title)}">
<meta name="twitter:description" content="{e(description)}">
<meta name="twitter:image" content="{SITE_URL}assets/og.png">
<meta name="twitter:image:alt" content="Stowr: every bucket and folder, in one page.">
<link rel="canonical" href="{canonical}">
<title>{e(page_title)}</title>
<link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
<link rel="icon" href="assets/favicon-32.png" sizes="32x32" type="image/png">
<link rel="icon" href="assets/favicon.ico" sizes="16x16 32x32 48x48">
<link rel="apple-touch-icon" href="assets/apple-touch-icon.png">
<link rel="manifest" href="site.webmanifest">
<meta name="theme-color" content="#fafafd" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0c0e15" media="(prefers-color-scheme: dark)">
<link rel="stylesheet" href="assets/site.css">
<script src="assets/site.js"></script>
</head>
<body>
"""


def header(current: str) -> str:
    section = SECTION.get(current)
    items = []
    for name, _title, short, _src, _eyebrow, _lede, nav in PAGES:
        if not nav:
            continue
        # "page" marks the page itself. "true" marks the menu entry of the section that holds the page.
        aria = ' aria-current="page"' if name == current else ' aria-current="true"' if name == section else ""
        items.append(f'<li><a href="{name}"{aria}>{short}</a></li>')
    items.append(f'<li class="nav-gh"><a href="{REPO_URL}">GitHub</a></li>')
    return f"""<a class="skip" href="#main">Skip to the content</a>
<header class="site-header">
  <div class="wrap bar">
    <a class="brand" href="index.html" aria-label="Stowr, home page">{MARK}<span>Stow<b>r</b></span></a>
    <button class="menu-btn" id="menu-btn" type="button" aria-expanded="false" aria-controls="site-nav">Menu</button>
    <nav id="site-nav" aria-label="Main"><ul>{"".join(items)}</ul></nav>
    <a class="gh-link" href="{REPO_URL}" aria-label="Stowr on GitHub" title="Stowr on GitHub">{GITHUB_ICON}<span>GitHub</span></a>
    <button class="icon-btn" id="theme-btn" type="button" aria-label="Switch colour theme" title="Switch colour theme">{THEME_ICON}</button>
  </div>
</header>
<main id="main">
"""


def footer() -> str:
    family = "".join(f'\n          <li><a href="{url}">{label}</a></li>' for label, url in FAMILY_LINKS)
    return f"""</main>
<footer class="site-footer">
  <div class="wrap">
    <div class="foot-grid">
      <div>
        <h2>Learn</h2>
        <ul>
          <li><a href="getting-started.html">Getting started</a></li>
          <li><a href="configuration.html">Configuration</a></li>
          <li><a href="architecture.html">Architecture</a></li>
          <li><a href="previews.html">Previews</a></li>
        </ul>
      </div>
      <div>
        <h2>Run</h2>
        <ul>
          <li><a href="access.html">Access and ProcurAuth</a></li>
          <li><a href="security.html">Security model</a></li>
          <li><a href="operations.html">Operations</a></li>
          <li><a href="reference.html">Configuration reference</a></li>
        </ul>
      </div>
      <div>
        <h2>Project</h2>
        <ul>
          <li><a href="{REPO_URL}">Repository</a></li>
          <li><a href="{REPO_URL}/releases/latest">Downloads</a></li>
          <li><a href="changelog.html">Changelog</a></li>
          <li><a href="development.html">Development</a></li>
          <li><a href="conformance.html">Conformance</a></li>
        </ul>
      </div>
      <div>
        <h2>ProcurAuth</h2>
        <ul>{family}
        </ul>
      </div>
    </div>
    <div class="foot-legal">
      <p>Stowr, version {VERSION}. Part of <a href="{FAMILY_HOME}">ProcurAuth</a>.</p>
      <p>Licence: <a href="{BLOB}LICENSE-MIT">MIT</a> or <a href="{BLOB}LICENSE-APACHE">Apache-2.0</a>.</p>
      <p><a href="{BLOB}SECURITY.md">Security policy</a></p>
    </div>
  </div>
</footer>
</body>
</html>
"""


def doc_page(name: str, title: str, eyebrow: str, lede: str, source: str) -> str:
    path = ROOT / source
    text = path.read_text(encoding="utf-8")
    md = Markdown(posixpath.dirname(source))
    body = md.render(text)
    toc = "".join(f'<li><a href="#{ident}">{html.escape(label)}</a></li>' for level, label, ident in md.headings if level == 2)
    description = lede
    h1_title = title
    lede_html = f'<p class="lede">{html.escape(lede)}</p>' if lede else ""
    edit = f'<p class="src">This page comes from <a href="{BLOB}{source}"><code>{source}</code></a> in the repository.</p>'
    toc_html = (
        f'<nav class="toc" aria-label="On this page"><details class="toc-details" open><summary>On this page</summary><ol>{toc}</ol></details></nav>'
        if toc else ""
    )
    layout = "wrap doc-layout" if toc else "wrap narrow doc-layout"
    return (
        head(name, title, description)
        + header(name)
        + f'<div class="page-head"><div class="wrap"><p class="eyebrow"><span class="badge">Version {VERSION}</span> {html.escape(eyebrow)}</p>'
        + f"<h1>{html.escape(h1_title)}</h1>{lede_html}</div></div>"
        + f'<div class="{layout}">{toc_html}<article class="doc">{edit}{body}</article></div>\n'
        + footer()
    )


def figure(src: str, alt: str, caption: str, extra: str = "") -> str:
    return (
        f'<figure class="shot{extra}"><img src="assets/img/{src}" alt="{html.escape(alt)}" loading="lazy" decoding="async">'
        f"<figcaption>{caption}</figcaption></figure>"
    )


def panel(src: str, alt: str, caption: str) -> str:
    return (
        f'<figure class="panel"><img src="assets/{src}" alt="{html.escape(alt)}" loading="lazy" decoding="async">'
        f"<figcaption>{caption}</figcaption></figure>"
    )


QUICKSTART = """docker run -d --rm --name stowr-demo-s3 -p 127.0.0.1:8333:8333 chrislusf/seaweedfs:4.41 server -s3 -dir=/data \\
  -master.volumeSizeLimitMB=64 -volume.max=30 -volume.minFreeSpace=1GiB
sleep 10
curl -s -X PUT http://127.0.0.1:8333/demo
printf '# Hello\\n\\nThis file is in the bucket demo.\\n' | curl -s --retry 5 --retry-delay 2 --retry-all-errors \\
  -X PUT -H 'Content-Type: text/markdown' --data-binary @- http://127.0.0.1:8333/demo/notes/hello.md
curl -fsSLO https://github.com/ProcurAuth/stowr/releases/download/v%(v)s/stowr_%(v)s_linux_amd64.tar.gz
tar -xzf stowr_%(v)s_linux_amd64.tar.gz
./stowr -c config.hcl"""


def overview() -> str:
    name = "index.html"
    description = DEFAULT_DESCRIPTION
    cards = [
        ("M4 7h16M4 12h16M4 17h10", "One page for each storage",
         "Browse AWS S3, MinIO, SeaweedFS, Garage, Google Cloud Storage and folders of the server. One menu lists them all, with the state of each bucket.",
         "architecture.html#storage-interfaces"),
        ("M12 3v18M5 8l7-5 7 5M5 16l7 5 7-5", "Bounded and stateless",
         "Stowr reads exact byte ranges. It has no database, no cache folder and no temporary file. Each limit has a key in the file.",
         "architecture.html#stateless-state-model"),
        ("M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z", "Access with ProcurAuth",
         "In the mode authzen, Stowr checks an identity token and asks a PDP before each operation. A grant on a folder covers the folders below it.",
         "access.html"),
    ]
    card_html = "".join(
        f'<a class="card" href="{href}"><div class="ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="{path}"/></svg></div><h3>{title}</h3><p>{text}</p></a>'
        for path, title, text, href in cards
    )
    features = [
        ("Storage", "AWS S3, MinIO, SeaweedFS and Garage through the S3 API. Google Cloud Storage. Folders of the server as volumes."),
        ("Browsing", "Dense tables, folders, search, sort, tags, version counts and the settings of the columns."),
        ("Previews", "Text, code, Markdown, JSON, CSV, Parquet, SQLite, Excel, Word, PDF, images, audio, video, archives, certificates and email."),
        ("Large objects", "Exact byte-range readers, an integrity check that hashes the stream, an inspection of the structure, and Insights on a folder."),
        ("Operations", "Resumable upload with SHA-256 checksums, copy in parts, archive download and extraction, and edit of metadata and tags."),
        ("Versions", "Versions of an object, restore, permanent delete, and the comparison of two versions in the browser."),
        ("Bucket functions", "Lifecycle rules, Object Lock, SSE-S3 encryption, incomplete multipart uploads, and the usage and quota of a bucket."),
        ("Access", "The mode authzen checks an identity token and asks a PDP. The mode open needs a proxy that signs users in."),
        ("Configuration", "One HCL file with a closed schema. A mistake stops the start. The command print-config shows each value and its source."),
        ("Runtime", "A read-only root file system is enough. No request goes to another origin. The binary is static, for Linux amd64 and arm64."),
    ]
    rows = "".join(f'<tr><th scope="row">{a}</th><td data-label="What Stowr does">{b}</td></tr>' for a, b in features)
    shots = "".join([
        figure("browser-light.webp", "The folder list of a bucket in the light theme", "<strong>Browse.</strong> A dense table of folders and files, with a bucket menu."),
        figure("browser-dark.webp", "The folder list of a bucket in the dark theme", "<strong>Two themes.</strong> The interface has a light theme and a dark theme."),
        figure("tags-versions.webp", "A folder with tag chips and a version count on one file", "<strong>Tags and versions.</strong> The list shows the tags and the number of versions of each file."),
        figure("preview-csv.webp", "A CSV file shown as a table with filters", "<strong>Tables.</strong> CSV, Excel, Parquet, SQLite and JSON lines open as tables."),
        figure("preview-archive.webp", "The contents of a ZIP archive", "<strong>Archives.</strong> Stowr reads the central directory. You can open, download or extract one entry."),
        figure("preview-image.webp", "An image shown in the dark theme", "<strong>Images.</strong> Stowr shows an image in the page, and reads only the bytes that it needs."),
        figure("preview-large.webp", "The schema of a Parquet file of 979 MB, read with two storage requests", "<strong>Large objects.</strong> A Parquet file of 979 MB. Stowr reads the footer: two storage requests."),
        figure("inspect.webp", "The inspection of a large object: three storage requests and 128 KB read", "<strong>Inspection.</strong> Stowr reads small exact ranges to find the format. It shows the requests and the bytes."),
        figure("uploads.webp", "The upload panel at 35 percent, with the rate and the time left", "<strong>Uploads.</strong> A large file goes in chunks. The panel shows the rate and the time left."),
        figure("insights.webp", "Storage insights: the size by type, the most recent files and the largest files", "<strong>Insights.</strong> The size and the count by type, the most recent files and the largest files."),
        figure("info.webp", "The information page of a bucket: identity, permissions, data protection, operations and the lifecycle rules", "<strong>One page for a bucket.</strong> The permissions, the protection of the data and the lifecycle rules."),
        figure("access-readonly.webp", "A folder that the person can read but not change: the badge Read only", "<strong>Access.</strong> The PDP lets this person read the folder. Stowr hides the controls that change data."),
        figure("access-refused.webp", "A folder that the access policy refuses: no folder to open", "<strong>Refusal.</strong> The PDP refuses this folder. Stowr shows no object of it."),
        figure("access-buckets.webp", "The menu of buckets with only the buckets that the person can use", "<strong>Only what you may use.</strong> The menu lists the buckets where the person holds an action."),
    ])
    return (
        head(name, "Stowr", description)
        + header(name)
        + f"""<section class="hero" aria-labelledby="hero-title">
  <div class="wrap hero-grid">
    <div>
      <p class="eyebrow"><span class="badge">Version {VERSION}</span> Browser for S3, Google Cloud Storage and folders</p>
      <h1 id="hero-title">Stowr</h1>
      <p class="promise">Every bucket and folder, in one page. One static binary and one HCL file.</p>
      <p class="sub">Stowr reads only the bytes that it shows, and it keeps no state on disk. It is for operators who run their own storage.</p>
      <div class="btn-row">
        <a class="btn primary" href="getting-started.html">Get started</a>
        <a class="btn" href="{REPO_URL}/releases/latest">Download v{VERSION}</a>
      </div>
      <p class="more"><a href="architecture.html">See how it works</a></p>
    </div>
    <div class="hero-shot">{figure("hero.webp", "The Stowr interface: a bucket with folders, and the menu of buckets and hosts", "The bucket menu shows the state of each bucket: read, write, delete, encryption, lock, versions and lifecycle.")}</div>
  </div>
</section>
<section class="section" aria-labelledby="why-h">
  <div class="wrap">
    <div class="section-head"><h2 id="why-h">One page for the storage that you have</h2>
    <p>Stowr shows the objects of many buckets, previews them and works on them. It runs on a host with little memory.</p></div>
    <div class="grid c3">{card_html}</div>
  </div>
</section>
<section class="section alt" aria-labelledby="how-h">
  <div class="wrap">
    <div class="section-head"><h2 id="how-h">How it works</h2>
    <p>Stowr is one static binary. The interface is inside. The access guard asks the PDP before each operation.</p></div>
    {panel("architecture.svg", "Architecture of Stowr: the browser, the edge, the single binary with the HTTP server, the access guard, the storage instances and the jobs, the three providers, and the PDP", "<strong>The single binary.</strong> The HTTP server, the access guard, the storage instances, the jobs and the three provider clients are in one program. Only a volume writes files.")}
    {panel("flow.svg", "Three request flows: a folder listing, a read of a large object by byte ranges, and an upload in chunks", "<strong>Three requests.</strong> In each one, the PDP decides before the first byte moves. A large object is read with exact byte ranges. An upload goes in chunks, with a token to resume it.")}
    {panel("access-model.svg", "The resource tree, the question that Stowr sends to the PDP, the five actions and the two limits", "<strong>The access model.</strong> The tree is service, bucket, folder and subfolder. A grant on a node covers the nodes below it. <a href='access.html'>Read the rules</a>.")}
  </div>
</section>
<section class="section" aria-labelledby="see-h">
  <div class="wrap">
    <div class="section-head"><h2 id="see-h">See it</h2>
    <p>Each picture comes from a live copy of the product, with demo data. Nothing is mocked.</p></div>
    <div class="shots">{shots}</div>
  </div>
</section>
<section class="section alt" aria-labelledby="features-h">
  <div class="wrap">
    <div class="section-head"><h2 id="features-h">What Stowr does</h2></div>
    <div class="tablewrap"><table class="feature-table"><thead><tr><th scope="col">Area</th><th scope="col">What Stowr does</th></tr></thead><tbody>{rows}</tbody></table></div>
  </div>
</section>
<section class="section" aria-labelledby="run-h">
  <div class="wrap narrow">
    <div class="section-head"><h2 id="run-h">Run it in five minutes</h2>
    <p>This test starts a local S3-compatible service in Docker, on 127.0.0.1. It needs a file <code>config.hcl</code>: the <a href="getting-started.html">guide</a> has it, with each step.</p></div>
    <div class="code-wrap"><span class="label">sh</span><pre data-copy tabindex="0" aria-label="Code example: quick start"><code>{html.escape(QUICKSTART % {"v": VERSION}, quote=False)}</code></pre></div>
    <div class="btn-row"><a class="btn primary" href="getting-started.html">Open the guide</a><a class="btn" href="configuration.html">Read the configuration</a></div>
  </div>
</section>
<section class="section alt" aria-labelledby="family-h">
  <div class="wrap">
    <div class="section-head"><h2 id="family-h">Part of ProcurAuth</h2>
    <p>Stowr is a PEP of the <a href="https://procurauth.github.io/procurauth/">ProcurAuth</a> specification. The portal gives it identity tokens and decisions.</p></div>
    <figure class="panel family-fig"><img src="assets/family.svg" alt="The ProcurAuth family: the specification, the reference tools, the portal, and the services Stowr, Hune and ClickHouse Dash" loading="lazy" decoding="async"></figure>
    <ul class="prose">
      <li><a href="https://github.com/ProcurAuth/procurauth">ProcurAuth</a>: the open specification, the tools and the conformance cases.</li>
      <li><a href="https://github.com/ProcurAuth/portal">portal</a>: the backend, the edge and the PDP.</li>
      <li>Hune: dashboards over ClickHouse, PostgreSQL and MongoDB.</li>
      <li><a href="https://github.com/Circular-fi/Clickhouse-dash">ClickHouse Dash</a>: a query console with MCP.</li>
    </ul>
  </div>
</section>
<section class="section" aria-labelledby="go-h">
  <div class="wrap">
    <div class="section-head"><h2 id="go-h">Where to go next</h2></div>
    <div class="btn-row">
      <a class="btn primary" href="getting-started.html">Getting started</a>
      <a class="btn" href="configuration.html">Configuration</a>
      <a class="btn" href="access.html">Access and ProcurAuth</a>
      <a class="btn" href="operations.html">Operations</a>
      <a class="btn" href="changelog.html">Changelog</a>
    </div>
  </div>
</section>
"""
        + footer()
    )


def not_found() -> str:
    name = "404.html"
    description = "The address does not match a page of this site. Go to the home page of Stowr or to the guide."
    page = head(name, "Page not found", description)
    # The page 404 can be served at any depth: it loads its files from the public address.
    page = page.replace('<meta name="color-scheme"', '<meta name="robots" content="noindex">\n<meta name="color-scheme"', 1)
    page = page.replace('<link rel="canonical" href="' + SITE_URL + '404.html">\n', "")
    page = page.replace(f'<meta property="og:url" content="{SITE_URL}404.html">\n', "")
    for rel in ("assets/favicon.svg", "assets/favicon-32.png", "assets/favicon.ico", "assets/apple-touch-icon.png", "assets/site.css", "assets/site.js", "site.webmanifest"):
        page = page.replace(f'"{rel}"', f'"{SITE_URL}{rel}"')
    body = header(name)
    body = body.replace('href="index.html"', f'href="{SITE_URL}index.html"')
    body = re.sub(r'<a href="([a-z-]+\.html)"', lambda m: f'<a href="{SITE_URL}{m.group(1)}"', body)
    main = (
        # The rule .page-404 sets the vertical padding. The inner .wrap keeps the side gutter on a narrow screen.
        '<div class="page-404"><div class="wrap narrow"><p class="eyebrow"><span class="badge">Error 404</span></p><h1>Page not found</h1>'
        '<p class="lede">The address does not match a page of this site.</p>'
        f'<div class="btn-row"><a class="btn primary" href="{SITE_URL}index.html">Go to the Stowr home page</a>'
        f'<a class="btn" href="{SITE_URL}getting-started.html">Getting started</a>'
        f'<a class="btn" href="{FAMILY_HOME}">ProcurAuth home</a></div></div></div>\n'
    )
    foot = footer()
    foot = re.sub(r'href="([a-z-]+\.html)"', lambda m: f'href="{SITE_URL}{m.group(1)}"', foot)
    return page + body + main + foot


def image_size(path: Path) -> tuple[int, int] | None:
    """Return the intrinsic width and height of a PNG, WebP, JPEG, GIF or SVG file, or None."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        kind = data[12:16]
        if kind == b"VP8X":
            return 1 + int.from_bytes(data[24:27], "little"), 1 + int.from_bytes(data[27:30], "little")
        if kind == b"VP8 ":
            return int.from_bytes(data[26:28], "little") & 0x3FFF, int.from_bytes(data[28:30], "little") & 0x3FFF
        if kind == b"VP8L":
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        return None
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return int.from_bytes(data[6:8], "little"), int.from_bytes(data[8:10], "little")
    if data[:2] == b"\xff\xd8":
        i = 2
        while i + 9 < len(data) and data[i] == 0xFF:
            marker = data[i + 1]
            length = int.from_bytes(data[i + 2:i + 4], "big")
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                return int.from_bytes(data[i + 7:i + 9], "big"), int.from_bytes(data[i + 5:i + 7], "big")
            i += 2 + length
        return None
    if path.suffix == ".svg":
        root = re.search(r"<svg\b[^>]*>", data.decode("utf-8", "replace"), re.S)
        if not root:
            return None
        tag = root.group(0)
        width = re.search(r'\swidth="([\d.]+)(?:px)?"', tag)
        height = re.search(r'\sheight="([\d.]+)(?:px)?"', tag)
        if width and height:
            return round(float(width.group(1))), round(float(height.group(1)))
        box = re.search(r'\sviewBox="\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*"', tag)
        if box:
            return round(float(box.group(1))), round(float(box.group(2)))
    return None


def size_images(name: str, page: str) -> str:
    """Write the intrinsic width and height on each local image, so that the layout does not move while it loads.

    The browser loads the image in the hero first, with a high priority. It loads each other image only when the image is
    near the visible part of the page. A local image without a known size stops the build. A local image must have an
    address relative to the page: an address that starts with "/" stops the build. The build ignores a query and a
    fragment in the address.
    """
    hero = re.search(r'<section class="hero".*?</section>', page, re.S)
    hero_span = hero.span() if hero else (0, 0)

    def fix(match: re.Match[str]) -> str:
        tag = match.group(0)
        src = re.search(r'\ssrc="([^"]+)"', tag)
        if src and " width=" not in tag and not re.match(r"^([a-z][a-z0-9+.-]*:|//)", src.group(1)):
            address = html.unescape(src.group(1))
            if address.startswith("/"):
                raise SystemExit(f"site: {name}: the image {src.group(1)} must have an address relative to the page")
            target = DOCS / re.split(r"[?#]", address, maxsplit=1)[0]
            size = image_size(target)
            if size is None:
                raise SystemExit(f"site: {name}: the size of the image {src.group(1)} is unknown")
            tag = tag.replace(src.group(0), f'{src.group(0)} width="{size[0]}" height="{size[1]}"', 1)
        tag = re.sub(r'\s(loading|fetchpriority)="[^"]*"', "", tag)[:-1].rstrip(" /")
        if hero_span[0] <= match.start() < hero_span[1]:
            return tag + ' loading="eager" fetchpriority="high">'
        return tag + ' loading="lazy">'

    return re.sub(r"<img\b[^>]*>", fix, page)


def small_files() -> dict[str, str]:
    urls = [SITE_URL] + [SITE_URL + p[0] for p in PAGES if p[0] not in ("index.html",)]
    sitemap = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    sitemap += "".join(f"  <url><loc>{u}</loc></url>\n" for u in urls) + "</urlset>\n"
    manifest = """{
  "name": "Stowr",
  "short_name": "Stowr",
  "description": "A browser for S3-compatible storage, Google Cloud Storage and folders of the server.",
  "start_url": "index.html",
  "scope": "./",
  "display": "browser",
  "background_color": "#fafafd",
  "theme_color": "#4338ca",
  "icons": [
    { "src": "assets/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "assets/icon-512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
"""
    robots = f"User-agent: *\nAllow: /\n\nSitemap: {SITE_URL}sitemap.xml\n"
    return {"sitemap.xml": sitemap, "site.webmanifest": manifest, "robots.txt": robots}


def build() -> dict[str, str]:
    out: dict[str, str] = {}
    for name, title, _short, source, eyebrow, lede, _nav in PAGES:
        page = overview() if name == "index.html" else doc_page(name, title, eyebrow, lede, source)
        out[name] = size_images(name, page)
    out["404.html"] = size_images("404.html", not_found())
    out.update(small_files())
    return out


def main(argv: list[str]) -> int:
    check = "--check" in argv
    pages = build()
    stale: list[str] = []
    for name, text in sorted(pages.items()):
        path = DOCS / name
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current != text:
            stale.append(name)
            if not check:
                path.write_text(text, encoding="utf-8")
    if check:
        if stale:
            sys.stdout.write("site: these pages differ from their source: " + ", ".join(stale) + "\nRun: python3 -I scripts/build-site.py\n")
            return 1
        sys.stdout.write(f"site: {len(pages)} files are current\n")
        return 0
    sys.stdout.write(f"site: wrote {len(stale)} of {len(pages)} files\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
