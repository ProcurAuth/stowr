#!/usr/bin/env python3
"""Check the documents and the site of this repository. Use only the Python standard library.

Use:
    python3 -I scripts/check-docs.py [--online] [CHECK ...]

The checks are: links, site, ste, hygiene. Without a name, the script runs all of them.
The option --online also asks each public URL with an HTTP request. Without it, the script
makes no network request and it maps the public URLs of this repository to local files.
The exit code is 0 when no check finds a problem.
"""

from __future__ import annotations

import html.parser
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE_URL = "https://procurauth.github.io/stowr/"
REPO_URL = "https://github.com/ProcurAuth/stowr"
DOCS = ROOT / "docs"

# Files that are not documents of this project, or that hold a fixed standard text.
NOT_STE = {"CODE_OF_CONDUCT.md", "THIRD-PARTY-NOTICES.md"}
NOT_CHECKED_DIRS = ("target/", "src/public/assets/vendor/")
# The normative texts have numbered paragraphs of many sentences. Their findings are warnings, not failures.
NORMATIVE = {"protocol/procurauth-protocol.md", "bindings/mcp/procurauth-mcp-binding.md"}


def tracked_and_new() -> list[Path]:
    """Return the files that git tracks, and the files that git does not ignore."""
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT, check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    return sorted(ROOT / line for line in out if (ROOT / line).is_file())


def files_with(suffix: str) -> list[Path]:
    return [p for p in tracked_and_new() if p.suffix == suffix
            and not str(p.relative_to(ROOT)).startswith(NOT_CHECKED_DIRS)]


# ---------------------------------------------------------------- anchors

def github_slug(heading: str) -> str:
    """Make the anchor that GitHub gives to a Markdown heading."""
    text = re.sub(r"`([^`]*)`", r"\1", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def markdown_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    fence = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        match = re.match(r"#{1,6}\s+(.*)", line)
        if match:
            slug = github_slug(match.group(1))
            n = counts.get(slug, 0)
            counts[slug] = n + 1
            anchors.add(slug if n == 0 else f"{slug}-{n}")
    return anchors


class PageParser(html.parser.HTMLParser):
    """Collect the facts of one HTML page that the checks need."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.links: list[tuple[str, str]] = []      # (attribute, value) of a, link, img, script
        self.tags: list[tuple[str, dict[str, str | None], int]] = []
        self.text_stack: list[str] = []
        self.title = ""
        self._in_title = False
        self.headings: list[tuple[int, str]] = []
        self._heading: tuple[int, list[str]] | None = None
        self.blocks: list[str] = []                  # visible text blocks, for the STE check
        self._block: list[str] | None = None
        self._skip = 0
        self._code = 0
        self._stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        self.tags.append((tag, a, self.getpos()[0]))
        self._stack.append(tag)
        if "id" in a and a["id"]:
            self.ids.append(a["id"])
        if tag == "title":
            self._in_title = True
        if tag in ("a", "link") and a.get("href") is not None:
            self.links.append(("href", a["href"] or ""))
        if tag in ("img", "script", "source") and a.get("src") is not None:
            self.links.append(("src", a["src"] or ""))
        if re.fullmatch(r"h[1-6]", tag):
            self._heading = (int(tag[1]), [])
        if tag in ("script", "style", "pre", "svg", "code-block"):
            self._skip += 1
        if tag == "code" and self._skip == 0 and self._block is not None:
            self._code += 1
            self._block.append("X")  # Inline code is a technical name: it counts as one word.
        if tag in ("p", "li", "td", "dd", "figcaption", "h1", "h2", "h3", "h4", "summary") and self._skip == 0:
            self._block = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if self._heading and tag == f"h{self._heading[0]}":
            self.headings.append((self._heading[0], "".join(self._heading[1]).strip()))
            self._heading = None
        if tag == "code" and self._code:
            self._code -= 1
        if tag in ("script", "style", "pre", "svg", "code-block"):
            self._skip = max(0, self._skip - 1)
        if tag in ("p", "li", "td", "dd", "figcaption", "h1", "h2", "h3", "h4", "summary") and self._block is not None:
            text = " ".join("".join(self._block).split())
            if text:
                self.blocks.append(text)
            self._block = None
        while self._stack and self._stack.pop() != tag:
            pass

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._heading:
            self._heading[1].append(data)
        if self._block is not None and self._skip == 0 and not self._code:
            self._block.append(data)


def parse_page(path: Path) -> PageParser:
    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser


# ----------------------------------------------------------------- links

class Report:
    def __init__(self) -> None:
        self.problems: list[str] = []
        self.warnings: list[str] = []
        self.counts: dict[str, int] = {}

    def add(self, name: str, message: str) -> None:
        self.problems.append(f"{name}: {message}")

    def warn(self, name: str, message: str) -> None:
        self.warnings.append(f"{name}: {message}")

    def count(self, name: str, n: int = 1) -> None:
        self.counts[name] = self.counts.get(name, 0) + n


def local_target(source: Path, target: str) -> tuple[Path | None, str]:
    """Map a link to a local file and an anchor. Return (None, "") for a link that is not local."""
    if target.startswith(SITE_URL):
        rest = target[len(SITE_URL):]
        path_part, _, anchor = rest.partition("#")
        path_part = path_part.split("?")[0] or "index.html"
        return DOCS / path_part, anchor
    for prefix in (f"{REPO_URL}/blob/main/", f"{REPO_URL}/tree/main/"):
        if target.startswith(prefix):
            rest = target[len(prefix):]
            path_part, _, anchor = rest.partition("#")
            return ROOT / path_part.rstrip("/"), anchor
    if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("//"):
        return None, ""
    path_part, _, anchor = target.partition("#")
    path_part = path_part.split("?")[0]
    if not path_part:
        return source, anchor
    if path_part.startswith("/"):
        return ROOT / path_part.lstrip("/"), anchor
    return (source.parent / urllib.parse.unquote(path_part)).resolve(), anchor


def anchors_of(path: Path, cache: dict[Path, set[str]]) -> set[str]:
    if path not in cache:
        if path.suffix == ".md":
            cache[path] = markdown_anchors(path)
        elif path.suffix == ".html":
            page = parse_page(path)
            cache[path] = set(page.ids)
        else:
            cache[path] = set()
    return cache[path]


MD_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_ATTR = re.compile(r"""(?:href|src|srcset)=["']([^"']+)["']""")


def extract_markdown_links(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    fence = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        clean = re.sub(r"`[^`]*`", "", line)
        for match in MD_LINK.finditer(clean):
            out.append((number, match.group(1).strip("<>")))
        for match in HTML_ATTR.finditer(clean):
            out.append((number, match.group(1)))
    return out


def check_links(report: Report, online: bool) -> None:
    cache: dict[Path, set[str]] = {}
    public: dict[str, list[str]] = {}
    for path in files_with(".md"):
        name = str(path.relative_to(ROOT))
        for number, target in extract_markdown_links(path):
            check_one_link(report, cache, public, path, f"{name}:{number}", target)
    for path in sorted(DOCS.glob("*.html")):
        page = parse_page(path)
        name = str(path.relative_to(ROOT))
        for _, target in page.links:
            check_one_link(report, cache, public, path, name, target)
        for tag, attrs, line in page.tags:
            if tag == "meta" and attrs.get("property") == "og:image" or tag == "meta" and attrs.get("name") == "twitter:image":
                check_one_link(report, cache, public, path, f"{name}:{line}", attrs.get("content") or "")
            if tag == "link" and attrs.get("rel") == "canonical":
                check_one_link(report, cache, public, path, f"{name}:{line}", attrs.get("href") or "")
    if online:
        check_online(report, public)


def check_one_link(report: Report, cache: dict[Path, set[str]], public: dict[str, list[str]],
                   source: Path, where: str, target: str) -> None:
    if not target or target.startswith(("mailto:", "javascript:", "data:")):
        return
    report.count("links")
    for part in re.split(r"\s*,\s*", target) if " " in target and "," in target else [target]:
        part = part.split()[0]
        path, anchor = local_target(source, part)
        if path is None:
            if part.startswith("http"):
                public.setdefault(part.split("#")[0], []).append(where)
            continue
        if part.startswith(("http://", "https://")):
            public.setdefault(part.split("#")[0], []).append(where)
        if not path.exists():
            report.add("links", f"{where}: the file of `{part}` does not exist")
            continue
        if anchor and path.is_file() and path.suffix in (".md", ".html"):
            if urllib.parse.unquote(anchor) not in anchors_of(path, cache):
                report.add("links", f"{where}: the anchor `#{anchor}` is not in {path.relative_to(ROOT)}")


def check_online(report: Report, public: dict[str, list[str]]) -> None:
    import time
    for url, places in sorted(public.items()):
        if not url.startswith(("http://", "https://")):
            continue
        status = 0
        for attempt in range(4):
            request = urllib.request.Request(url, method="GET", headers={"User-Agent": "procurauth-link-check"})
            try:
                with urllib.request.urlopen(request, timeout=30) as answer:
                    status = answer.status
            except urllib.error.HTTPError as error:
                status = error.code
            except (urllib.error.URLError, TimeoutError) as error:
                report.add("links", f"{url}: {error} (in {places[0]})")
                status = -1
                break
            if status not in (429, 500, 502, 503, 504):
                break
            time.sleep(3 * (attempt + 1))
        if status == -1:
            continue
        report.count("online")
        if status >= 400:
            local, _ = local_target(ROOT / "README.md", url)
            if status == 404 and local is not None and local.exists():
                # The file exists in the working tree. The public address answers after the next publication.
                report.warn("links", f"{url}: HTTP 404, the file is local only (in {places[0]})")
            else:
                report.add("links", f"{url}: HTTP {status} (in {places[0]})")


# ------------------------------------------------------------------ site

NAV_PAGES = ["index.html", "getting-started.html", "configuration.html", "architecture.html",
             "security.html", "operations.html", "reference.html", "changelog.html"]
EXTRA_PAGES = ["access.html", "previews.html", "conformance.html", "development.html"]


def check_site(report: Report) -> None:
    pages = sorted(DOCS.glob("*.html"))
    names = [p.name for p in pages]
    for page_name in NAV_PAGES + EXTRA_PAGES:
        if page_name not in names:
            report.add("site", f"docs/{page_name} is missing")
    navs: dict[str, list[str]] = {}
    for path in pages:
        page = parse_page(path)
        name = f"docs/{path.name}"
        report.count("pages")
        text = path.read_text(encoding="utf-8")
        if path.name == "404.html":
            # The 404 page loads its files from the public address: a missing page can have any depth.
            pass
        h1 = [h for h in page.headings if h[0] == 1]
        if len(h1) != 1:
            report.add("site", f"{name}: {len(h1)} h1 headings (one is needed)")
        previous = 0
        for level, heading in page.headings:
            if previous and level > previous + 1:
                report.add("site", f"{name}: the heading `{heading}` jumps from h{previous} to h{level}")
            previous = level
        seen: set[str] = set()
        for identifier in page.ids:
            if identifier in seen:
                report.add("site", f"{name}: the id `{identifier}` is not unique")
            seen.add(identifier)
        if not page.title.strip():
            report.add("site", f"{name}: no title")
        if '<html lang="en"' not in text:
            report.add("site", f"{name}: no lang attribute")
        if 'name="viewport"' not in text:
            report.add("site", f"{name}: no viewport")
        if text.count("<main") != 1 or "<footer" not in text or "<nav" not in text:
            report.add("site", f"{name}: the landmarks main, nav and footer are not all present")
        if 'class="skip"' not in text:
            report.add("site", f"{name}: no skip link")
        for tag, attrs, line in page.tags:
            if tag == "img" and attrs.get("alt") is None:
                report.add("site", f"{name}:{line}: an img has no alt attribute")
            if tag == "svg" and attrs.get("role") == "img":
                pass
            if tag == "a" and attrs.get("target") == "_blank" and "noopener" not in (attrs.get("rel") or ""):
                report.add("site", f"{name}:{line}: target=_blank without rel=noopener")
            if tag == "meta" and attrs.get("property") == "og:image" and not (attrs.get("content") or "").startswith(SITE_URL):
                report.add("site", f"{name}:{line}: og:image is not an address of the site")
            if tag in ("link", "script", "img", "source", "iframe") and name != "docs/404.html":
                value = attrs.get("href") or attrs.get("src") or ""
                if re.match(r"(https?:)?//", value) and not (tag == "link" and attrs.get("rel") in ("canonical", "alternate")):
                    report.add("site", f"{name}:{line}: an external request `{value}`")
            if attrs.get("tabindex") not in (None, "0", "-1"):
                report.add("site", f"{name}:{line}: a positive tabindex")
        # An empty link or an empty button has no name for a screen reader.
        for match in re.finditer(r"<(a|button)\b([^>]*)>(.*?)</\1>", text, re.S):
            inner = re.sub(r"<svg.*?</svg>", "", match.group(3), flags=re.S)
            visible = re.sub(r"<[^>]+>", "", inner).strip()
            if not visible and "aria-label" not in match.group(2) and "title=" not in match.group(2):
                report.add("site", f"{name}: a {match.group(1)} has no name: {match.group(0)[:80]}")
        for match in re.finditer(r"<th\b(?![^>]*scope)([^>]*)>", text):
            if "<thead" in text:
                pass
        nav = re.search(r'<nav id="site-nav".*?</nav>', text, re.S)
        if nav and path.name != "404.html":
            navs[path.name] = re.findall(r'<a href="([^"]+)"', nav.group(0))
        elif path.name != "404.html":
            report.add("site", f"{name}: no main navigation")
        if re.search(r"<style[^>]*>[^<]*(@import|@font-face)", text):
            report.add("site", f"{name}: a web font or an import")
        canonical = [a.get("href") for t, a, _ in page.tags if t == "link" and a.get("rel") == "canonical"]
        expected = SITE_URL if path.name == "index.html" else SITE_URL + path.name
        if path.name != "404.html" and canonical != [expected]:
            report.add("site", f"{name}: the canonical link is {canonical}, not {expected}")
    reference = navs.get("index.html")
    for name, links in navs.items():
        if links != reference:
            report.add("site", f"docs/{name}: the navigation differs from the navigation of index.html")
    if reference is not None:
        for page_name in NAV_PAGES:
            if page_name not in reference:
                report.add("site", f"the navigation has no link to {page_name}")
    css = (DOCS / "assets" / "site.css").read_text(encoding="utf-8")
    if re.search(r"url\(\s*['\"]?https?:|@import|@font-face", css):
        report.add("site", "site.css makes an external request or loads a font")
    # The sitemap lists each page of the navigation, and nothing else.
    sitemap = DOCS / "sitemap.xml"
    if sitemap.exists():
        listed = re.findall(r"<loc>([^<]+)</loc>", sitemap.read_text(encoding="utf-8"))
        wanted = sorted([SITE_URL] + [SITE_URL + n for n in NAV_PAGES + EXTRA_PAGES if n != "index.html"])
        if sorted(listed) != wanted:
            report.add("site", f"sitemap.xml differs from the pages: {sorted(set(listed) ^ set(wanted))}")
    else:
        report.add("site", "docs/sitemap.xml is missing")
    for required in ("robots.txt", "404.html", ".nojekyll", "site.webmanifest", "assets/og.png", "assets/og.svg",
                     "assets/favicon.svg", "assets/favicon.ico", "assets/apple-touch-icon.png", "assets/family.svg",
                     "assets/banner.svg", "assets/logo.svg", "assets/architecture.svg", "assets/flow.svg",
                     "assets/access-model.svg"):
        if not (DOCS / required).exists():
            report.add("site", f"docs/{required} is missing")
    robots = DOCS / "robots.txt"
    if robots.exists() and SITE_URL + "sitemap.xml" not in robots.read_text(encoding="utf-8"):
        report.add("site", "robots.txt does not name the sitemap")
    total = 0
    for picture in sorted(list(DOCS.rglob("*.png")) + list(DOCS.rglob("*.webp")) + list(DOCS.rglob("*.svg"))):
        size = picture.stat().st_size
        total += size
        if picture.suffix != ".svg" and size > 250 * 1024:
            report.add("site", f"{picture.relative_to(ROOT)} is larger than 250 KB")
    if total > 3 * 1024 * 1024:
        report.add("site", f"the pictures of docs/ have {total} bytes: the limit is 3 MB")
    report.count("picture bytes", total)
    # The pages must be the output of scripts/build-site.py.
    result = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "build-site.py"), "--check"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        report.add("site", result.stdout.strip().replace("\n", " "))


# ------------------------------------------------------------------- STE

ALLOWED_ING = {
    "string", "strings", "ceiling", "ceilings", "nothing", "anything", "something", "everything", "during",
    "thing", "bring", "encoding", "padding", "being", "binding", "bindings", "meaning", "signing", "mapping",
    "remaining", "finding", "findings", "warning", "warnings", "pending", "building", "string", "morning",
    "evening", "king", "ring", "spring", "sibling", "darling",
    # Technical names and technical verbs of the field.
    "listing", "listings", "versioning", "setting", "settings", "heading", "headings", "logging", "parsing", "decoding",
    "hashing", "streaming", "sorting", "scrolling", "nesting", "browsing", "forwarding", "substring", "caching",
    "routing", "scanning", "padding", "tagging", "encoding", "marshalling", "bucketing", "indexing", "mapping",
    # Names of pages and of headings.
    "getting", "troubleshooting", "contributing",
}
BANNED = {
    "ensure": "make sure", "ensures": "make sure", "provide": "give", "provides": "give", "allow": "let",
    "allows": "let", "allowed": "valid, or can", "utilize": "use", "e.g.": "for example", "i.e.": "that is",
    "etc.": "list each item", "via": "with",
}
PHRASAL = [
    "set up", "carry out", "turn on", "turn off", "look up", "find out", "fill in", "point out", "give up", "go on",
    "come back", "build up", "break down", "pick up", "write down", "clean up", "hand over", "take out", "cut off",
    "back up", "line up", "start up", "shut down", "log in", "sign in", "log out", "sign up",
]


def split_sentences(text: str) -> list[str]:
    out: list[str] = []
    current = ""
    chars = list(text)
    for i, c in enumerate(chars):
        current += c
        if c in ".?!" and (i + 1 == len(chars) or chars[i + 1].isspace()):
            out.append(current.strip())
            current = ""
    if current.strip():
        out.append(current.strip())
    return out


def ste_problems(text: str, count_sentences: bool = True) -> list[str]:
    found: list[str] = []
    sentences = split_sentences(text)
    if count_sentences and len(sentences) > 6:
        found.append(f"{len(sentences)} sentences in one paragraph")
    for sentence in sentences:
        words = sentence.split()
        if len(words) > 25:
            found.append(f"{len(words)} words: {sentence[:110]}")
        for word in words:
            bare = word.strip("\"'()[]{}:;,!?*_<>").lower()
            letters = bare.rstrip(".")
            if len(letters) >= 5 and letters.endswith("ing") and letters.isascii() and letters.isalpha() \
                    and letters not in ALLOWED_ING:
                found.append(f"the -ing form `{letters}` in: {sentence[:90]}")
            if bare in BANNED or letters in BANNED:
                key = bare if bare in BANNED else letters
                found.append(f"the word `{key}` (use {BANNED[key]}) in: {sentence[:90]}")
        lower = f" {sentence.lower()} "
        for phrase in PHRASAL:
            if f" {phrase} " in lower:
                found.append(f"the phrasal verb `{phrase}` in: {sentence[:90]}")
    return found


def clean_markdown(text: str) -> str:
    # A quoted text of the interface is a name, not a sentence of the document.
    text = re.sub(r'"[^"]{20,}"', '"X"', text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"`[^`]*`", "X", text)
    return text.replace("*", "")


def markdown_paragraphs(path: Path) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    current: list[str] = []
    start = 0
    fence = False
    html_block = False

    def flush() -> None:
        if current:
            out.append((start, clean_markdown(" ".join(current).strip())))
            current.clear()

    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            fence = not fence
            continue
        if fence or stripped.startswith("|") or not stripped or stripped.startswith("<!--"):
            flush()
            continue
        if stripped.startswith("<") and not stripped.startswith("<http"):
            flush()
            html_block = not stripped.endswith(">") and not stripped.startswith("</")
            continue
        if stripped.startswith("#"):
            flush()
            out.append((number, clean_markdown(stripped.lstrip("#").strip())))
            continue
        marker = re.match(r"\s*(?:[-*]|\d+\.)\s+", line)
        if marker:
            flush()
            start = number
            current.append(line[marker.end():].strip())
        else:
            if not current:
                start = number
            current.append(stripped)
    flush()
    return out


def check_ste(report: Report) -> None:
    for path in files_with(".md"):
        if path.name in NOT_STE:
            continue
        name = str(path.relative_to(ROOT))
        report.count("markdown files")
        seen: set[str] = set()
        for number, text in markdown_paragraphs(path):
            for problem in ste_problems(text):
                line = f"{name}:{number}: {problem}"
                if line not in seen:
                    seen.add(line)
                    if name in NORMATIVE:
                        report.warn("ste", line)
                    else:
                        report.add("ste", line)
    for path in sorted(DOCS.glob("*.html")):
        page = parse_page(path)
        report.count("html files")
        for block in page.blocks:
            block = re.sub(r'"[^"]{20,}"', '"X"', block)
            for problem in ste_problems(block, count_sentences=False):
                report.add("ste", f"docs/{path.name}: {problem}")


# --------------------------------------------------------------- hygiene

HYGIENE = [
    (re.compile(r"\bsccagg5\b", re.I), "the old account name"),
    (re.compile(r"[A-Za-z0-9._%+-]+@(?!example\.|users\.noreply)[A-Za-z0-9-]+\.[A-Za-z]{2,}"), "an e-mail address"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "an IP address"),
    (re.compile(r"docker\s+push|ghcr\.io|docker\.io/[a-z]+/", re.I), "an image registry"),
    (re.compile(r"\b(?:ghp_|github_pat_|gho_|AKIA|xox[bp]-|sk-[A-Za-z0-9]{20})[A-Za-z0-9_]{8,}"), "a token"),
    (re.compile(r"the owner (?:decides if|chooses|updates the site)|the maintainers? (?:decides|keeps|owns)|the lead\b", re.I), "an internal decision"),
    (re.compile(r"\blot [A-Z]{1,2}[0-9]\b"), "an internal lot name"),
]
ALLOWED_IPS = {"127.0.0.1", "0.0.0.0", "1.2.3.4", "1.1.0.0", "1.0.0.0"}
# Public test keys. See .gitignore.
PUBLIC_KEY_FILES = re.compile(r"src/provider/test_server\.rs$")


def check_hygiene(report: Report) -> None:
    for path in tracked_and_new():
        rel = str(path.relative_to(ROOT))
        if rel.startswith(("target/", ".git/")) or rel in ("Cargo.lock",) or path.suffix in (".png", ".ico"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        report.count("files")
        if re.search(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s+[A-Za-z0-9+/=]{40,}", text) and not PUBLIC_KEY_FILES.search(rel):
            report.add("hygiene", f"{rel}: a private key")
        if rel in ("LICENSE-MIT", "LICENSE-APACHE", "scripts/check-docs.py", "CODE_OF_CONDUCT.md", "THIRD-PARTY-NOTICES.md"):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for pattern, what in HYGIENE:
                for match in pattern.finditer(line):
                    value = match.group(0)
                    if what == "an IP address":
                        if value in ALLOWED_IPS or value.startswith(("203.0.113.", "127.", "192.0.2.", "198.51.100.", "10.")):
                            continue
                        if re.search(r"version|\d+\.\d+\.\d+\.\d+-", line, re.I) or rel.endswith((".lock", ".json")) and "ip" not in line.lower():
                            continue
                    if what == "the old account name" and rel in (".github/CODEOWNERS",):
                        continue  # CODEOWNERS names the account of the owner.
                    if what == "an e-mail address":
                        before = line[max(0, match.start() - 60):match.start()]
                        if "git@github.com" in value or value.endswith((".example", ".invalid", ".test", ".example.com")):
                            continue
                        if "://" in before or "gserviceaccount.com" in line:
                            continue  # The user information of a URL, or a fake service account of a test.
                        if rel.endswith("fixtures.json") and value == "accv@accv.es":
                            continue  # The issuer contact of a public certificate in a test fixture.
                    if what == "a token" and value == "AKIAIOSFODNN7EXAMPLE":
                        continue  # The access key id of the AWS documentation: a public test vector.
                    report.add("hygiene", f"{rel}:{number}: {what}: {value}")


CHECKS = {"links": check_links, "site": check_site, "ste": check_ste, "hygiene": check_hygiene}


def main(argv: list[str]) -> int:
    online = "--online" in argv
    names = [a for a in argv if not a.startswith("--")] or list(CHECKS)
    unknown = [n for n in names if n not in CHECKS]
    if unknown:
        sys.stderr.write(f"Unknown check: {unknown[0]}. Use one of: {', '.join(CHECKS)}.\n")
        return 2
    report = Report()
    for name in names:
        before = len(report.problems)
        if name == "links":
            check_links(report, online)
        else:
            CHECKS[name](report)
        sys.stdout.write(f"== {name}: {len(report.problems) - before} problems\n")
    for line in report.problems:
        sys.stdout.write(line + "\n")
    if report.warnings:
        sys.stdout.write(f"warnings (not a failure): {len(report.warnings)}\n")
        for line in report.warnings[:3]:
            sys.stdout.write(f"  {line}\n")
    sys.stdout.write("counts: " + ", ".join(f"{k}={v}" for k, v in sorted(report.counts.items())) + "\n")
    return 1 if report.problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
