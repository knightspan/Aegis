"""The built UI must work with the ethernet unplugged. Prove it, do not assume.

The naive form of this test greps the bundle for ``http://`` and fails on any
hit. That form is wrong in a way worth writing down, because the wrongness is
instructive: a React production build contains W3C **namespace URIs** - strings
like ``http://www.w3.org/2000/svg`` - which are identifiers, not addresses.
Nothing ever fetches them; they are compared as strings when the DOM decides
whether an element is SVG. A test that failed on those would be unfixable
without forking React, so the first person to hit it would delete the test, and
the real property would then go unchecked.

So this checks the property that actually matters, in two layers:

1. **No external origin in a fetchable position.** Anything that would cause a
   network request - ``src=``, ``href=``, ``url()``, ``fetch()``, ``import()``,
   ``EventSource``, ``WebSocket``, ``XMLHttpRequest`` - must be same-origin or
   relative. This is the strict check.
2. **Every remaining literal is on a justified allowlist.** A new external
   string that is not a namespace URI fails the build, so a CDN link cannot be
   added without someone deliberately widening the list.
"""

from __future__ import annotations

import re
from pathlib import Path

#: Origins a bundled asset may legitimately mention as an *identifier*.
#: Nothing here is ever fetched: XML namespace URIs are compared as strings,
#: and React's error-decoder URL appears inside a message it prints to the
#: console when a minified error is thrown.
ALLOWED_IDENTIFIER_ORIGINS = {
    "http://www.w3.org",
    "https://www.w3.org",
    "https://react.dev",
    "https://reactjs.org",
}

#: Hosts a fetch may legitimately target. Everything is same-origin, so this is
#: only reached by an absolute URL somebody wrote deliberately.
ALLOWED_FETCH_HOSTS = {"localhost", "127.0.0.1", "[::1]"}

#: Positions that cause the browser to make a request.
_FETCHABLE = re.compile(
    r"""(?:
        \bsrc\s*=\s*["']([^"']+)["']
      | \bhref\s*=\s*["']([^"']+)["']
      | \burl\(\s*["']?([^"')]+)["']?\s*\)
      | \bfetch\(\s*["']([^"']+)["']
      | \bimport\(\s*["']([^"']+)["']
      | \bnew\s+EventSource\(\s*["']([^"']+)["']
      | \bnew\s+WebSocket\(\s*["']([^"']+)["']
      | \.open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']
    )""",
    re.VERBOSE,
)

_ORIGIN = re.compile(r"https?://[^\s\"'`)<>\\]+")


def _bundle_files(dist: Path) -> list[Path]:
    return [item for item in dist.rglob("*") if item.is_file()]


def test_the_bundle_exists_and_is_not_empty(ui_dist: Path) -> None:
    files = _bundle_files(ui_dist)
    assert (ui_dist / "index.html").is_file()
    assert any(item.suffix == ".js" for item in files)
    assert any(item.suffix == ".css" for item in files)


def test_nothing_in_a_fetchable_position_points_off_this_host(
    ui_dist: Path,
) -> None:
    """The strict check: anything the browser would actually request."""
    offenders: list[str] = []
    for path in _bundle_files(ui_dist):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # a binary asset requests nothing
        for match in _FETCHABLE.finditer(text):
            target = next(group for group in match.groups() if group)
            if not target.startswith(("http://", "https://", "//")):
                continue  # relative or same-origin
            host = target.split("//", 1)[1].split("/", 1)[0].split(":")[0]
            if host not in ALLOWED_FETCH_HOSTS:
                offenders.append(f"{path.name}: {target}")

    assert not offenders, (
        "the bundle would fetch from outside this host, so it cannot run with "
        f"the network unplugged: {offenders}"
    )


def test_every_external_literal_is_a_justified_identifier(ui_dist: Path) -> None:
    """The backstop: a new external string cannot appear unnoticed.

    This is what stops someone adding a CDN link and having the strict check
    above miss it because it was written in a form the regex does not model.
    """
    unexpected: list[str] = []
    for path in _bundle_files(ui_dist):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for found in _ORIGIN.findall(text):
            scheme, _, rest = found.partition("//")
            host = rest.split("/", 1)[0].split(":")[0]
            origin = f"{scheme}//{host}"
            if origin in ALLOWED_IDENTIFIER_ORIGINS or host in ALLOWED_FETCH_HOSTS:
                continue
            unexpected.append(f"{path.name}: {found[:100]}")

    assert not unexpected, (
        "an external origin appeared in the bundle that is not a known "
        "identifier. If it is genuinely never fetched, add it to "
        f"ALLOWED_IDENTIFIER_ORIGINS with a reason: {unexpected}"
    )


#: Hosts that ship by accident. Matched against the *host* of a URL literal,
#: never as a bare substring: React's `ondoubleclick` event name contains
#: "doubleclick", and a substring check failed on it - which is the failure
#: mode that teaches people to delete the test rather than fix the bundle.
FORBIDDEN_HOSTS = (
    "google-analytics.com",
    "googletagmanager.com",
    "sentry.io",
    "segment.io",
    "posthog.com",
    "mixpanel.com",
    "hotjar.com",
    "doubleclick.net",
    "cloudflareinsights.com",
    "vercel-insights.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "esm.sh",
)


def test_no_analytics_or_telemetry_host_is_referenced(ui_dist: Path) -> None:
    """Named explicitly, because these are the ones that ship by accident."""
    hits: list[str] = []
    for path in _bundle_files(ui_dist):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for found in _ORIGIN.findall(text):
            _scheme, _, rest = found.partition("//")
            host = rest.split("/", 1)[0].split(":")[0].lower()
            for forbidden in FORBIDDEN_HOSTS:
                if host == forbidden or host.endswith(f".{forbidden}"):
                    hits.append(f"{path.name}: {found[:80]}")

    assert not hits, f"the bundle references a telemetry or CDN host: {hits}"


def test_the_html_loads_only_relative_assets(ui_dist: Path) -> None:
    """A relative base is what lets the bundle work from file:// as well."""
    html = (ui_dist / "index.html").read_text(encoding="utf-8")
    for match in re.finditer(r'(?:src|href)="([^"]+)"', html):
        target = match.group(1)
        assert not target.startswith(("http://", "https://", "//")), (
            f"index.html loads {target} from another origin"
        )


def test_every_font_is_bundled_and_served_from_the_app_itself(
    ui_dist: Path,
) -> None:
    """The typefaces ship inside the bundle and load same-origin, never remotely.

    This used to forbid fonts outright on the grounds that a webfont is a
    network request. A *remote* one is; a font file the app serves itself over
    loopback is not, and it is how the interface gets a face drawn to keep 0/O
    and 1/l/I apart in the serials an operator types. The property that matters
    is checked instead: every ``@font-face`` source is a relative URL naming a
    file that is in the bundle, so the fonts render with no network at all.
    """
    fonts = {
        item.name
        for item in _bundle_files(ui_dist)
        if item.suffix in {".woff", ".woff2", ".ttf", ".otf", ".eot"}
    }
    sources: list[str] = []
    for path in _bundle_files(ui_dist):
        if path.suffix != ".css":
            continue
        text = path.read_text(encoding="utf-8")
        for face in re.findall(r"@font-face\s*{([^}]*)}", text):
            sources.extend(re.findall(r"url\(\s*[\"']?([^\"')]+)", face))
    assert sources, "no @font-face found; the bundled faces did not make it in"
    for source in sources:
        assert not re.match(r"^[a-z][a-z0-9+.-]*:|^//", source, re.I), (
            f"a font is loaded from {source}, not from the bundle"
        )
        assert Path(source).name in fonts, f"{source} is not a file in the bundle"


def test_the_bundle_is_small_enough_to_review(ui_dist: Path) -> None:
    """A size bound, so a dependency cannot be added without anyone noticing.

    Not a performance target - it is loaded from disk over loopback. It is a
    review bound: a bundle that suddenly triples has grown a dependency, and
    that is worth a conversation before it ships on an air-gapped machine.
    """
    total = sum(item.stat().st_size for item in _bundle_files(ui_dist))
    assert total < 2 * 1024 * 1024, f"bundle grew to {total} bytes"
