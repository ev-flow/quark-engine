#!/usr/bin/env python3
"""Validate links from README.md to the rendered Quark Engine documentation."""

from __future__ import annotations

import argparse
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlparse


DOCS_HOST = "quark-engine.readthedocs.io"
DOCS_PREFIX = "/en/latest/"
URL_PATTERN = re.compile(r"https?://[^\s)>]+")


class AnchorParser(HTMLParser):
    """Collect HTML ids without depending on an external parser."""

    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)


def extract_doc_links(readme: Path) -> list[tuple[str, str | None]]:
    """Return local documentation page paths and optional anchors from README."""
    links: list[tuple[str, str | None]] = []

    for match in URL_PATTERN.finditer(readme.read_text(encoding="utf-8")):
        parsed = urlparse(match.group(0))
        if parsed.netloc != DOCS_HOST or not parsed.path.startswith(DOCS_PREFIX):
            continue

        page = unquote(parsed.path.removeprefix(DOCS_PREFIX)) or "index.html"
        anchor = unquote(parsed.fragment) or None
        links.append((page, anchor))

    return links


def validate_links(readme: Path, html_dir: Path) -> list[str]:
    """Return one descriptive error for every missing documentation target."""
    errors: list[str] = []

    for page, anchor in extract_doc_links(readme):
        target = html_dir / page
        if not target.is_file():
            errors.append(f"Missing documentation page: {page}")
            continue

        if anchor:
            parser = AnchorParser()
            parser.feed(target.read_text(encoding="utf-8"))
            if anchor not in parser.ids:
                errors.append(f"Missing anchor '{anchor}' in {page}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check README links against built documentation."
    )
    parser.add_argument("--readme", type=Path, default=Path("README.md"))
    parser.add_argument(
        "--html-dir", type=Path, default=Path("docs/_build/html")
    )
    args = parser.parse_args()

    errors = validate_links(args.readme, args.html_dir)
    if errors:
        print("README documentation link check failed:", file=sys.stderr)
        print(*errors, sep="\n", file=sys.stderr)
        return 1

    print(f"Validated {len(extract_doc_links(args.readme))} README documentation links.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
