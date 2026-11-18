import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).parents[1] / "check_readme_links.py"
SPEC = importlib.util.spec_from_file_location("check_readme_links", SCRIPT_PATH)
check_readme_links = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_readme_links)


class ReadmeLinkCheckTests(unittest.TestCase):
    def write_readme(self, directory: Path, links: list[str]) -> Path:
        readme = directory / "README.md"
        readme.write_text("\n".join(links), encoding="utf-8")
        return readme

    def test_extracts_only_quark_documentation_links(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            readme = self.write_readme(
                directory,
                [
                    "https://quark-engine.readthedocs.io/en/latest/guide.html#intro",
                    "https://example.com/en/latest/guide.html#ignored",
                ],
            )

            self.assertEqual(
                check_readme_links.extract_doc_links(readme),
                [("guide.html", "intro")],
            )

    def test_accepts_existing_page_and_anchor(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            html_dir = directory / "html"
            html_dir.mkdir()
            (html_dir / "guide.html").write_text(
                '<section id="intro">Guide</section>', encoding="utf-8"
            )
            readme = self.write_readme(
                directory,
                ["https://quark-engine.readthedocs.io/en/latest/guide.html#intro"],
            )

            self.assertEqual(check_readme_links.validate_links(readme, html_dir), [])

    def test_reports_missing_pages_and_anchors(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            html_dir = directory / "html"
            html_dir.mkdir()
            (html_dir / "guide.html").write_text(
                '<section id="intro">Guide</section>', encoding="utf-8"
            )
            readme = self.write_readme(
                directory,
                [
                    "https://quark-engine.readthedocs.io/en/latest/missing.html",
                    "https://quark-engine.readthedocs.io/en/latest/guide.html#missing",
                ],
            )

            self.assertEqual(
                check_readme_links.validate_links(readme, html_dir),
                [
                    "Missing documentation page: missing.html",
                    "Missing anchor 'missing' in guide.html",
                ],
            )
