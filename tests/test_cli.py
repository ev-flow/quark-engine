import json
from types import SimpleNamespace

from click.testing import CliRunner

from quark import cli


class DummyQuark:
    def __init__(self, *args, **kwargs):
        self.quark_analysis = SimpleNamespace(
            score_sum=0,
            weight_sum=0,
            summary_report_table="",
        )

    def run(self, rule_checker):
        pass

    def show_summary_report(self, rule_checker, threshold):
        pass


def get_rule_option():
    return next(param for param in cli.entry_point.params if param.name == "rule")


def test_custom_rule_file_does_not_require_default_rules_directory(
    tmp_path, monkeypatch
):
    missing_default_rules = tmp_path / "missing-rules"
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"not a real apk")

    custom_rule_path = tmp_path / "custom_rule.json"
    custom_rule_path.write_text(
        json.dumps(
            {
                "crime": "Test rule",
                "permission": [],
                "api": [
                    {
                        "class": "Landroid/test/First;",
                        "method": "first",
                        "descriptor": "()V",
                    },
                    {
                        "class": "Landroid/test/Second;",
                        "method": "second",
                        "descriptor": "()V",
                    },
                ],
                "score": 1,
                "label": ["test"],
            }
        )
    )

    monkeypatch.setattr(get_rule_option(), "default", str(missing_default_rules))
    monkeypatch.setattr(cli, "Quark", DummyQuark)

    result = CliRunner().invoke(
        cli.entry_point,
        ["--apk", str(apk_path), "--summary", str(custom_rule_path)],
    )

    assert result.exit_code == 0, result.output


def test_missing_rules_directory_is_reported_when_default_rules_are_used(
    tmp_path, monkeypatch
):
    missing_default_rules = tmp_path / "missing-rules"
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"not a real apk")

    monkeypatch.setattr(get_rule_option(), "default", str(missing_default_rules))

    result = CliRunner().invoke(
        cli.entry_point,
        ["--apk", str(apk_path), "--summary"],
    )

    assert result.exit_code == 0, result.output
    assert "Specified rules path not found" in result.output
