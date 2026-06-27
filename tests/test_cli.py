import json
from unittest.mock import patch

from click.testing import CliRunner

from quark.cli import entry_point


def _rule_option():
    for param in entry_point.params:
        if param.name == "rule":
            return param
    raise AssertionError("rule option not found")


def _write_rule(path):
    path.write_text(
        json.dumps(
            {
                "crime": "test",
                "permission": [],
                "api": [
                    {
                        "class": "Lfoo/Bar;",
                        "method": "first",
                        "descriptor": "()V",
                    },
                    {
                        "class": "Lfoo/Bar;",
                        "method": "second",
                        "descriptor": "()V",
                    },
                ],
                "score": 1,
                "label": ["test"],
            }
        )
    )


def test_custom_rule_does_not_validate_missing_default_rules(tmp_path, monkeypatch):
    missing_default_rules = tmp_path / "missing-rules"
    custom_rule = tmp_path / "custom_rule.json"
    apk = tmp_path / "sample.apk"
    _write_rule(custom_rule)
    apk.write_text("")
    monkeypatch.setattr(_rule_option(), "default", str(missing_default_rules))

    runner = CliRunner()

    with patch("quark.cli.Quark") as mock_quark:
        data = mock_quark.return_value
        data.quark_analysis.score_sum = 0
        data.quark_analysis.weight_sum = 0
        data.quark_analysis.summary_report_table = ""

        result = runner.invoke(
            entry_point,
            ["-a", str(apk), "-s", str(custom_rule)],
        )

    assert result.exit_code == 0
    mock_quark.assert_called_once()


def test_missing_rules_path_fails_when_rules_are_loaded(tmp_path, monkeypatch):
    missing_rules = tmp_path / "missing-rules"
    apk = tmp_path / "sample.apk"
    apk.write_text("")
    monkeypatch.setattr(_rule_option(), "default", str(missing_rules))

    runner = CliRunner()

    result = runner.invoke(entry_point, ["-a", str(apk), "-s"])

    assert result.exit_code != 0
    assert "Path" in result.output
    assert str(missing_rules) in result.output


def test_existing_rules_directory_is_loaded(tmp_path, monkeypatch):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    _write_rule(rules_dir / "custom_rule.json")
    apk = tmp_path / "sample.apk"
    apk.write_text("")
    monkeypatch.setattr(_rule_option(), "default", str(rules_dir))

    runner = CliRunner()

    with patch("quark.cli.Quark") as mock_quark:
        data = mock_quark.return_value
        data.quark_analysis.score_sum = 0
        data.quark_analysis.weight_sum = 0
        data.quark_analysis.summary_report_table = ""

        result = runner.invoke(entry_point, ["-a", str(apk), "-s"])

    assert result.exit_code == 0
    mock_quark.assert_called_once()
