from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from quark import config
from quark.cli import entry_point


def test_missing_default_rule_path_does_not_block_explicit_rule_file():
    runner = CliRunner()

    with runner.isolated_filesystem():
        apk = Path("sample.apk")
        apk.write_bytes(b"not an apk")
        rule = Path("custom_rule.json")
        rule.write_text("""
            {
                "crime": "test rule",
                "permission": [],
                "api": [
                    {"class": "Landroid/test/A;", "method": "a", "descriptor": "()V"},
                    {"class": "Landroid/test/B;", "method": "b", "descriptor": "()V"}
                ],
                "score": 1,
                "label": ["test"]
            }
            """)
        missing_rule_dir = "missing-default-rules"
        config.DIR_PATH = missing_rule_dir
        for param in entry_point.params:
            if param.name == "rule":
                param.default = missing_rule_dir

        with patch("quark.cli.Quark") as mock_quark:
            quark = mock_quark.return_value
            quark.quark_analysis.score_sum = 0
            quark.quark_analysis.weight_sum = 0
            quark.quark_analysis.summary_report_table = ""
            result = runner.invoke(entry_point, ["-a", str(apk), "-s", str(rule)])

        assert result.exit_code == 0
        assert "Invalid value for '-r' / '--rule'" not in result.output
        mock_quark.assert_called_once()
