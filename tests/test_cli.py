from types import SimpleNamespace
from unittest.mock import Mock, patch

from click.testing import CliRunner

from quark import cli


def test_summary_rule_file_does_not_validate_default_rule_path(tmp_path):
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"")
    rule_path = tmp_path / "custom_rule.json"
    rule_path.write_text("{}", encoding="utf-8")
    missing_default_rules = tmp_path / "missing-rules"

    rule_param = next(
        param for param in cli.entry_point.params if param.name == "rule"
    )
    previous_default = rule_param.default
    rule_param.default = str(missing_default_rules)

    seen_rule_paths = []

    def fake_update_rule_buffer(rule_buffer_list, rule_path_list):
        seen_rule_paths.extend(rule_path_list)
        rule_buffer_list.append(SimpleNamespace(label=[]))

    quark = Mock()
    quark.quark_analysis = SimpleNamespace(
        score_sum=0,
        weight_sum=1,
        summary_report_table="",
    )

    try:
        with (
            patch("quark.cli.Quark", return_value=quark),
            patch(
                "quark.cli.update_rule_buffer",
                side_effect=fake_update_rule_buffer,
            ),
            patch("quark.cli.Weight") as weight,
        ):
            weight.return_value.calculate.return_value = 0
            result = CliRunner().invoke(
                cli.entry_point,
                ["-a", str(apk_path), "-s", str(rule_path)],
            )
    finally:
        rule_param.default = previous_default

    assert result.exit_code == 0, result.output
    assert seen_rule_paths == [str(rule_path)]
