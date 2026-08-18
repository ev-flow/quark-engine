import sys
import pytest

from unittest.mock import patch

from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject
from tests.agent.conftest import reload

import quark.agent.agentTools as agentTools


@pytest.fixture(scope="session")
def quarkObject(SAMPLE_PATH_14d9f):
    rulePath = "quark/rules/sendLocation_SMS.json"
    rule = RuleObject(rulePath)
    quark = Quark(SAMPLE_PATH_14d9f)
    quark.run(rule)
    quark.show_summary_report(rule)

    return quark


def testImportAgentToolsWithoutLangChain():
    reload("quark.agent.agentTools")


def testListDirectory():
    directory = "tests/agent"

    result = agentTools.listDirectory.func(directory)

    assert "test_agentTools.py" in result


def testInitRuleObject():
    rulePath = "quark/rules/sendLocation_SMS.json"

    agentTools.initRuleObject.func(rulePath)

    assert isinstance(agentTools.rule_checker, list)
    assert isinstance(agentTools.rule_checker[0], RuleObject)


def testInitQuarkObject(SAMPLE_PATH_14d9f):
    agentTools.initQuarkObject.func(SAMPLE_PATH_14d9f)

    assert isinstance(agentTools.quark, Quark)


def testRunQuarkAnalysisForSummaryReport(SAMPLE_PATH_14d9f):
    rulePath = "quark/rules/sendLocation_SMS.json"

    with patch("quark.core.quark.Quark.run") as mockedRun:
        with patch(
            "quark.core.quark.Quark.show_summary_report"
        ) as mockedShowSummaryReport:

            agentTools.initRuleObject.func(rulePath)
            agentTools.initQuarkObject.func(SAMPLE_PATH_14d9f)
            agentTools.runQuarkAnalysisForSummaryReport.func()

            assert mockedRun.assert_called_once
            assert mockedShowSummaryReport.assert_called_once


def testCalculateTotalScore():
    scores = [0, 0.5, 1]
    weights = [1, 0.5, 0]

    result = agentTools.calculateTotalScore.func(scores, weights)

    assert result == 0.25


def testGetSummaryReportTable(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getSummaryReportTable.func()

    assert "Send Location via SMS" in result


def testGetAnalysisResultRisk(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getAnalysisResultRisk.func()

    assert "High Risk" in result


def testGetAnalysisResultScore(quarkObject):
    agentTools.quark = quarkObject

    result = agentTools.getAnalysisResultScore.func()

    assert result == 4


@pytest.mark.parametrize(
    "colorizeFunction, expectedColorCode",
    [
        (agentTools.colorizeInYellow, 33),
        (agentTools.colorizeInCyan, 36),
        (agentTools.colorizeInGreen, 92),
        (agentTools.colorizeInRed, 91),
    ],
)
def testColorizeInColor(colorizeFunction, expectedColorCode):
    text = "Text"

    result = colorizeFunction.func(text)

    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        assert result == text
    else:
        assert f"\x1b[{expectedColorCode}m" in result
