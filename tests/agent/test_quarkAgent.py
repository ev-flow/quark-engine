from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from langchain_core.messages import AIMessage

from quark.agent.quarkAgent import entryPoint
from tests.agent.conftest import reload


def testImportQuarkAgentWithoutLangChain(missingLangchain):
    reload("quark.agent.agentTools")


def testEntryPointWithoutLangChain(missingLangchain):
    runner = CliRunner()
    result = runner.invoke(entryPoint)

    assert result.output
    assert not result.exception


def testEntryPointWithAPIKeyInEnv():
    runner = CliRunner()
    result = runner.invoke(
        entryPoint,
        input="bye\n",
        env={"OPENAI_API_KEY": "API-key-for-unit-tests"},
    )

    assert "User Input: " in result.output
    assert not result.exception


def testEntryPointSendsMessageAndPrintsReply():
    mockAgentExecutor = MagicMock()
    mockAgentExecutor.invoke.return_value = {
        "messages": [AIMessage(content="Hello from agent")]
    }

    runner = CliRunner()
    with patch(
        "langchain.agents.create_agent", return_value=mockAgentExecutor
    ):
        result = runner.invoke(
            entryPoint,
            input="hi\nbye\n",
            env={"OPENAI_API_KEY": "API-key-for-unit-tests"},
        )

    assert "Hello from agent" in result.output
    assert not result.exception
    mockAgentExecutor.invoke.assert_called_once()
