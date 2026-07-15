import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage


@pytest.fixture
def quarkAgentWebModule():
    sys.modules.pop("quark.agent.quarkAgentWeb", None)

    with patch("langchain_openai.ChatOpenAI"), patch(
        "langchain.agents.create_agent"
    ) as mockCreateAgent:
        mockAgentExecutor = MagicMock()
        mockCreateAgent.return_value = mockAgentExecutor
        module = importlib.import_module("quark.agent.quarkAgentWeb")
        yield module, mockAgentExecutor

    sys.modules.pop("quark.agent.quarkAgentWeb", None)


def testGetResponseReturnsAgentReply(quarkAgentWebModule):
    module, mockAgentExecutor = quarkAgentWebModule
    mockAgentExecutor.invoke.return_value = {
        "messages": [AIMessage(content="Hello from agent")]
    }

    client = module.app.test_client()
    response = client.get("/get_response", query_string={"message": "hi"})

    assert response.status_code == 200
    assert response.get_json()["plain_text"] == "Hello from agent"

    mockAgentExecutor.invoke.assert_called_once()
    # conversation_history is the same list object passed to invoke() and
    # mutated afterwards, so check membership rather than indexing it
    # after the fact.
    assert HumanMessage(content="hi") in module.conversation_history
    assert AIMessage(content="Hello from agent") in module.conversation_history
    assert module.conversation_history[-1] == "Hello from agent"


def testGetResponseParsesCodeBlocks(quarkAgentWebModule):
    module, mockAgentExecutor = quarkAgentWebModule
    reply = (
        "Here is data:\n"
        '```{"key": "value"}```\n'
        "and a snippet:\n"
        "```not json at all```"
    )
    mockAgentExecutor.invoke.return_value = {
        "messages": [AIMessage(content=reply)]
    }

    client = module.app.test_client()
    response = client.get("/get_response", query_string={"message": "hi"})
    data = response.get_json()

    assert response.status_code == 200
    # The valid JSON block is parsed; the non-JSON block hits the
    # JSONDecodeError branch and is skipped.
    assert data["json_blocks"] == [{"key": "value"}]
    assert len(data["code_blocks"]) == 2
    # Fenced code is stripped out of the plain-text reply.
    assert "data:" in data["plain_text"]
    assert "```" not in data["plain_text"]
