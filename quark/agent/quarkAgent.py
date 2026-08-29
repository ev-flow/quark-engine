# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

import os
import click
from quark.utils.colors import green, cyan


def __printDependencyMissingMessage() -> None:
    print("Quark Agent requires langchain and its OpenAI integration to work.")
    print(
        (
            "Please use the command 'python3 -m pip install"
            " langchain langchain-core langchain-openai --upgrade'"
            " to install the packages."
        )
    )


def __setOrAskAPIKey(apiKey: str) -> bool:
    if apiKey:
        os.environ["OPENAI_API_KEY"] = apiKey
    elif "OPENAI_API_KEY" not in os.environ:
        try:
            os.environ["OPENAI_API_KEY"] = click.prompt(
                "Please provide the access key of OpenAI API"
            )
        except click.Abort:
            return False

    return True


@click.command()
@click.option(
    "--api-key",
    help="Access key of OpenAI API",
    type=str,
    show_default=False,
    default=None,
)
def entryPoint(api_key: str) -> None:

    try:
        from langchain_openai import ChatOpenAI
        from langchain.agents import create_agent
        from langchain_core.messages import AIMessage, HumanMessage
    except ModuleNotFoundError:
        __printDependencyMissingMessage()
        # langchain is not installed.
        return

    from quark.agent.agentTools import agentTools
    from quark.agent.prompts import SUMMARY_REPORT_FORMAT

    if not __setOrAskAPIKey(api_key):
        # OpenAI API Key is not provided.
        return

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0.8)

    systemPrompt = (
        "You are very powerful assistant, but don't know current events"
        + SUMMARY_REPORT_FORMAT
    )

    agentExecutor = create_agent(
        model=llm, tools=agentTools, system_prompt=systemPrompt
    )

    conversationHistory: list[HumanMessage | AIMessage] = []

    try:
        inputText = input(green("User Input: "))
        while inputText.lower() != "bye":
            if inputText:
                conversationHistory.append(HumanMessage(content=inputText))
                response = agentExecutor.invoke(
                    {"messages": conversationHistory}
                )
                replyText = response["messages"][-1].content
                conversationHistory.append(AIMessage(content=replyText))

                print()
                print(cyan("Agent: "), replyText)
                print()

            inputText = input(green("User Input: "))
    except click.Abort:
        return


if __name__ == "__main__":
    entryPoint()  # pylint: disable=E1120
