
import os
import re
import json

from flask import Flask, render_template, request

from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from langchain_core.messages import AIMessage, HumanMessage
from quark.agent.agentTools import agentTools
from quark.agent.prompts import PREPROMPT

app = Flask(__name__)

os.environ["OPENAI_API_KEY"] = ''

conversation_history = []


llm = ChatOpenAI(model="gpt-4o", temperature=0.2)

systemPrompt = (
    "You are very powerful assistant, but don't know current events"
    + PREPROMPT
)

agent_executor = create_agent(
    model=llm, tools=agentTools, system_prompt=systemPrompt
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/get_response")
def get_response():
    message = request.args.get("message")
    conversation_history.append(message)
    conversation_history.append(HumanMessage(content=message))

    response = agent_executor.invoke({"messages": conversation_history})
    replyText = response["messages"][-1].content
    conversation_history.append(AIMessage(content=replyText))

    full_response = replyText
    conversation_history.append(full_response)

    code_blocks = re.findall(r'```(.*?)```', full_response, re.DOTALL)
    plain_text = re.sub(r'```.*?```', '', full_response,
                        flags=re.DOTALL).strip()

    json_blocks = []
    for code in code_blocks:
        try:
            parsed_json = json.loads(code.strip())
            json_blocks.append(parsed_json)
        except json.JSONDecodeError:
            continue

    result = {
        "plain_text": plain_text,
        "code_blocks": code_blocks,
        "json_blocks": json_blocks
    }

    return result


if __name__ == "__main__":
    app.run()
