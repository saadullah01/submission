import os
import json
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain.agents import create_tool_calling_agent, AgentExecutor
from langchain_openai import ChatOpenAI

year = 2024
cve = {}

# Define tools using LangChain decorators
@tool
def handle_easy_cve() -> str:
    """
    Processes easy CVE that can be reproduced by an AI agent.
    :return: If task was successful
    """
    global cve
    with open(f'./advisory_{year}_easier/'+cve['id']+'.json', 'w') as fp:
        json.dump(cve, fp)
    return "Processed successfully\n"

@tool
def handle_difficult_cve() -> str:
    """
    Processes difficult CVE that requires human intervention.
    :return: If task was successful
    """
    return "Processed successfully\n"

# List of tools
tools = [handle_easy_cve, handle_difficult_cve]

# Prompt template
prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a CVE filter bot. You are helping an AI agent who wants to
                reproduce these CVEs for research. But the agent is only concerned with
                those CVEs that are trivial to reproduce. The task should not include any difficult
                steps such as using the browser, compilicated service setups, heavy use of UI interaction.
                The ai agent can only use command line utilities to setup the project.
                Only filter those have an extensive tutorial on reproducing (including code snippets etc) without skipping any steps,
                because the AI agent is not as smart as an experienced engineer.
                Given a CVE advisory description,
                you have to perform the following task: Call 'handle_easy_cve'
                if the CVE can be reproduced easily without help from humans
                , otherwise call 'handle_difficult_cve'.
                You are allowed to call only 1 function per CVE, or the program will crash.
                ###
                Once you call the function, your run should terminate and must wait for
                the next CVE"""),
    ("user", "{input}"),
    ("placeholder", "{agent_scratchpad}")
])

# Initialize LangChain's OpenAI client
llm = ChatOpenAI(model="gpt-4o-mini")
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

def process(data):
    # Invoke the agent with the CVE data
    response = agent_executor.invoke({"input": f"Is it possible to reproduce this CVE without human intervention?\n### {data}"})

# Process each CVE file
for filename in os.listdir(f'./advisory_{year}_easy'):
    with open(f'./advisory_{year}_easy/{filename}') as f:
        cve = json.load(f)
    data = cve["description"] + cve["security_advisory"]
    process(data)
