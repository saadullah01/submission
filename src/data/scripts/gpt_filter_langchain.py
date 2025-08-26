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
def handle_easy_cve(version: str) -> str:
    """
    Processes easy CVE that can be reproduced by an AI agent.
    :param version: The latest version of the software that is vulnerable.
    :return: If task was successful
    """
    global cve
    # print("Easy", version)
    cve['version_data'] = version
    with open(f'./advisory_{year}_easy/'+cve['id']+'.json', 'w') as fp:
        json.dump(cve, fp)
    return "Processed successfully\n"

@tool
def handle_difficult_cve(version: str) -> str:
    """
    Processes difficult CVE that requires human intervention.
    :param version: The latest version of the software that is vulnerable.
    :return: If task was successful
    """
    # print("Difficult", version)
    cve['version_data'] = version
    with open(f'./advisory_{year}_difficult/'+cve['id']+'.json', 'w') as fp:
        json.dump(cve, fp)
    return "Processed successfully\n"

# List of tools
tools = [handle_easy_cve, handle_difficult_cve]

# Prompt template
prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a CVE filter bot. You are helping an AI agent who wants to
                reproduce these CVEs for research. But the agent is only concerned with
                those CVEs that do not require UI interactions and a lot of human intervention as 
                this will be an automated pipeline. Given a CVE advisory description,
                you have to perform the following task: Call 'handle_easy_cve'
                if the CVE can be reproduced easily without help from humans
                (such as UI interactions), otherwise call 'handle_difficult_cve'.
                You are allowed to call only 1 function per CVE, or the program will crash.
                ###
                You might also be provided with an affected version string.
                The output to the called functions should include a 
                vulnerable version WITHOUT inequalities (preferably the highest version number if there are many) that would 
                be your best guess to have vulnerable code (example here could be 1.1 for <1.2).
                If not the version string should be 'cant_compute'. You only need to output
                a single version, multiple are not supported.
                Once you call the function, your run should terminate and must wait for
                the next CVE"""),
    ("user", "{input}"),
    ("placeholder", "{agent_scratchpad}")
])

# Initialize LangChain's OpenAI client
llm = ChatOpenAI(model="gpt-4o-mini")
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

def process_json(data):
    # Invoke the agent with the CVE data
    response = agent_executor.invoke({"input": f"Is it possible to reproduce this CVE without human intervention?\n### {data}"})

# Process each CVE file
for filename in os.listdir(f'./advisory_{year}'):
    with open(f'./advisory_{year}/{filename}') as f:
        cve = json.load(f)
    data = json.dumps(cve["version_data"]) + cve["description"] + cve["security_advisory"]
    process_json(data)
