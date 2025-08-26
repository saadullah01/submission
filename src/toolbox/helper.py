import os
import subprocess
import json
import csv

LOGS_DIR="/shared"

def remove_tree_from_setup_logs(logs: str) -> str:
    lines = logs.splitlines()
    keep = []
    skip = False
    for line in lines:
        if "## DIRECTORY TREE" in line:
            skip = True
            continue
        if "## IMPORTANT FILES" in line:
            skip = False
        if not skip:
            keep.append(line)
    return "\n".join(keep)

def remove_tree_from_exploit_logs(logs: str) -> str:
    lines = logs.splitlines()
    keep = []
    skip = False
    for line in lines:
        if "## DIRECTORY TREE" in line:
            skip = True
            continue
        if "## ACCESSS TO THE SYSTEM" in line:
            skip = False
        if not skip:
            keep.append(line)
    return "\n".join(keep)

def save_result(cve: str, result: dict):
    if not os.path.isfile(f"{LOGS_DIR}/results.csv"):
        # Create the file and write a header row
        with open(f"{LOGS_DIR}/results.csv", mode="w", newline="", encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["CVE", "SUCCESS", "REASON", "COST", "TIME", "MODEL"])

    with open(f"{LOGS_DIR}/results.csv", mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([cve, result['success'], result['reason'], result['cost'], result['time'], result['model']])

def save_log(cve: str, name: str, log: str):
    os.makedirs(os.path.dirname(f"{LOGS_DIR}/{cve}/logs/"), exist_ok=True)
    with open(f"{LOGS_DIR}/{cve}/logs/{name}.log", "w", encoding='utf-8') as f:
        f.write(log)

def load_log(cve: str, name: str):
    with open(f"{LOGS_DIR}/{cve}/logs/{name}.log", "r", encoding='utf-8') as f:
        return f.read()

def save_response(cve: str, response: str, agent: str, struct: bool = False) -> None:
    """
    Saves the response from the agent to a file
    """
    os.makedirs(f"{LOGS_DIR}/{cve}/conversations/", exist_ok=True)
    LANG = "json" if struct else "txt"
    with open(f"{LOGS_DIR}/{cve}/conversations/{agent}.{LANG}", "w", encoding='utf-8') as f:
        if struct:
            json.dump(response, f, indent=4)
        else:
            f.write(response)

def load_response(cve: str, agent: str, struct: bool = False) -> str:
    """
    Loads the response from the agent from a file
    """
    LANG = "json" if struct else "txt"
    with open(f"{LOGS_DIR}/{cve}/conversations/{agent}.{LANG}", "r", encoding='utf-8') as f:
        if struct:
            return json.load(f)
        return f.read()

def save_ctf_script(cve: str, verifier: str, exploit: str) -> None:
    os.makedirs(f"{LOGS_DIR}/{cve}/scripts/", exist_ok=True)
    with open(f"{LOGS_DIR}/{cve}/scripts/verifier.py", "w", encoding='utf-8') as f:
        f.write(verifier)
    with open(f"{LOGS_DIR}/{cve}/scripts/exploit.py", "w", encoding='utf-8') as f:
        f.write(exploit)

def create_exploit_script(exploit: str) -> None:
    with open(f"simulation_environments/{os.environ['REPO_PATH']}/exploit.py", "w", encoding='utf-8') as f:
        f.write(exploit)

def normalise_ai_message(msg):
    """
    Returns 3 lists:
      texts         - one free-text reason ***per*** tool call (may be '')      
      tool_calls    - list of "name(args_as_pretty_string)"                  
      pending_texts - trailing text *after* the last tool call (used later as final_response)
    """
    texts, tool_calls = [], []
    buffer = []                 # accumulate free text that precedes the next tool call

     # ---------- handle messages whose .content is just a string ----------
    if isinstance(msg.content, str) and msg.content.strip():
        buffer.append(msg.content.strip())

    # ---------- 1a. Anthropic-style content ----------
    if isinstance(msg.content, list):                    # may be list[dict]  *or* list[str]
        for part in msg.content:
            # content from Anthropic is a list of dicts with 'type'
            if isinstance(part, dict) and part.get("type") == "text":
                if part.get("text", "").strip():
                    buffer.append(part["text"].strip())

            elif isinstance(part, dict) and part.get("type") == "tool_use":
                # flush the buffered text as the reason for this call
                texts.append(" ".join(buffer).strip())
                buffer.clear()

                name  = part.get("name", "")
                args  = part.get("input", {})
                tool_calls.append(f"{name}({args})")

            else:                        # list element is a bare string
                if str(part).strip():
                    buffer.append(str(part).strip())

    # ---------- 1b. OpenAI-GPT tool_calls ----------
    for call in msg.additional_kwargs.get("tool_calls", []):
        texts.append(" ".join(buffer).strip()); buffer.clear()
        fn  = call.get("function", {}) or call     # sometimes wrapped in 'function', sometimes not
        name = fn.get("name", call.get("name", ""))
        args = fn.get("arguments", call.get("args", {}))
        tool_calls.append(f"{name}({args})")

    # ---------- 1c. Google function_call ----------
    fc = msg.additional_kwargs.get("function_call")
    if fc:                                           # one call per message
        texts.append(" ".join(buffer).strip()); buffer.clear()
        tool_calls.append(f"{fc.get('name','')}({fc.get('arguments','')})")

    pending_texts = " ".join(buffer).strip()
    return texts, tool_calls, pending_texts

def parse_chat_messages(chat_messages: list, include_human: bool = False) -> str:
    input = ""
    output = []
    tool_texts = []
    tool_calls = []
    tool_messages = []
    final_response = None

    for msg in chat_messages:
        role = type(msg).__name__

        if role == 'HumanMessage' and include_human:
            input = f"{msg.content.strip()}"

        elif role == 'AIMessage':
            t_texts, t_calls, tail_text = normalise_ai_message(msg)
            tool_texts.extend(t_texts)
            tool_calls.extend(t_calls)

            if tail_text:
                final_response = tail_text

        elif role == 'ToolMessage':
            content = msg.content.strip()
            tool_messages.append(f"{content}")
    
    # Handle human messages
    if include_human:
        # output.append(f"# Input\n\"\"\"\n{input}\n\"\"\"\n")
        output.append("###########################\n" \
                      "### HUMAN INPUT SECTION ###\n" \
                      "###########################\n")
        output.append(f"{input}\n")

    output.append(f"{'####' * 15}\n")

    # Start LLM response
    # output.append("# LLM\n\"\"\"")
    output.append("############################\n" \
                  "### LLM RESPONSE SECTION ###\n" \
                  "############################\n")

    # Add tool calls if any
    if tool_calls:
        for ix, (call, message) in enumerate(zip(tool_calls, tool_messages)):
            if ix < len(tool_texts) and tool_texts[ix].strip():
                output.append(f"- TOOL REASON {ix + 1}: \"\"\"{tool_texts[ix]}\"\"\"")
            output.append(f"- TOOL CALL {ix + 1}: \"\"\"{call}\"\"\"")
            output.append(f"- TOOL MESSAGE {ix + 1}: \"\"\"{message}\"\"\"\n")

    # Add final response if present
    if final_response:
        output.append(f"- RESPONSE: \"\"\"{final_response}\"\"\"\n")

    output.append(f"{'####' * 15}")

    return "\n".join(output)
