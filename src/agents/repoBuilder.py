import re
import os

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any
from langchain_core.agents import AgentFinish

from toolbox.tools import TOOLS

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the project build information in the following specified format.

```
<report>
<success>...</success>
<access>...</access>
</report>
```

Within <success></success>, replace ... with the information if the setup is working or not, ONLY use "yes" or "no".
Within <access></access>, replace ... with the information on how the another agent can interact with or access the software.
'''

class MyParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict | str:
        response = msg['output']
        if isinstance(response, list):
            response = ' '.join(response)
        if response == 'Agent stopped due to max iterations.':
            return response
        return self.parse(response)

    def fix_patch_format(self, text: str) -> str:
        fix_llm = LLMFunction.create(
            'Fix the format of the current report according to the format instructions.\n\n# CURRENT REPORT\n{{ info.current_report }}\n\n# OUTPUT FORMAT\n{{ info.output_format }}',
            model='gpt-4o-mini',
            temperature=0.0
        )
        fixed_text = fix_llm(
            info = dict(
                current_report = text,
                output_format = self.get_format_instructions()
            )
        )
        return fixed_text

    def raise_format_error(self) -> None:
        raise ValueError(f'🤡 Output format is not correct!!')

    def parse(self, text: str) -> dict:
        try_itr = 1
        while try_itr <= self.MAX_FIX_FORMAT_TRIES:
            try:
                m = re.search(r'<success>(.*?)</success>', text, re.DOTALL)
                success = m.group(1).strip() if m else self.raise_format_error()
                m = re.search(r'<access>(.*?)</access>', text, re.DOTALL)
                access = m.group(1) if m else self.raise_format_error()
                return dict(
                    success = success.strip(),
                    access = access.strip()
                )
            except ValueError:
                text = self.fix_patch_format(text)
                try_itr += 1

class RepoBuilder(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = 'o4-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'repoBuilder/repoBuilder.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'repoBuilder/repoBuilder.user.j2'
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 60

    # general
    PROJECT_DIR_TREE: Optional[str]

    # from knowledge builder
    CVE_KNOWLEDGE: Optional[str]

    # from pre-req builder
    PROJECT_OVERVIEW: Optional[str]
    PROJECT_FILES: Optional[str]
    PROJECT_SERVICES: Optional[str]
    PROEJCT_OUTPUT: Optional[str]
    PROJECT_VERIFIER: Optional[str]

    # feedback
    FEEDBACK: Optional[str]
    ERROR: Optional[str]
    CRITIC_FEEDBACK: Optional[str]

    # TOOL_LOGS = ""
    # CAPTURE_TOOL_OUTPUT = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PROJECT_DIR_TREE = kwargs.get('project_dir_tree')
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.BUILD_PRE_REQS = kwargs.get('build_pre_reqs')
        self.FEEDBACK = kwargs.get('feedback')
        self.CRITIC_FEEDBACK = kwargs.get('critic_feedback')

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            PROJECT_DIR_TREE = self.PROJECT_DIR_TREE,
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            PROJECT_OVERVIEW = self.BUILD_PRE_REQS['overview'],
            PROJECT_FILES = self.BUILD_PRE_REQS['files'],
            PROJECT_SERVICES = self.BUILD_PRE_REQS['services'],
            PROJECT_OUTPUT = self.BUILD_PRE_REQS['output'],
            FEEDBACK = self.FEEDBACK,
            ERROR = None,
            CRITIC_FEEDBACK = self.CRITIC_FEEDBACK
        )
        return vars

    def get_available_tools(self):
        return TOOLS.values()
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
