import re
import os

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional
from toolbox.tools import TOOLS

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output a verifier for the exploit in the following specified format.

```
<report>
<verifier>...</verifier>
</report>
```
Within <verifier>...</verifier>, replace ... with the python script containing the verifier for the exploit.
'''

class MyParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        response = msg['output']
        if isinstance(response, list):
            response = ' '.join(response)
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
                m = re.search(r'<verifier>(.*?)</verifier>', text, re.DOTALL)
                verifier = m.group(1) if m else self.raise_format_error()

                if verifier.startswith('```'):
                    verifier = verifier.strip()
                    verifier = verifier[verifier.index('\n')+1:]
                    verifier = verifier[:verifier.rindex('\n')]

                print(f'✅ Successfully parsed the output!')
                return dict(
                    verifier = verifier.strip()
                )
            except Exception as e:
                print(f'🤡 Regex Error: {e}')
                print(f'🤡 Trying to fix the format ... Attempt {try_itr}!!')
                text = self.fix_patch_format(text)
                try_itr += 1

class CTFVerifier(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = 'o3'
    __SYSTEM_PROMPT_TEMPLATE__ = 'ctfVerifier/verifier.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'ctfVerifier/verifier.user.j2'
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 60

    # general
    PROJECT_DIR_TREE: Optional[str]

    # from knowledge builder
    CVE_KNOWLEDGE: Optional[str]

    # from pre-reqs builder
    PROJECT_OVERVIEW: Optional[str]

    # from repo builder
    PROJECT_ACCESS: Optional[str]

    # from exploit builder
    EXPLOIT_INFO: Optional[str]
    EXPLOIT_POC: Optional[str]

    # feedback
    FEEDBACK: Optional[bool]
    VALIDATOR_OUTPUT: Optional[dict]

    # TOOL_LOGS = ""
    # CAPTURE_TOOL_OUTPUT = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.PROJECT_OVERVIEW = kwargs.get('project_overview')
        self.PROJECT_DIR_TREE = kwargs.get('project_dir_tree')
        self.REPO_BUILD = kwargs.get('repo_build')
        self.EXPLOIT = kwargs.get('exploit')
        self.FEEDBACK = kwargs.get('feedback')
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            PROJECT_DIR_TREE = self.PROJECT_DIR_TREE,
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            PROJECT_OVERVIEW = self.PROJECT_OVERVIEW,
            PROJECT_ACCESS = self.REPO_BUILD['access'],
            EXPLOIT_INFO = self.EXPLOIT['exploit'],
            EXPLOIT_POC = self.EXPLOIT['poc'],
            FEEDBACK = self.FEEDBACK
        )
        return vars

    def get_available_tools(self):
        return [TOOLS['get_file'], TOOLS['execute_ls_command']]
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost