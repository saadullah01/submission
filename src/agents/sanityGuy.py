import re
import os

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional, Any
from langchain_core.agents import AgentFinish

from toolbox.tools import TOOLS

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the report in the following specified format.

```
<report>
<analysis>...</analysis>
<decision>...</decision>
<steps_to_fix>...</steps_to_fix>
</report>
```

Within <analysis></analysis>, replace ... with a detailed analysis of the verifier script based on the criteria mentioned above.
Within <decision></decision>, replace ... with the your decision on whether the verifier is effective or not, ONLY use "yes" or "no".
Within <steps_to_fix></steps_to_fix>, replace ... with the steps to fix the issues in the verifier script (if any), or "none" if the script is valid.
'''

class MyParser(BaseParser):
    MAX_FIX_FORMAT_TRIES = 3

    def get_format_instructions(self) -> str:
        return OUTPUT_DESCRIPTION

    def invoke(self, msg, *args, **kwargs) -> dict:
        # if msg['output'] == 'Agent stopped due to max iterations.':
        #     return msg['output']
        response = msg.content
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
                m = re.search(r'<analysis>(.*?)</analysis>', text, re.DOTALL)
                analysis = m.group(1).strip() if m else self.raise_format_error()
                m = re.search(r'<decision>(.*?)</decision>', text, re.DOTALL)
                decision = m.group(1).strip() if m else self.raise_format_error()
                m = re.search(r'<steps_to_fix>(.*?)</steps_to_fix>', text, re.DOTALL)
                steps_to_fix = m.group(1).strip() if m else self.raise_format_error()

                print(f"🧴 Sanity Guy Response: '''\n{text}\n'''")
                print(f"✅ Successfully parsed the output of Sanity Guy.")
                return dict(
                    analysis = analysis.strip(),
                    decision = decision.strip(),
                    steps_to_fix = steps_to_fix.strip()
                )
            except ValueError:
                text = self.fix_patch_format(text)
                try_itr += 1

class SanityGuy(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = 'o3'
    __SYSTEM_PROMPT_TEMPLATE__ = 'sanityGuy/sanityGuy.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'sanityGuy/sanityGuy.user.j2'
    __OUTPUT_PARSER__ = MyParser

    # from knowledge builder
    CVE_KNOWLEDGE: Optional[str]
    
    # from repo builder
    PROJECT_ACCESS: Optional[str]
    
    # from exploiter
    EXPLOIT: Optional[str]
    POC: Optional[str]
    VERIFIER: Optional[str]
    VALIDATOR_LOGS: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.PROJECT_ACCESS = kwargs.get('project_access')
        self.EXPLOIT = kwargs.get('exploit')
        self.POC = kwargs.get('poc')
        self.VERIFIER = kwargs.get('verifier')
        self.VALIDATOR_LOGS = kwargs.get('validator_logs')

    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            PROJECT_ACCESS = self.PROJECT_ACCESS,
            EXPLOIT = self.EXPLOIT,
            POC = self.POC,
            VERIFIER = self.VERIFIER,
            VALIDATOR_LOGS = self.VALIDATOR_LOGS
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
