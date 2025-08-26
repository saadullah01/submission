import re
import os

from agentlib import AgentWithHistory, LLMFunction
from agentlib.lib.common.parsers import BaseParser
from typing import Optional
from toolbox.tools import TOOLS

OUTPUT_DESCRIPTION = '''
After completing the analysis, you MUST output the pre-requisites in the following specified format.

```
<report>
<overview>...</overview>
<files>...</files>
<services>...</services>
<output>...</output>
</report>
```

Within <overview></overview>, replace ... with the overview.
Within <files></files>, replace ... with the files.
Within <services></services>, replace ... with the services.
Within <output></output>, replace ... with the final output.
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
                m = re.search(r'<overview>(.*?)</overview>', text, re.DOTALL)
                overview = m.group(1) if m else self.raise_format_error()
                m = re.search(r'<files>(.*?)</files>', text, re.DOTALL)
                files = m.group(1) if m else self.raise_format_error()
                m = re.search(r'<services>(.*?)</services>', text, re.DOTALL)
                services = m.group(1) if m else self.raise_format_error()
                m = re.search(r'<output>(.*?)</output>', text, re.DOTALL)
                output = m.group(1) if m else self.raise_format_error()

                print(f'✅ Successfully parsed the output!')
                return dict(
                    overview = overview.strip(),
                    files = files.strip(),
                    services = services.strip(),
                    output = output.strip()
                )
            except Exception as e:
                print(f'🤡 Regex Error: {e}')
                print(f'🤡 Trying to fix the format ... Attempt {try_itr}!!')
                text = self.fix_patch_format(text)
                try_itr += 1

class PreReqBuilder(AgentWithHistory[dict, str]):
    __LLM_MODEL__ = 'o4-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'preReqBuilder/preReqBuilder.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'preReqBuilder/preReqBuilder.user.j2'
    __OUTPUT_PARSER__ = MyParser
    __MAX_TOOL_ITERATIONS__ = 60

    CVE_KNOWLEDGE: Optional[str]
    PROJECT_DIR_TREE: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.CVE_KNOWLEDGE = kwargs.get('cve_knowledge')
        self.PROJECT_DIR_TREE = kwargs.get('project_dir_tree')
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            CVE_KNOWLEDGE = self.CVE_KNOWLEDGE,
            PROJECT_DIR_TREE = self.PROJECT_DIR_TREE
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