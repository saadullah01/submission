import os
from agentlib import Agent
from typing import Optional

class KnowledgeBuilder(Agent[dict, str]):
    __LLM_MODEL__ = 'o4-mini'
    __SYSTEM_PROMPT_TEMPLATE__ = 'knowledgeBuilder/knowledgeBuilder.system.j2'
    __USER_PROMPT_TEMPLATE__ = 'knowledgeBuilder/knowledgeBuilder.user.j2'

    ID: Optional[str]
    DESCRIPTION: Optional[str]
    CWE: Optional[str]
    PROJECT_NAME: Optional[str]
    AFFECTED_VERSION: Optional[str]
    SECURITY_ADVISORY: Optional[str]
    PATCH: Optional[str]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ID = kwargs.get('id')
        self.DESCRIPTION = kwargs.get('description')
        self.CWE = kwargs.get('cwe')
        self.PROJECT_NAME = kwargs.get('project_name')
        self.AFFECTED_VERSION = kwargs.get('affected_version')
        self.SECURITY_ADVISORY = kwargs.get('security_advisory')
        self.PATCH = kwargs.get('patch')
    
    def get_input_vars(self, *args, **kwargs) -> dict:
        vars = super().get_input_vars(*args, **kwargs)
        vars.update(
            ID = self.ID,
            DESCRIPTION = self.DESCRIPTION,
            CWE = self.CWE,
            PROJECT_NAME = self.PROJECT_NAME,
            AFFECTED_VERSION = self.AFFECTED_VERSION,
            SECURITY_ADVISORY = self.SECURITY_ADVISORY,
            PATCH = self.PATCH
        )
        return vars
    
    def get_cost(self, *args, **kw) -> float:
        total_cost = 0
        # We have to sum up all the costs of the LLM used by the agent
        for model_name, token_usage in self.token_usage.items():
            total_cost += token_usage.get_costs(model_name)['total_cost']
        return total_cost
