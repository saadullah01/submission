import os
from openai import OpenAI
from pydantic import BaseModel

def ask_structured_llm(sys: str = None, examples: list[str, str] = None, prompt: str = None, model: str = None, response_model: BaseModel = None):
    # Create a list of messages
    msgs = []
    if sys:
        msgs.append({"role": "system", "content": sys})
    if examples:
        for ex in examples:
            msgs.append({"role": "user", "content": ex[0]})
            msgs.append({"role": "assistant", "content": ex[1]})
    if prompt:
        msgs.append({"role": "user", "content": prompt})
    else:
        raise ValueError("🤡 Prompt is required!!")
    
    # Check if the model is valid
    if not model:
        raise ValueError("🤡 Model is required!!")
    
    # Check if the response model is valid
    if isinstance(response_model, BaseModel):
        raise ValueError("🤡 Response model is required in BaseModel format!!")
    
    # Create the request
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    completion = client.beta.chat.completions.parse(
        model=model,
        messages=msgs,
        response_format=response_model,
    )
    res = completion.choices[0].message.parsed

    return res