from dotenv import load_dotenv
load_dotenv()
import os, json, sys
sys.path.insert(0, os.getcwd())

from openai import OpenAI
from src.models import Z3PropertyJSON
from src.prompts import Z3_PROPERTY_SYSTEM, Z3_PROPERTY_USER

client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])
code = 'def add_one(x: int) -> int:\n    return x + 1'

response = client.chat.completions.create(
    model='gpt-5.4-mini',
    messages=[
        {'role': 'system', 'content': Z3_PROPERTY_SYSTEM},
        {'role': 'user', 'content': Z3_PROPERTY_USER.format(code=code)},
    ],
)
raw = response.choices[0].message.content.strip()
if raw.startswith("```"):
    raw = "\n".join(raw.split("\n")[1:-1])

print("RAW LLM OUTPUT:")
print(raw)

prop = Z3PropertyJSON.model_validate(json.loads(raw))
print("\nPARSED:", prop)

from src.formal.verifier import _to_z3
script = _to_z3(prop)
print("\nGENERATED Z3 SCRIPT:")
print(script)

import subprocess, tempfile
with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
    f.write(script)
    sp = f.name

p = subprocess.run(['python', sp], capture_output=True, text=True, timeout=15)
print("\nSTDOUT:", p.stdout)
print("STDERR:", p.stderr)