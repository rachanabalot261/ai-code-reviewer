import sys, os
sys.path.insert(0, os.getcwd())
from src.formal.verifier import verify

result = verify('def add_one(x: int) -> int:\n    return x + 1')
print(result)
