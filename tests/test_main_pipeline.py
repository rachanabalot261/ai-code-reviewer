import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.main import analyze_file

VULN = sorted([f"samples/vulnerable/{f}" for f in os.listdir("samples/vulnerable") if f.endswith(".py")])
SAFE = sorted([f"samples/safe/{f}" for f in os.listdir("samples/safe") if f.endswith(".py")])

tp = fp = fn = tn = 0
for path in VULN:
    r = analyze_file(path, run_z3=False)
    if r['total_findings'] > 0: tp += 1
    else: fn += 1

for path in SAFE:
    r = analyze_file(path, run_z3=False)
    if r['total_findings'] > 0: fp += 1
    else: tn += 1

print(f"\n{'='*50}")
print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
print(f"{'='*50}")
