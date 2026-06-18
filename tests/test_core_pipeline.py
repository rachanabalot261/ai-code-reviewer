import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.orchestrator import analyze

VULN = sorted([f"samples/vulnerable/{f}"
               for f in os.listdir("samples/vulnerable") if f.endswith(".py")])
SAFE = sorted([f"samples/safe/{f}"
               for f in os.listdir("samples/safe") if f.endswith(".py")])

tp=fp=fn=tn=0; times=[]; missed=[]; false_pos=[]

print("\n=== VULNERABLE SAMPLES — all must have findings ===")
for path in VULN:
    with open(path) as f: code = f.read()
    t = time.time()
    r = analyze(code, use_cache=False)
    times.append(time.time() - t)
    found = r.total_findings > 0
    err   = " [API ERROR]" if r.has_error else ""
    print(f"  {'✅ CAUGHT' if found else '❌ MISSED'} {os.path.basename(path):35s} ({r.total_findings} findings){err}")
    if found: tp += 1
    else: fn += 1; missed.append(path)

print("\n=== SAFE SAMPLES — all must have ZERO findings ===")
for path in SAFE:
    with open(path) as f: code = f.read()
    r = analyze(code, use_cache=False)
    found = r.total_findings > 0
    print(f"  {'❌ FALSE POS' if found else '✅ CLEAN'} {os.path.basename(path):35s}")
    if found: fp += 1; false_pos.append(path)
    else: tn += 1

p  = tp/(tp+fp+1e-9)
rc = tp/(tp+fn+1e-9)
f1 = 2*p*rc/(p+rc+1e-9)

print(f"\n{'='*50}")
print(f"  TP={tp}  FP={fp}  FN={fn}  TN={tn}")
print(f"  Precision : {p:.1%}")
print(f"  Recall    : {rc:.1%}")
print(f"  F1        : {f1:.1%}")
print(f"  Avg time  : {sum(times)/len(times):.1f}s per function")
print(f"{'='*50}")

if missed:
    print("\n⚠️  Missed — fix REASONING PROTOCOL in prompts.py for these classes:")
    for m in missed: print(f"   - {os.path.basename(m)}")
if false_pos:
    print("\n⚠️  False positives — tighten FALSE POSITIVE RULE in prompts.py:")
    for fp_path in false_pos: print(f"   - {os.path.basename(fp_path)}")

if tp == 8 and fp == 0:
    print("\n✅ EXIT GATE 1 PASSED — proceed to Step 15.")
else:
    print("\n🛑 EXIT GATE 1 FAILED — fix prompts.py before proceeding.")
