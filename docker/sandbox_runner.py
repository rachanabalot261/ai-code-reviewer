import sys
import json
import importlib.util
import traceback

TARGET_PATH = "/sandbox/target.py"


def main():
    input_value = sys.argv[1] if len(sys.argv) > 1 else ""

    spec = importlib.util.spec_from_file_location("target", TARGET_PATH)
    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        print(json.dumps({"output": "", "exception": f"module load failed: {e}"}))
        return

    funcs = [
        getattr(module, name) for name in dir(module)
        if callable(getattr(module, name))
        and not name.startswith("_")
        and getattr(getattr(module, name), "__module__", None) == "target"
    ]

    if not funcs:
        print(json.dumps({"output": "", "exception": "no callable function found in target"}))
        return

    target_fn = funcs[0]

    try:
        result = target_fn(input_value)
        print(json.dumps({"output": str(result)[:2000], "exception": None}))
    except Exception:
        print(json.dumps({"output": "", "exception": traceback.format_exc()[-2000:]}))


if __name__ == "__main__":
    main()
