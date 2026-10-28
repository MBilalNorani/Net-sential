"""Minimal runner so tests work without pytest (pytest works too: `pytest -q`)."""
import contextlib, importlib, inspect, io, pathlib, sys, tempfile, traceback
sys.path.insert(0, ".")
mod = importlib.import_module("tests.test_core")
fails = 0
for name, fn in inspect.getmembers(mod, inspect.isfunction):
    if not name.startswith("test_"): continue
    kw = {}
    buf = io.StringIO()
    class Cap:
        def readouterr(self_inner):
            v = buf.getvalue(); buf.seek(0); buf.truncate(); return type("O", (), {"out": v})()
    params = inspect.signature(fn).parameters
    if "tmp_path" in params: kw["tmp_path"] = pathlib.Path(tempfile.mkdtemp())
    if "capsys" in params: kw["capsys"] = Cap()
    try:
        with contextlib.redirect_stdout(buf) if "capsys" in params else contextlib.nullcontext():
            fn(**kw)
        print("PASS", name)
    except Exception:
        fails += 1; print("FAIL", name); traceback.print_exc()
sys.exit(1 if fails else 0)
