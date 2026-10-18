"""Makes research/ importable when tests run via `python -m unittest discover -s tests`."""
import atexit
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolate all tests from the persistent default shadow log
if "PAI_SHADOW_LOG" not in os.environ:
    _test_log = os.path.join(tempfile.gettempdir(), f"pai_test_shadow_{os.getpid()}.jsonl")
    os.environ["PAI_SHADOW_LOG"] = _test_log

    def _cleanup_test_shadow_log():
        try:
            if os.path.exists(_test_log):
                os.remove(_test_log)
        except OSError:
            pass

    atexit.register(_cleanup_test_shadow_log)

if "PAI_TELEMETRY_SOURCE" not in os.environ:
    os.environ["PAI_TELEMETRY_SOURCE"] = "test"
