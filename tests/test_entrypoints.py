import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EntrypointTests(unittest.TestCase):
    def check_entrypoint(self, invocation, exit_code):
        # Separate interpreters exercise import bootstrapping without leaking
        # patched entrypoints or sys.modules state into the rest of the suite.
        code = (
            "import runpy; import wifi_auto_login.app as app; "
            f"app.main = lambda: {exit_code}; {invocation}"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, exit_code, result.stderr)
        self.assertEqual(result.stderr, "")

    def test_module_entrypoint_propagates_exit_code(self):
        self.check_entrypoint(
            "runpy.run_module('wifi_auto_login.cli', run_name='__main__')", 4
        )

    def test_compatibility_script_propagates_exit_code(self):
        self.check_entrypoint(
            "runpy.run_path('scripts/wifi_portal_login.py', run_name='__main__')", 2
        )


if __name__ == "__main__":
    unittest.main()
