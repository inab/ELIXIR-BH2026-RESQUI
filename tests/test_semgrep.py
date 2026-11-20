import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from resqui.core import Context
from resqui.plugins.semgrep import Semgrep


class TestSemgrepPlugin(unittest.TestCase):

    def _run(self, report, commit_hash="main"):
        plugin = Semgrep.__new__(Semgrep)
        plugin.context = Context(github_token="token")
        plugin._cache = {}

        with tempfile.TemporaryDirectory() as tmp:
            def fake_executor_run(command, run_args=None):
                with open(os.path.join(tmp, "report.json"), "w") as f:
                    json.dump(report, f)
                return SimpleNamespace(
                    returncode=0, args=command, stdout="", stderr=""
                )

            plugin.executor = SimpleNamespace(run=fake_executor_run)

            with patch("resqui.plugins.semgrep.create_workspace") as mock_ws:
                mock_ws.return_value.__enter__ = lambda s: s
                mock_ws.return_value.__exit__ = MagicMock(return_value=False)
                mock_ws.return_value.local_path = tmp
                mock_ws.return_value.container_path = lambda p: "/semgrep"
                mock_ws.return_value.docker_mount_args = lambda p: []

                with patch("resqui.plugins.semgrep.subprocess.run") as mock_run:
                    mock_run.return_value = SimpleNamespace(stdout="", stderr="")
                    return plugin.no_critical_vulnerability(
                        "https://github.com/example/repo", commit_hash
                    )

    def test_no_critical_vulnerabilities(self):
        """Zero CRITICAL findings pass: raw_value 0, threshold 0."""
        result = self._run({"results": []})
        self.assertTrue(result.success)
        self.assertEqual(result.output, "true")
        self.assertEqual(result.raw_value, "0")
        self.assertEqual(result.threshold, "0")

    def test_critical_vulnerability_found(self):
        """One CRITICAL finding fails: raw_value 1, threshold 0."""
        result = self._run({"results": [
            {
                "check_id": "python.lang.security.audit.test",
                "path": "example.py",
                "start": {"line": 7},
                "extra": {"severity": "CRITICAL", "message": "critical issue"},
            }
        ]})
        self.assertFalse(result.success)
        self.assertEqual(result.output, "false")
        self.assertEqual(result.raw_value, "1")
        self.assertEqual(result.threshold, "0")
        self.assertIn("critical issue", result.evidence)