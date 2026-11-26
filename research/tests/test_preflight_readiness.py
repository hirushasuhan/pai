"""Unit tests for Preflight check and Ollama readiness."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from desktop.bridge_server import (
    ensure_ollama_server,
    get_system_preflight,
)


class TestPreflightAndReadiness(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_ensure_ollama_server_online(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        self.assertTrue(ensure_ollama_server())

    @patch("desktop.bridge_server.ensure_ollama_server")
    def test_get_system_preflight_format(self, mock_ensure):
        mock_ensure.return_value = True
        data = get_system_preflight()
        self.assertTrue(data.get("success"))
        self.assertIn("ollama", data)
        self.assertIn("python", data)
        self.assertIn("models", data)
        self.assertIn("hardware", data)
        self.assertTrue(data["ollama"]["running"])


if __name__ == "__main__":
    unittest.main()
