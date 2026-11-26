"""Comprehensive negative-control test suite for complete offline air-gap enforcement.

Verifies:
1. Cloud AI functions (query_cloud_ai, generate_image_cloud, run_model_fusion,
   test_provider_connection) immediately fail closed when PAI_INTERNET_ENABLED=0.
2. Web knowledge functions (search_web, fetch_live_weather, geocode_location,
   get_live_grounding_context, fetch_url_text) immediately fail closed when PAI_INTERNET_ENABLED=0.
3. Fact checking engine returns empty claims immediately when PAI_INTERNET_ENABLED=0.
4. Bridge server settings toggle disables fact-checking and switches cloud models to local
   models when internet is toggled off.
5. Factcheck enable requests are rejected with HTTP 400 while offline.
6. /api/factcheck and update checks/downloads fail closed without network calls while offline.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

RESEARCH_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = RESEARCH_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(RESEARCH_DIR) not in sys.path:
    sys.path.insert(0, str(RESEARCH_DIR))

from research.cloud_ai import (
    generate_image_cloud,
    query_cloud_ai,
    run_model_fusion,
    test_provider_connection,
)
from research.fact_checker import verify_text_claims
from research.internet_service import (
    fetch_live_weather,
    fetch_url_text,
    geocode_location,
    get_live_grounding_context,
    is_internet_enabled,
    search_web,
    set_internet_enabled,
)
import desktop.bridge_server as bridge_server
from desktop.bridge_server import (
    PAIBridgeHandler,
    PAI_BRIDGE_TOKEN,
    _update_manager,
    get_current_model,
    set_current_model,
)


class TestOfflineAirGapDirect(unittest.TestCase):
    """Direct negative-control unit tests for all network-bound research modules."""

    def setUp(self):
        self._orig_env = os.environ.get("PAI_INTERNET_ENABLED")
        set_internet_enabled(False)

    def tearDown(self):
        if self._orig_env is not None:
            os.environ["PAI_INTERNET_ENABLED"] = self._orig_env
        else:
            set_internet_enabled(True)

    def test_internet_enabled_flag_reflects_disabled_state(self):
        self.assertFalse(is_internet_enabled())

    def test_query_cloud_ai_fails_closed_when_offline(self):
        ok, res = query_cloud_ai("What is the capital of France?", model="gemini-2.0-flash")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", res)

    def test_generate_image_cloud_fails_closed_when_offline(self):
        ok, res, fpath, fname = generate_image_cloud("A blue ocean wave", model="imagen-3.0-generate-002")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", res)
        self.assertIsNone(fpath)
        self.assertIsNone(fname)

    def test_run_model_fusion_fails_closed_when_offline(self):
        ok, res = run_model_fusion("Explain quantum physics")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", res)

    def test_test_provider_connection_fails_closed_when_offline(self):
        ok, msg, latency = test_provider_connection("gemini")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", msg)
        self.assertEqual(latency, 0.0)

    def test_search_web_fails_closed_when_offline(self):
        ok, msg, results = search_web("Latest technology news")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", msg)
        self.assertEqual(results, [])

    def test_fetch_live_weather_fails_closed_when_offline(self):
        ok, msg, data = fetch_live_weather("Colombo")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", msg)
        self.assertEqual(data, {})

    def test_geocode_location_fails_closed_when_offline(self):
        res = geocode_location("Tokyo")
        self.assertIsNone(res)

    def test_get_live_grounding_context_fails_closed_when_offline(self):
        has_ground, ctx, cites = get_live_grounding_context("Who won the 2024 election?")
        self.assertFalse(has_ground)
        self.assertEqual(ctx, "")
        self.assertEqual(cites, [])

    def test_fetch_url_text_fails_closed_when_offline(self):
        ok, msg = fetch_url_text("https://example.com/article")
        self.assertFalse(ok)
        self.assertIn("Internet access is disabled", msg)

    def test_verify_text_claims_returns_empty_when_offline(self):
        claims = verify_text_claims("The earth revolves around the sun in 365 days.")
        self.assertEqual(claims, [])


class TestBridgeServerOfflineAirGap(unittest.TestCase):
    """End-to-end HTTP tests against local bridge server verifying offline enforcement."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), PAIBridgeHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._orig_env = os.environ.get("PAI_INTERNET_ENABLED")
        self._orig_model = get_current_model()
        set_internet_enabled(True)

    def tearDown(self):
        if self._orig_env is not None:
            os.environ["PAI_INTERNET_ENABLED"] = self._orig_env
        else:
            set_internet_enabled(True)
        set_current_model(self._orig_model)

    def _post(self, path: str, payload: dict) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-PAI-Token": PAI_BRIDGE_TOKEN,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def _get(self, path: str) -> tuple[int, dict]:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"X-PAI-Token": PAI_BRIDGE_TOKEN},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_toggle_internet_off_disables_factcheck_and_switches_cloud_model(self):
        set_current_model("gemini-2.0-flash")
        status, body = self._post("/api/settings/toggle", {"feature": "internet", "value": False})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("success"))
        self.assertFalse(body.get("internet_enabled"))
        self.assertFalse(body.get("factcheck_enabled"))
        self.assertTrue(body.get("switched_to_local"))
        self.assertNotEqual(body.get("active_model"), "gemini-2.0-flash")

    def test_factcheck_enable_rejected_when_offline(self):
        set_internet_enabled(False)
        status, body = self._post("/api/settings/toggle", {"feature": "factcheck", "value": True})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertIn("disabled", body.get("error", "").lower())

    def test_factcheck_route_fails_closed_when_offline(self):
        set_internet_enabled(False)
        status, body = self._post("/api/factcheck", {"text": "Water boils at 100 degrees Celsius."})
        self.assertEqual(status, 200)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("claims"), [])
        self.assertIn("requires internet access", body.get("error", ""))

    def test_update_manager_offline_airgap(self):
        set_internet_enabled(False)
        check_res = _update_manager.check_for_updates()
        self.assertFalse(check_res.get("success"))
        self.assertTrue(check_res.get("offline"))
        self.assertIn("disabled", check_res.get("error", "").lower())

        dl_res = _update_manager.start_download(download_url="https://example.com/file.zip")
        self.assertFalse(dl_res.get("success"))
        self.assertEqual(dl_res.get("status"), "error")
        self.assertIn("disabled", dl_res.get("error", "").lower())

    def test_cloud_test_connection_route_offline(self):
        set_internet_enabled(False)
        status, body = self._post("/api/cloud/test_connection", {"provider": "gemini"})
        self.assertEqual(status, 200)
        self.assertFalse(body.get("success"))
        self.assertIn("disabled", body.get("message", "").lower())

    def test_search_api_route_offline(self):
        set_internet_enabled(False)
        status, body = self._get("/api/search?q=Python+programming")
        self.assertEqual(status, 200)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("results"), [])
        self.assertIn("disabled", body.get("message", "").lower())

    def test_weather_api_route_offline(self):
        set_internet_enabled(False)
        status, body = self._get("/api/weather?city=London")
        self.assertEqual(status, 200)
        self.assertFalse(body.get("success"))
        self.assertEqual(body.get("data"), {})
        self.assertIn("disabled", body.get("message", "").lower())

    def test_image_generate_api_route_offline(self):
        set_internet_enabled(False)
        status, body = self._post("/api/image/generate", {"prompt": "A sunset on a lake"})
        self.assertEqual(status, 400)
        self.assertFalse(body.get("success"))
        self.assertIn("disabled", body.get("error", "").lower())


if __name__ == "__main__":
    unittest.main()
