"""Unit Tests for Enhanced Cloud AI Subsystem, 4D Quota Ledger, and Fallback Engine."""

import json
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
RESEARCH_DIR = os.path.dirname(TEST_DIR)
if RESEARCH_DIR not in sys.path:
    sys.path.insert(0, RESEARCH_DIR)

from quota_engine import QuotaLedger
import cloud_ai


class TestEnhancedCloudAI(unittest.TestCase):
    def setUp(self):
        # Reset singleton ledger with clean in-memory ledger for test isolation
        QuotaLedger._instance = QuotaLedger(persistent=False)
        self.ledger = QuotaLedger._instance

    def test_quota_ledger_sliding_window_rpm(self):
        """Verify that RPM window respects cap and sliding window expiry."""
        prov = "test_prov"
        key = "test_key_123"

        # Initially available
        avail, reason = self.ledger.is_available(prov, key, rpm_cap=2, rpd_cap=100)
        self.assertTrue(avail)

        # Acquire and release lease 1
        l1 = self.ledger.acquire_lease(prov, key, estimated_tokens=100)
        self.ledger.release_lease(l1, success=True, status_code=200)

        # 1 request in minute, cap is 2 -> still available
        avail, reason = self.ledger.is_available(prov, key, rpm_cap=2, rpd_cap=100)
        self.assertTrue(avail)

        # Acquire and release lease 2
        l2 = self.ledger.acquire_lease(prov, key, estimated_tokens=100)
        self.ledger.release_lease(l2, success=True, status_code=200)

        # 2 requests in minute, cap is 2 -> now throttled
        avail, reason = self.ledger.is_available(prov, key, rpm_cap=2, rpd_cap=100)
        self.assertFalse(avail)
        self.assertIn("RPM cap reached", reason)

    def test_in_flight_leases_block_concurrency_race(self):
        """In-flight leases must count toward RPM while requests are in flight."""
        prov = "race_prov"
        key = "key_abc"

        avail, _ = self.ledger.is_available(prov, key, rpm_cap=1)
        self.assertTrue(avail)

        # Acquire lease (request is now in flight)
        l1 = self.ledger.acquire_lease(prov, key)

        # Second caller should be blocked immediately due to active lease
        avail, reason = self.ledger.is_available(prov, key, rpm_cap=1)
        self.assertFalse(avail)
        self.assertIn("RPM cap reached", reason)

        # Release lease
        self.ledger.release_lease(l1, success=True)

    def test_cooldown_ladder_escalation(self):
        """HTTP 429 should place key in escalating cooldown ladder."""
        prov = "cooldown_prov"
        key = "fail_key"

        # Initially 0s cooldown
        self.assertEqual(self.ledger.get_cooldown_remaining(prov, key), 0.0)

        # First 429 -> Level 0 ladder (30s)
        dur1 = self.ledger.record_failure(prov, key, status_code=429)
        self.assertEqual(dur1, 30.0)
        self.assertGreater(self.ledger.get_cooldown_remaining(prov, key), 25.0)

        # Second 429 -> Level 1 ladder (60s)
        dur2 = self.ledger.record_failure(prov, key, status_code=429)
        self.assertEqual(dur2, 60.0)

        # Third 429 -> Level 2 ladder (300s)
        dur3 = self.ledger.record_failure(prov, key, status_code=429)
        self.assertEqual(dur3, 300.0)

    def test_multi_key_pooling_and_rotation(self):
        """Verify adding, removing, and pooling multiple keys per provider."""
        test_prov = "groq_test"
        k1 = "gsk_key_one"
        k2 = "gsk_key_two"

        with patch.object(cloud_ai, "get_cloud_credentials_path") as mock_path:
            # Test in-memory config dict
            mem_cfg = {"keys": {}}
            with patch.object(cloud_ai, "load_cloud_config", return_value=mem_cfg), \
                 patch.object(cloud_ai, "save_cloud_config"):
                
                # Add first key
                ok1 = cloud_ai.add_provider_key(test_prov, k1)
                self.assertTrue(ok1)
                
                # Add second key
                ok2 = cloud_ai.add_provider_key(test_prov, k2)
                self.assertTrue(ok2)

                keys = cloud_ai.get_provider_keys(test_prov)
                self.assertIn(k1, keys)
                self.assertIn(k2, keys)
                self.assertEqual(len(keys), 2)

                # Remove first key
                ok_rem = cloud_ai.remove_provider_key(test_prov, k1)
                self.assertTrue(ok_rem)
                keys_after = cloud_ai.get_provider_keys(test_prov)
                self.assertNotIn(k1, keys_after)
                self.assertIn(k2, keys_after)

    def test_virtual_models_identification(self):
        """Virtual models (auto, auto:fast, auto:smart, fusion) must be recognized as cloud models."""
        self.assertTrue(cloud_ai.is_cloud_model("auto"))
        self.assertTrue(cloud_ai.is_cloud_model("auto:fast"))
        self.assertTrue(cloud_ai.is_cloud_model("auto:smart"))
        self.assertTrue(cloud_ai.is_cloud_model("fusion"))
        self.assertTrue(cloud_ai.is_cloud_model("gemini-2.5-flash"))
        self.assertTrue(cloud_ai.is_cloud_model("llama-3.3-70b"))
        self.assertTrue(cloud_ai.is_cloud_model("meta-llama/llama-3.3-70b-instruct:free"))
        self.assertTrue(cloud_ai.is_cloud_model("deepseek-chat"))
        self.assertTrue(cloud_ai.is_cloud_model("deepseek-reasoner"))
        # Local Ollama models must strictly NOT be classified as cloud models
        self.assertFalse(cloud_ai.is_cloud_model("llama3.2:3b"))
        self.assertFalse(cloud_ai.is_cloud_model("deepseek-r1:7b"))
        self.assertFalse(cloud_ai.is_cloud_model("mistral:7b"))
        self.assertFalse(cloud_ai.is_cloud_model("qwen2.5-coder:7b"))

    def test_resolve_local_virtual_model(self):
        """Verify intelligent local mapping for fast, smart, and balanced auto models."""
        installed = ["deepseek-r1:7b", "llama3.2:1b", "llama3.2:3b", "qwen2.5-coder:7b"]
        
        # Fast should pick smallest/lightest model
        fast_choice = cloud_ai.resolve_local_virtual_model("auto:fast", installed)
        self.assertEqual(fast_choice, "llama3.2:1b")

        # Smart should pick deepest reasoning model (DeepSeek R1)
        smart_choice = cloud_ai.resolve_local_virtual_model("auto:smart", installed)
        self.assertEqual(smart_choice, "deepseek-r1:7b")

        # Auto should pick balanced model
        auto_choice = cloud_ai.resolve_local_virtual_model("auto", installed)
        self.assertIn(auto_choice, ["qwen2.5-coder:7b", "deepseek-r1:7b", "llama3.2:3b"])

    def test_automatic_failover_on_429(self):
        """When candidate 1 returns 429, candidate 2 must be tried automatically and succeed."""
        fake_candidates = [
            {"provider": "prov1", "model": "m1", "endpoint": "http://prov1/v1", "key": "k1", "rpm_cap": 30, "rpd_cap": 1000},
            {"provider": "prov2", "model": "m2", "endpoint": "http://prov2/v1", "key": "k2", "rpm_cap": 30, "rpd_cap": 1000},
        ]

        # Candidate 1 fails with 429, Candidate 2 succeeds with 200
        call_count = 0
        def fake_single_request(candidate, prompt, system_prompt, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if candidate["provider"] == "prov1":
                return False, "Rate limit exceeded (429)", 429
            return True, "Success from candidate 2!", 200

        with patch.object(cloud_ai, "_resolve_candidate_chain", return_value=fake_candidates), \
             patch.object(cloud_ai, "_execute_single_cloud_request", side_effect=fake_single_request):
            ok, reply = cloud_ai.query_cloud_ai("Test question", model="auto")
            self.assertTrue(ok)
            self.assertEqual(reply, "Success from candidate 2!")
            self.assertEqual(call_count, 2)

    def test_model_fusion_synthesis(self):
        """Fusion virtual model should query panel in parallel and synthesize with judge."""
        fake_candidates = [
            {"provider": "groq", "model": "llama-3.3-70b", "endpoint": "http://ep1", "key": "k1", "rpm_cap": 30, "rpd_cap": 1000},
            {"provider": "gemini", "model": "gemini-2.0-flash", "endpoint": "http://ep2", "key": "k2", "rpm_cap": 30, "rpd_cap": 1000},
        ]

        def fake_single_request(cand, prompt, *args, **kwargs):
            if "Chief Intelligence Judge" in prompt:
                return True, "Synthesized consensus by Judge.", 200
            return True, f"Draft answer from {cand['provider']}", 200

        with patch.object(cloud_ai, "_resolve_candidate_chain", return_value=fake_candidates), \
             patch.object(cloud_ai, "_execute_single_cloud_request", side_effect=fake_single_request):
            ok, reply = cloud_ai.query_cloud_ai("What is Rust?", model="fusion")
            self.assertTrue(ok)
            self.assertIn("Synthesized consensus", reply)


if __name__ == "__main__":
    unittest.main()
