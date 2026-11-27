"""Tests & Negative Controls for Ternary Bonsai 2.5 Sidecar, Free Cloud FLUX, and Local stable-diffusion.cpp."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cloud_ai
import local_sidecars
import multi_agent
import sidecar_installer


class _FakeHTTPResp:
    def __init__(self, body: bytes, status: int = 200, headers: dict | None = None) -> None:
        self._body = body
        self._offset = 0
        self.status = status
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        if self._offset >= len(self._body):
            return b""
        if n < 0:
            chunk = self._body[self._offset:]
            self._offset = len(self._body)
            return chunk
        chunk = self._body[self._offset:self._offset + n]
        self._offset += len(chunk)
        return chunk

    def __enter__(self) -> "_FakeHTTPResp":
        return self

    def __exit__(self, *args) -> None:
        return None


class TestTernaryBonsaiAndImageGeneration(unittest.TestCase):
    def test_sidecar_rejects_non_loopback_endpoints(self) -> None:
        with self.assertRaises(ValueError):
            local_sidecars.SidecarRuntimeManager(llama_endpoint="https://evil.example.com:11435")
        with self.assertRaises(ValueError):
            local_sidecars._validate_loopback_url("http://169.254.169.254:11435")

    def test_hardware_fit_assessment_modes(self) -> None:
        fit = local_sidecars.assess_model_hardware_fit("ternary-bonsai-2.5-27b-q2_0", 7.67)
        self.assertIn(fit.fit_mode, ("GPU_FULL", "HYBRID_GPU_RAM_OFFLOAD", "CPU_RAM_ONLY", "LOW_HEADROOM_WARN"))
        self.assertTrue(len(fit.advisory) > 10)

    def test_router_and_multi_agent_prefer_bonsai_when_available(self) -> None:
        installed = ["llama3.2:3b", "qwen2.5-coder:7b", "deepseek-r1:7b", "ternary-bonsai-2.5-27b-q2_0"]
        chosen = cloud_ai.resolve_local_virtual_model("auto:smart", installed)
        self.assertEqual(chosen, "ternary-bonsai-2.5-27b-q2_0")

        with patch.object(multi_agent, "discover_available_models", return_value=installed):
            reg = multi_agent.TeamRoleModelRegistry()
            self.assertEqual(reg.role_models["senior_developer"], "ternary-bonsai-2.5-27b-q2_0")
            self.assertEqual(reg.role_models["debugger"], "ternary-bonsai-2.5-27b-q2_0")

    def test_generate_image_cloud_supports_free_pollinations_and_validates_magic_bytes(self) -> None:
        png_bytes = b"\x89PNG\r\n\x1a\n" + (b"\x00" * 64)
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_INTERNET_ENABLED": "1"}), patch(
            "pathlib.Path.home", return_value=Path(td)
        ), patch("cloud_ai.get_provider_key", return_value=None), patch(
            "cloud_ai.load_cloud_config", return_value={"configured_models": []}
        ), patch("cloud_ai._guarded_urlopen", return_value=_FakeHTTPResp(png_bytes)):
            ok, uri, out_path, fname = cloud_ai.generate_image_cloud("A serene Sri Lankan sunset", model="pollinations-flux")
            self.assertTrue(ok)
            self.assertTrue(uri.startswith("data:image/png;base64,"))
            self.assertTrue(Path(out_path).is_file())
            self.assertTrue(fname.endswith(".png"))

        # Negative control: corrupt HTML instead of PNG/JPEG must fail closed
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_INTERNET_ENABLED": "1"}), patch(
            "pathlib.Path.home", return_value=Path(td)
        ), patch("cloud_ai.get_provider_key", return_value=None), patch(
            "cloud_ai.load_cloud_config", return_value={"configured_models": []}
        ), patch("cloud_ai._guarded_urlopen", return_value=_FakeHTTPResp(b"<html>not an image</html>")):
            ok_bad, msg_bad, f_bad, _ = cloud_ai.generate_image_cloud("A bridge", model="pollinations-flux")
            self.assertFalse(ok_bad)
            self.assertIsNone(f_bad)
            self.assertTrue(len(msg_bad) > 10)

    def test_local_sdcpp_offline_image_generation_and_magic_validation(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_CONFIG_DIR": td}):
            bin_dir = Path(td) / "bin" / "stable-diffusion.cpp"
            bin_dir.mkdir(parents=True)
            fake_exe = bin_dir / ("sd-cli.exe" if sys.platform == "win32" else "sd-cli")
            fake_exe.write_bytes(b"MZ")

            img_dir = Path(td) / "models" / "image"
            img_dir.mkdir(parents=True)
            (img_dir / "flux1-schnell-q4_k.gguf").write_bytes(b"GGUF")
            (img_dir / "ae.safetensors").write_bytes(b"AE")
            (img_dir / "clip_l.safetensors").write_bytes(b"CLIP")
            (img_dir / "t5xxl_fp8_e4m3fn.safetensors").write_bytes(b"T5")

            sc = local_sidecars.SidecarRuntimeManager()

            def _fake_run(cmd, **_kwargs):
                out_idx = cmd.index("-o") + 1
                Path(cmd[out_idx]).write_bytes(b"\x89PNG\r\n\x1a\nTESTPNG")
                return SimpleNamespace(returncode=0, stderr="", stdout="done")

            with patch.object(local_sidecars, "check_runtime_admission", return_value={"allowed": True, "recommended_ctx_size": 4096, "recommended_gpu_layers": 26}), \
                 patch.object(local_sidecars.subprocess, "run", side_effect=_fake_run):
                ok, data_uri, out_f, fname = sc.generate_image_local_sdcpp("Mountain valley", model_tag="flux-1-schnell-q4")
                self.assertTrue(ok)
                self.assertTrue(data_uri.startswith("data:image/png;base64,"))
                self.assertTrue(Path(out_f).is_file())

            # Negative control: non-PNG output from binary is deleted and rejected
            def _bad_run(cmd, **_kwargs):
                out_idx = cmd.index("-o") + 1
                Path(cmd[out_idx]).write_bytes(b"NOT_AN_IMAGE")
                return SimpleNamespace(returncode=0, stderr="", stdout="")

            with patch.object(local_sidecars, "check_runtime_admission", return_value={"allowed": True, "recommended_ctx_size": 4096, "recommended_gpu_layers": 26}), \
                 patch.object(local_sidecars.subprocess, "run", side_effect=_bad_run):
                ok2, err2, out2, _ = sc.generate_image_local_sdcpp("Bad file test", model_tag="flux-1-schnell-q4")
                self.assertFalse(ok2)
                self.assertIsNone(out2)
                self.assertIn("PNG/JPEG", err2)

    def test_gate1_readiness_storage_sync_and_installer_security(self) -> None:
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_CONFIG_DIR": td}):
            custom_root = Path(td) / "CustomModels"
            custom_root.mkdir()
            sc = local_sidecars.SidecarRuntimeManager(storage_root=custom_root)
            gguf_dir = local_sidecars.get_gguf_models_dir(custom_root)
            (gguf_dir / "Ternary-Bonsai-2.5-27B-Q2_0.gguf").write_bytes(b"GGUF_TEST")
            listed = sc.list_installed_gguf_models()
            self.assertEqual([m["name"] for m in listed], ["ternary-bonsai-2.5-27b-q2_0"])

            readiness = local_sidecars.assess_install_and_run_readiness("ternary-bonsai-2.5-27b-q2_0", target_path=str(custom_root))
            self.assertTrue(readiness["disk_free_gb"] >= 0.0)
            self.assertIn("required_disk_gb", readiness)
            self.assertIn("gpu_backend", readiness)

            adm = local_sidecars.check_runtime_admission("ternary-bonsai-2.5-27b-q2_0", 7.67)
            self.assertIn("recommended_ctx_size", adm)

            # Negative control: installer blocks disallowed hosts, zip-slip archives, and offline air-gap
            with self.assertRaises(ValueError):
                sidecar_installer._validated_open("https://evil-host.example.com/model.gguf")
            ok_off, msg_off = sidecar_installer.provision_runtime_and_model(
                "ternary-bonsai-2.5-27b-q2_0",
                storage_path=str(custom_root),
                offline_check_fn=lambda: False,
            )
            self.assertFalse(ok_off)
            self.assertIn("Offline", msg_off)

            import zipfile as _zf
            evil_zip = Path(td) / "evil_runtime.zip"
            with _zf.ZipFile(evil_zip, "w") as z:
                z.writestr("../escape.exe", b"MZ")
            with self.assertRaises(ValueError):
                sidecar_installer._safe_extract_zip(evil_zip, Path(td) / "extract")

            # Negative control: FLUX missing companion weights (ae/clip_l/t5xxl) fails closed clearly
            bin_dir = Path(td) / "bin" / "stable-diffusion.cpp"
            bin_dir.mkdir(parents=True)
            (bin_dir / ("sd-cli.exe" if sys.platform == "win32" else "sd-cli")).write_bytes(b"MZ")
            img_dir = local_sidecars.get_image_models_dir(custom_root)
            (img_dir / "flux1-schnell-q4_k.gguf").write_bytes(b"GGUF")
            ok_flux, msg_flux, _, _ = sc.generate_image_local_sdcpp("Cat", model_tag="flux-1-schnell-q4")
            self.assertFalse(ok_flux)
            self.assertIn("ae.safetensors", msg_flux)

    def test_audit_fixes_zip_stream_limit_html_rejection_unc_path_abort_and_admission(self) -> None:
        import threading
        import zipfile as _zf
        repo_root = str(Path(__file__).resolve().parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from desktop import bridge_server

        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_CONFIG_DIR": td}):
            # 1. Negative control: spoofed info.file_size ZIP bomb caught via actual decompressed byte counter
            spoof_zip = Path(td) / "spoof_bomb.zip"
            with _zf.ZipFile(spoof_zip, "w", compression=_zf.ZIP_DEFLATED) as z:
                z.writestr("big.bin", b"A" * (600 * 1024))
            with patch.object(sidecar_installer, "MAX_RUNTIME_ARCHIVE_BYTES", 256 * 1024):
                with self.assertRaises(ValueError) as ctx:
                    sidecar_installer._safe_extract_zip(spoof_zip, Path(td) / "out_bomb")
                self.assertIn("extraction limit", str(ctx.exception).lower())

            # 2. Negative control: HTML gated response masquerading as binary GGUF weight rejected
            html_resp = _FakeHTTPResp(b"<!doctype html><html>Sign in</html>", headers={"Content-Type": "text/html"})
            with patch.object(sidecar_installer, "_validated_open", return_value=html_resp):
                with self.assertRaises(ValueError):
                    sidecar_installer._stream_download_resumable(
                        "https://huggingface.co/test/model.gguf",
                        Path(td) / "model.gguf",
                    )

            # 3. Negative control: pre-set abort_event halts download loop cleanly
            abort_ev = threading.Event()
            abort_ev.set()
            bin_resp = _FakeHTTPResp(b"GGUF" + b"\x00" * 4096, headers={"Content-Type": "application/octet-stream"})
            with patch.object(sidecar_installer, "_validated_open", return_value=bin_resp):
                with self.assertRaises(InterruptedError):
                    sidecar_installer._stream_download_resumable(
                        "https://huggingface.co/test/ok.gguf",
                        Path(td) / "ok.gguf",
                        abort_event=abort_ev,
                    )

            # 4. Negative control: UNC & ADS storage paths blocked in both installer and bridge_server
            with self.assertRaises(ValueError):
                sidecar_installer.validate_safe_storage_path(r"\\evil-smb\models")
            with self.assertRaises(ValueError):
                sidecar_installer.validate_safe_storage_path(r"C:\models:stream")
            self.assertFalse(bridge_server.set_model_storage_path(r"\\evil-smb\models"))

            # 5. Negative control: Gate 3 blocks admission under <1024 MB free RAM & infers 27B/70B sizes
            self.assertGreaterEqual(local_sidecars._estimate_model_size_gb("qwen2.5:32b"), 18.0)
            self.assertGreaterEqual(local_sidecars._estimate_model_size_gb("llama3.3:70b"), 40.0)
            low_snap = {"avail_ram_mb": 700.0, "budget": SimpleNamespace(compute_tier="COMPRESSED")}
            with patch.object(local_sidecars.hardware_telemetry.HardwareTelemetry, "get_system_snapshot", return_value=low_snap), \
                 patch.object(local_sidecars, "_detect_nvidia_vram_mb", return_value=8192):
                adm_low = local_sidecars.check_runtime_admission("llama3.2:3b", 0.0)
                self.assertFalse(adm_low["allowed"])

            # 6. Parity: _get_active_sidecar_manager picks up configured custom models_path & set_model_storage_path accepts valid paths
            custom_p = str(Path(td) / "ActiveCustom")
            Path(custom_p).mkdir(parents=True, exist_ok=True)
            with patch.object(bridge_server, "get_pai_config_path", return_value=Path(td) / "desktop_config.json"):
                self.assertTrue(bridge_server.set_model_storage_path(custom_p))
            with patch.object(bridge_server, "get_model_storage_path", return_value=custom_p):
                active_mgr = bridge_server._get_active_sidecar_manager()
                self.assertEqual(str(active_mgr.storage_root), custom_p)

    def test_release_list_skips_non_binary_latest_pairs_cudart_and_detects_missing_cuda_dlls(self) -> None:
        import json

        # 1. Simulate ggml-org/llama.cpp returning b12700 (no win zips) before b12780 (with cuda + cudart + vulkan)
        releases_payload = [
            {"tag_name": "b12700", "draft": False, "assets": [{"name": "llama-b12700.tar.gz", "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b12700/x.tar.gz"}]},
            {
                "tag_name": "b12780",
                "draft": False,
                "assets": [
                    {"name": "cudart-llama-bin-win-cuda-12.4-x64.zip", "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b12780/cudart.zip", "size": 373000000},
                    {"name": "llama-b12780-bin-win-cuda-12.4-x64.zip", "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b12780/cuda.zip", "size": 343000000},
                    {"name": "llama-b12780-bin-win-vulkan-x64.zip", "browser_download_url": "https://github.com/ggml-org/llama.cpp/releases/download/b12780/vulkan.zip", "size": 37000000},
                ],
            },
        ]
        with patch.object(sidecar_installer, "_validated_open", return_value=_FakeHTTPResp(json.dumps(releases_payload).encode("utf-8"))):
            rel, asset, err = sidecar_installer._find_latest_binary_release(
                "ggml-org/llama.cpp",
                gpu_backend="cuda",
                runtime="llama.cpp",
                min_build=sidecar_installer.MIN_LLAMA_CPP_BUILD,
            )
            self.assertIsNone(err)
            self.assertEqual(rel["tag_name"], "b12780")
            self.assertEqual(asset["name"], "llama-b12780-bin-win-cuda-12.4-x64.zip")
            cudart = sidecar_installer._select_cudart_asset(rel["assets"], asset["name"])
            self.assertIsNotNone(cudart)
            self.assertEqual(cudart["name"], "cudart-llama-bin-win-cuda-12.4-x64.zip")

        # 2. Missing cudart64_12.dll alongside ggml-cuda.dll marks folder unhealthy on Windows
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {"PAI_CONFIG_DIR": td}):
            sd_dir = Path(td) / "bin" / "stable-diffusion.cpp"
            sd_dir.mkdir(parents=True)
            (sd_dir / "sd-cli.exe").write_bytes(b"MZ")
            (sd_dir / "ggml-cuda.dll").write_bytes(b"MZ")
            if sys.platform == "win32":
                self.assertTrue(local_sidecars._has_missing_cuda_runtime_dlls(sd_dir))
                with patch.object(local_sidecars, "_has_missing_cuda_runtime_dlls", return_value=True):
                    self.assertIsNone(local_sidecars.find_sd_cpp_binary())
            (sd_dir / "cudart64_12.dll").write_bytes(b"MZ")
            (sd_dir / "cublas64_12.dll").write_bytes(b"MZ")
            self.assertFalse(local_sidecars._has_missing_cuda_runtime_dlls(sd_dir))

        # 3. Verify FLUX VAE URL is no longer pointing to 401-gated black-forest-labs repo
        flux_spec = local_sidecars.get_model_spec("flux-1-schnell-q4")
        vae_urls = [f["url"] for f in flux_spec["files"] if f["filename"] == "ae.safetensors"]
        self.assertTrue(vae_urls and "black-forest-labs/FLUX.1-schnell" not in vae_urls[0])
        self.assertGreaterEqual(sidecar_installer.MAX_RUNTIME_ARCHIVE_BYTES, 2 * 1024 * 1024 * 1024)

    def test_hf_cdn_redirect_allowed_evil_blocked_and_transient_drop_resumes(self) -> None:
        import http.client
        import urllib.request

        # 1. us.aws.cdn.hf.co is accepted by provision host allowlist & Auth stripped cross-origin
        handler = sidecar_installer._SafeProvisionRedirectHandler()
        orig_req = urllib.request.Request(
            "https://huggingface.co/prism-ml/Ternary-Bonsai-2.5-27B-GGUF/resolve/main/Ternary-Bonsai-2.5-27B-Q2_0.gguf",
            headers={"Authorization": "Bearer hf_secret_tok"},
        )
        cdn_url = "https://us.aws.cdn.hf.co/xet-bridge-us/blob123"
        next_req = handler.redirect_request(orig_req, None, 302, "Found", {}, cdn_url)
        self.assertIsNotNone(next_req)
        self.assertNotIn("Authorization", dict(next_req.header_items()))

        with self.assertRaises(Exception):
            handler.redirect_request(orig_req, None, 302, "Found", {}, "https://evil.example.com/payload.gguf")
        with self.assertRaises(Exception):
            handler.redirect_request(orig_req, None, 302, "Found", {}, "http://127.0.0.1:8080/internal")

        # 2. Transient IncompleteRead mid-stream automatically resumes using Range: bytes=...
        full_blob = b"GGUF" + (b"X" * 4096)
        class _DroppingResp:
            def __init__(self, data: bytes, fail_after: int | None, status: int) -> None:
                self._data = data
                self._pos = 0
                self._fail_after = fail_after
                self.status = status
                self.headers = {"Content-Length": str(len(data)), "Content-Type": "application/octet-stream"}
            def read(self, n: int = -1) -> bytes:
                if self._fail_after is not None and self._pos >= self._fail_after:
                    raise http.client.IncompleteRead(self._data[:self._pos], len(full_blob) - self._pos)
                end = len(self._data) if n < 0 else min(len(self._data), self._pos + n)
                if self._fail_after is not None:
                    end = min(end, self._fail_after)
                chunk = self._data[self._pos:end]
                self._pos = end
                return chunk
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return None

        calls = []
        def _fake_open(url, headers=None, timeout=60.0):
            rng = (headers or {}).get("Range")
            calls.append(rng)
            if rng is None:
                return _DroppingResp(full_blob, fail_after=1500, status=200)
            off = int(rng.split("=")[1].rstrip("-"))
            return _DroppingResp(full_blob[off:], fail_after=None, status=206)

        with tempfile.TemporaryDirectory() as td, patch.object(sidecar_installer, "_validated_open", side_effect=_fake_open), \
             patch.object(sidecar_installer, "DOWNLOAD_CHUNK_BYTES", 512), \
             patch.object(sidecar_installer.time, "sleep", return_value=None):
            out = sidecar_installer._stream_download_resumable(
                "https://huggingface.co/test/model.gguf",
                Path(td) / "model.gguf",
            )
            self.assertTrue(out.is_file())
            self.assertEqual(out.read_bytes(), full_blob)
            self.assertEqual(calls, [None, "bytes=1500-"])

    def test_bonsai_gpu_offload_503_500_retry_and_team_cowork_integration(self) -> None:
        import json
        import urllib.error
        repo_root = str(Path(__file__).resolve().parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from desktop import bridge_server

        # 1. With 6141 MB VRAM and low free RAM, offload layers stay high (>= 16), never hardcoded 4
        low_snap = {"avail_ram_mb": 900.0, "budget": SimpleNamespace(compute_tier="COMPRESSED")}
        with patch.object(local_sidecars.hardware_telemetry.HardwareTelemetry, "get_system_snapshot", return_value=low_snap), \
             patch.object(local_sidecars, "_detect_nvidia_vram_mb", return_value=6141):
            fit = local_sidecars.assess_model_hardware_fit("ternary-bonsai-2.5-27b-q2_0", 7.15)
            self.assertGreaterEqual(fit.recommended_gpu_layers, 16)

        # 2. query_llama_cpp retries 503 warming up and 500 oversized prompt cleanly
        sc = local_sidecars.SidecarRuntimeManager()
        attempt_prompts = []

        class _MockOpener:
            def open(self, req, timeout=60):
                body = json.loads(req.data.decode("utf-8"))
                attempt_prompts.append(len(body["messages"][0]["content"]))
                idx = len(attempt_prompts)
                if idx == 1:
                    raise urllib.error.HTTPError(req.full_url, 503, "Loading model", {}, None)
                if idx == 2:
                    raise urllib.error.HTTPError(req.full_url, 500, "Context overflow", {}, None)
                return _FakeHTTPResp(json.dumps({"choices": [{"message": {"content": "def add(a, b): return a + b"}}]}).encode("utf-8"))

        with patch.object(sc, "is_llama_server_running", return_value=True), \
             patch.object(local_sidecars.urllib.request, "build_opener", return_value=_MockOpener()), \
             patch.object(local_sidecars.time, "sleep", return_value=None):
            ok_q, res_q = sc.query_llama_cpp("x" * 14000, model_name="ternary-bonsai-2.5-27b-q2_0")
            self.assertTrue(ok_q)
            self.assertIn("def add", res_q)
            self.assertLessEqual(attempt_prompts[0], 9250)
            self.assertLessEqual(attempt_prompts[-1], 4850)

        # 3. multi_agent TeamRoleModelRegistry sees Bonsai on disk even when server not yet started
        ls_mod = sys.modules.get("research.local_sidecars", local_sidecars)
        with patch.object(ls_mod, "find_llama_server_binary", return_value=Path("llama-server.exe")), \
             patch.object(ls_mod.SidecarRuntimeManager, "is_llama_server_running", return_value=False), \
             patch.object(ls_mod.SidecarRuntimeManager, "list_installed_gguf_models", return_value=[{"name": "ternary-bonsai-2.5-27b-q2_0"}]):
            with patch("urllib.request.urlopen", side_effect=OSError("offline")):
                found = multi_agent.discover_available_models()
                self.assertIn("ternary-bonsai-2.5-27b-q2_0", found)

        # 4. Cowork _run_cowork_step_llm resolves "auto" to installed ternary-bonsai instead of literal "auto"
        called_models = []
        with patch.object(bridge_server, "is_internet_enabled", return_value=False), \
             patch.object(bridge_server, "get_current_model", return_value="auto"), \
             patch.object(bridge_server, "get_all_installed_local_models", return_value=([{"name": "ternary-bonsai-2.5-27b-q2_0", "model_type": "text"}], False)), \
             patch.object(bridge_server, "_execute_local_ollama_query", side_effect=lambda m, p, **kw: (called_models.append(m) or (True, "CONFIRMED"))):
            ok_cw, rep_cw = bridge_server._run_cowork_step_llm("Build step 1", "System prompt", 4096, 512)
            self.assertTrue(ok_cw)
            self.assertEqual(called_models, ["ternary-bonsai-2.5-27b-q2_0"])

    def test_memory_optimizer_mutual_exclusion_64_layer_and_sse_streaming(self) -> None:
        import json
        import memory_optimizer

        # 1. Mutual exclusion: prepare_memory_for_engine stops running llama-server & evicts idle Ollama before sd.cpp
        mgr = local_sidecars.SidecarRuntimeManager()
        stopped = []
        evicted_calls = []
        with patch.object(mgr, "is_llama_server_running", return_value=True), \
             patch.object(mgr, "stop_llama_server", side_effect=lambda: stopped.append(True)), \
             patch.object(memory_optimizer, "evict_ollama_loaded_models", side_effect=lambda except_model=None: evicted_calls.append(except_model) or ["qwen2.5-coder:7b"]):
            res = memory_optimizer.prepare_memory_for_engine("sd.cpp", sidecar_mgr=mgr)
            self.assertEqual(stopped, [True])
            self.assertEqual(evicted_calls, [None])
            self.assertIn("Stopped idle llama.cpp sidecar server", res["actions"])

        # 2. 64-layer fit calculation & streaming FLUX peak calibration (~5.5 GB vs 11.5 GB)
        snap = {"avail_ram_mb": 2000.0, "budget": SimpleNamespace(compute_tier="BALANCED")}
        with patch.object(local_sidecars.hardware_telemetry.HardwareTelemetry, "get_system_snapshot", return_value=snap), \
             patch.object(local_sidecars, "_detect_nvidia_vram_mb", return_value=6141):
            fit_27b = local_sidecars.assess_model_hardware_fit("ternary-bonsai-2.5-27b-q2_0", 7.15)
            self.assertGreaterEqual(fit_27b.recommended_gpu_layers, 40)
            adm_flux = local_sidecars.check_runtime_admission("flux-1-schnell-q4", 11.5, streaming_image=True)
            self.assertTrue(adm_flux["allowed"])

        # 3. SSE streaming response assembly in query_llama_cpp
        sse_body = (
            b'data: {"choices":[{"delta":{"content":"```python\\n"}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"print(42)"}}]}\n\n'
            b'data: {"choices":[{"delta":{"content":"\\n```"}}]}\n\n'
            b'data: [DONE]\n\n'
        )
        class _StreamResp:
            def __init__(self, raw: bytes) -> None:
                self._lines = raw.splitlines(keepends=True)
                self._idx = 0
                self.headers = {"Content-Type": "text/event-stream"}
            def readline(self) -> bytes:
                if self._idx >= len(self._lines):
                    return b""
                ln = self._lines[self._idx]
                self._idx += 1
                return ln
            def __enter__(self): return self
            def __exit__(self, *a): return None
        class _StreamOpener:
            def open(self, req, timeout=45): return _StreamResp(sse_body)

        with patch.object(mgr, "is_llama_server_running", return_value=True), \
             patch.object(local_sidecars.urllib.request, "build_opener", return_value=_StreamOpener()):
            ok_s, txt_s = mgr.query_llama_cpp("Print 42", model_name="ternary-bonsai-2.5-27b-q2_0")
            self.assertTrue(ok_s)
            self.assertIn("print(42)", txt_s)

        # 4. Negative control: FLUX with <1024 MB RAM still fails closed even in streaming mode
        low_snap = {"avail_ram_mb": 650.0, "budget": SimpleNamespace(compute_tier="COMPRESSED")}
        with patch.object(local_sidecars.hardware_telemetry.HardwareTelemetry, "get_system_snapshot", return_value=low_snap), \
             patch.object(local_sidecars, "_detect_nvidia_vram_mb", return_value=6141):
            adm_bad = local_sidecars.check_runtime_admission("flux-1-schnell-q4", 11.5, streaming_image=True)
            self.assertFalse(adm_bad["allowed"])

    def test_free_keyless_cloud_flux_fallback_and_image_save_as(self) -> None:
        import base64
        import http.client
        import json
        import threading
        repo_root = str(Path(__file__).resolve().parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from desktop import bridge_server

        # 1. Both cloudflare-flux-schnell and hf-flux-schnell fall back cleanly to Free Keyless Pollinations FLUX
        valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        seen_urls = []

        def _fake_urlopen(req_or_url, timeout=30.0, allow_private=False, allow_redirects=True):
            u = req_or_url.full_url if hasattr(req_or_url, "full_url") else str(req_or_url)
            seen_urls.append(u)
            return _FakeHTTPResp(valid_png, status=200, headers={"Content-Type": "image/png"})

        with tempfile.TemporaryDirectory() as td, \
             patch("pathlib.Path.home", return_value=Path(td)), \
             patch.object(cloud_ai, "is_internet_enabled", return_value=True), \
             patch.object(cloud_ai, "get_provider_key", return_value=""), \
             patch.object(cloud_ai, "_guarded_urlopen", side_effect=_fake_urlopen):
            for tag in ("cloudflare-flux-schnell", "hf-flux-schnell"):
                ok_g, data_uri, fpath, fname = cloud_ai.generate_image_cloud("blue tree", model=tag)
                self.assertTrue(ok_g)
                self.assertTrue(data_uri.startswith("data:image/png;base64,"))
                self.assertTrue(Path(fpath).is_file())
            self.assertEqual(len(seen_urls), 2)
            self.assertTrue(all("image.pollinations.ai" in u for u in seen_urls))

        # 2. /api/models/pull enables both presets without requiring HF/CF keys; /api/image/save_as validates & saves
        srv = bridge_server.ThreadingHTTPServer(("127.0.0.1", 0), bridge_server.PAIBridgeHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            b64_png = base64.b64encode(valid_png).decode("ascii")
            hdrs = {"Content-Type": "application/json", "X-PAI-Token": bridge_server.PAI_BRIDGE_TOKEN}

            def _req(path: str, payload: dict):
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                c.request("POST", path, body=json.dumps(payload), headers=hdrs)
                r = c.getresponse()
                raw = r.read().decode("utf-8", errors="replace")
                st_code = r.status
                c.close()
                return st_code, raw

            with tempfile.TemporaryDirectory() as td, \
                 patch("pathlib.Path.home", return_value=Path(td)), \
                 patch.object(bridge_server, "is_internet_enabled", return_value=True), \
                 patch.object(bridge_server, "get_provider_key", return_value=""), \
                 patch.object(bridge_server, "create_physical_model_folder"), \
                 patch.object(bridge_server, "set_installed_image_model") as mock_reg:
                for tag in ("cloudflare-flux-schnell", "hf-flux-schnell"):
                    st_p, body_p = _req("/api/models/pull", {"model": tag, "path": td})
                    self.assertEqual(st_p, 200)
                    self.assertIn('"status": "success"', body_p)
                    mock_reg.assert_any_call(tag, is_installed=True)

                # Valid PNG + path traversal filename sanitized -> writes inside picked folder
                save_dir = Path(td) / "Desktop"
                save_dir.mkdir(parents=True, exist_ok=True)
                with patch.object(bridge_server, "open_native_folder_dialog", return_value=str(save_dir)):
                    st_s, body_s = _req("/api/image/save_as", {
                        "data_url": f"data:image/png;base64,{b64_png}",
                        "filename": "../../evil/my art.png",
                    })
                    self.assertEqual(st_s, 200)
                    res_s = json.loads(body_s)
                    self.assertTrue(res_s["success"])
                    saved = Path(res_s["saved_path"])
                    self.assertEqual(saved.parent.resolve(), save_dir.resolve())
                    self.assertEqual(saved.name, "my_art.png")
                    self.assertEqual(saved.read_bytes(), valid_png)

                # Negative control: cancel folder picker returns cancelled cleanly
                with patch.object(bridge_server, "open_native_folder_dialog", return_value=None):
                    st_c, body_c = _req("/api/image/save_as", {
                        "data_url": f"data:image/png;base64,{b64_png}",
                        "filename": "cancel.png",
                    })
                    self.assertEqual(st_c, 200)
                    self.assertTrue(json.loads(body_c).get("cancelled"))

                # Negative control: non-image payload disguised as PNG base64 rejected with 400
                evil_b64 = base64.b64encode(b"<html>not a png</html>").decode("ascii")
                st_bad, body_bad = _req("/api/image/save_as", {
                    "data_url": f"data:image/png;base64,{evil_b64}",
                    "filename": "bad.png",
                })
                self.assertEqual(st_bad, 400)
                self.assertFalse(json.loads(body_bad).get("success"))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_keyless_horde_fallback_image_prompt_guard_and_friendly_errors(self) -> None:
        import io
        import json
        import urllib.error
        repo_root = str(Path(__file__).resolve().parent.parent.parent)
        if repo_root not in sys.path:
            sys.path.insert(0, repo_root)
        from desktop import bridge_server

        # 1. AI Horde anonymous cluster fallback triggers when Pollinations returns HTTP 402 cooldown
        valid_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        called_urls = []

        def _fake_urlopen(req_or_url, timeout=30.0, allow_private=False, allow_redirects=True):
            u = req_or_url.full_url if hasattr(req_or_url, "full_url") else str(req_or_url)
            called_urls.append(u)
            if "image.pollinations.ai" in u:
                raise urllib.error.HTTPError(u, 402, "Payment Required", {"Retry-After": "43"}, io.BytesIO(b"rate limit"))
            if "stablehorde.net/api/v2/generate/async" in u:
                return _FakeHTTPResp(json.dumps({"id": "job-12345678"}).encode("utf-8"))
            if "stablehorde.net/api/v2/generate/check/" in u:
                return _FakeHTTPResp(json.dumps({"done": True}).encode("utf-8"))
            if "stablehorde.net/api/v2/generate/status/" in u:
                return _FakeHTTPResp(json.dumps({"generations": [{"img": "https://cdn.example.net/out.png"}]}).encode("utf-8"))
            return _FakeHTTPResp(valid_png, headers={"Content-Type": "image/png"})

        with tempfile.TemporaryDirectory() as td, \
             patch("pathlib.Path.home", return_value=Path(td)), \
             patch.object(cloud_ai, "is_internet_enabled", return_value=True), \
             patch.object(cloud_ai, "get_provider_key", return_value=""), \
             patch.object(cloud_ai.time, "sleep", return_value=None), \
             patch.object(cloud_ai, "_guarded_urlopen", side_effect=_fake_urlopen):
            ok_h, data_uri, fpath, _ = cloud_ai.generate_image_cloud("dog painting", model="pollinations-flux")
            self.assertTrue(ok_h)
            self.assertTrue(data_uri.startswith("data:image/png;base64,"))
            self.assertTrue(any("stablehorde.net/api/v2/generate/async" in u for u in called_urls))

        # 2. Image-model prompt guard rejects Q&A/code questions while keeping real image prompts
        self.assertFalse(bridge_server._looks_like_image_generation_request("who is the president of us?"))
        self.assertFalse(bridge_server._looks_like_image_generation_request("can you write python code"))
        self.assertTrue(bridge_server._looks_like_image_generation_request("/image dog painting"))
        self.assertTrue(bridge_server._looks_like_image_generation_request("draw a golden retriever in a forest"))

        # 3. _format_sdcpp_friendly_error strips CUDA/DLL/local paths and surfaces actionable RAM guidance
        raw_sd_log = (
            "ggml_cuda_init: found 1 CUDA devices\n"
            "load_backend: loaded CUDA backend from C:\\Users\\alice\\.pai\\bin\\ggml-cuda.dll\n"
            "[E] RAM graph capacity exceeded. Requested 21417680 bytes, 0 bytes available --- model_manager.cpp:1359\n"
        )
        friendly = local_sidecars._format_sdcpp_friendly_error(raw_sd_log, "flux-1-schnell-q4")
        self.assertIn("Not enough free memory", friendly)
        self.assertNotIn("ggml_cuda_init", friendly)
        self.assertNotIn("alice", friendly)


if __name__ == "__main__":
    unittest.main()
