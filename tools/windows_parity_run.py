#!/usr/bin/env python3
"""
tools/windows_parity_run.py - Automated Comprehensive Windows Tree Shadow Parity Runner.

Performs an exhaustive end-to-end parity validation on real Windows NTFS filesystems:
1. Sinhala UTF-8 non-ASCII filenames and directories (e.g. සිංහල_ෆෝල්ඩරය/විස්තරය.md).
2. Windows directory junctions (mklink /J junction_link).
3. Windows reserved device names (CON.txt, NUL.py, PRN.log, AUX.dat -> SPECIAL_FILE).
4. NTFS Alternate Data Streams (ADS).
5. Secret deny patterns (.env, credentials.json -> SECRET_FILE).
6. Junk directories (.git, node_modules -> JUNK_DIRECTORY).
7. Deep and multi-file tree (35+ files, >300 KB).
8. Full end-to-end operation execution: pai analyze, pai docs, ingest_file, ingest_folder, Updater.verify_release, pai doctor.
9. Asserts 0 shadow discrepancies across all comparisons.

Run after each Rust core change or release build on Windows.
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from typing import Any, Dict

# Resolve paths
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RESEARCH_DIR = os.path.join(REPO_ROOT, "research")
TESTS_DIR = os.path.join(RESEARCH_DIR, "tests")

if RESEARCH_DIR not in sys.path:
    sys.path.insert(0, RESEARCH_DIR)
if TESTS_DIR not in sys.path:
    sys.path.insert(0, TESTS_DIR)

import pai
import pai_core_bridge
from updater import Updater
from test_updater_differential import make_test_release, TEST_PUB, TEST_CONST_SHA


class StubOllamaHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"version": "0.1.0"}).encode("utf-8"))
        elif self.path == "/api/tags":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"models": [{"name": "stub-model", "digest": "sha256:12345"}]}).encode("utf-8"))
        elif self.path == "/api/ps":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"models": []}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/generate":
            content_length = int(self.headers.get("Content-Length", 0))
            _ = self.rfile.read(content_length).decode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"response": "Analysis summary completed successfully."}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


def run_windows_parity() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    print("================================================================================")
    print("      AUTOMATED COMPREHENSIVE WINDOWS SHADOW PARITY VERIFICATION RUN           ")
    print("================================================================================")

    # 1. Start loopback stub server
    server = http.server.HTTPServer(("127.0.0.1", 0), StubOllamaHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    stub_url = f"http://127.0.0.1:{port}"

    # 2. Configure dedicated runner shadow log to strictly isolate from default log
    runner_shadow_log = os.path.join(tempfile.gettempdir(), f"pai_runner_shadow_{os.getpid()}.jsonl")
    orig_shadow_log = os.environ.get("PAI_SHADOW_LOG")
    orig_telemetry_source = os.environ.get("PAI_TELEMETRY_SOURCE")

    os.environ["PAI_SHADOW_LOG"] = runner_shadow_log
    os.environ["PAI_TELEMETRY_SOURCE"] = "runner"
    pai_core_bridge.set_telemetry_source("runner")

    # Clear only the runner's isolated shadow log
    pai_core_bridge.clear_shadow_log()

    # 3. Configure environment
    orig_core = os.environ.get("PAI_USE_RUST_CORE")
    orig_shadow = os.environ.get("PAI_SHADOW_COMPARE")
    orig_model_url = os.environ.get("PAI_MODEL_URL")
    orig_ollama_url = os.environ.get("OLLAMA_BASE_URL")

    os.environ["PAI_USE_RUST_CORE"] = "1"
    os.environ["PAI_SHADOW_COMPARE"] = "1"
    os.environ["PAI_MODEL_URL"] = stub_url
    os.environ["OLLAMA_BASE_URL"] = stub_url
    os.environ.pop("PAI_RUST_FALLBACK_PYTHON", None)

    pai_core_bridge.PAI_USE_RUST_CORE = True
    pai_core_bridge.PAI_SHADOW_COMPARE = True
    pai_core_bridge.PAI_RUST_FALLBACK_PYTHON = False

    # 4. Create rich real test tree
    root_dir = tempfile.mkdtemp(prefix="pai_comprehensive_real_")
    print(f"Target test directory: {root_dir}")

    try:
        # A. Sinhala Unicode UTF-8 files & folders
        sinhala_dir = os.path.join(root_dir, "සිංහල_ෆෝල්ඩරය")
        os.makedirs(sinhala_dir, exist_ok=True)
        sinhala_doc = os.path.join(sinhala_dir, "විස්තරය.md")
        with open(sinhala_doc, "w", encoding="utf-8") as f:
            f.write("# ව්‍යාපෘති විස්තරය\nමෙය සිංහල භාෂාවෙන් ලියන ලද පරීක්ෂණ ගොනුවකි.\n" * 50)

        sinhala_code = os.path.join(sinhala_dir, "ක්‍රමලේඛනය.py")
        with open(sinhala_code, "w", encoding="utf-8") as f:
            f.write("def එකතුව(අ, ආ):\n    return අ + ආ\n\nprint(එකතුව(10, 20))\n")

        # B. Reserved device names (CON.txt, NUL.py, PRN.log, AUX.dat)
        reserved_verbatim_paths = []
        for res_name in ["CON.txt", "NUL.py", "PRN.log", "AUX.dat"]:
            try:
                vp = "\\\\?\\" + os.path.abspath(os.path.join(root_dir, res_name))
                with open(vp, "w", encoding="utf-8") as f:
                    f.write("reserved device test")
                if not os.path.exists(vp):
                    print(f"FATAL: Reserved name file does not exist after creation: {res_name}", file=sys.stderr)
                    return 1
                reserved_verbatim_paths.append(vp)
                print(f"[OK] Created reserved name file via verbatim path: {res_name}")
            except Exception as e:
                print(f"FATAL: Failed to create reserved name file {res_name}: {e}", file=sys.stderr)
                return 1

        # C. NTFS Alternate Data Stream
        ads_base = os.path.join(root_dir, "ads_test.txt")
        with open(ads_base, "w", encoding="utf-8") as f:
            f.write("Normal base stream content")
        try:
            with open(ads_base + ":hidden_stream", "w", encoding="utf-8") as f:
                f.write("Secret ADS hidden content")
            print("[OK] Successfully wrote NTFS Alternate Data Stream ads_test.txt:hidden_stream")
        except Exception as e:
            print(f"FATAL: Failed to create NTFS Alternate Data Stream: {e}", file=sys.stderr)
            return 1

        # C2. Lone surrogate non-decodable filename (INVALID_FILENAME hazard)
        surrogate_file = "\\\\?\\" + os.path.abspath(os.path.join(root_dir, "bad_\ud800_name.txt"))
        try:
            with open(surrogate_file, "w", encoding="utf-8") as f:
                f.write("lone surrogate test content")
            if not os.path.exists(surrogate_file):
                print("FATAL: Lone surrogate file does not exist after creation", file=sys.stderr)
                return 1
            print("[OK] Created lone surrogate filename: bad_\\ud800_name.txt")
        except Exception as e:
            print(f"FATAL: Failed to create lone surrogate filename: {e}", file=sys.stderr)
            return 1

        # D. Secret deny files
        with open(os.path.join(root_dir, ".env"), "w", encoding="utf-8") as f:
            f.write("API_KEY=sk-test-secret-1234567890\n")
        with open(os.path.join(root_dir, "credentials.json"), "w", encoding="utf-8") as f:
            f.write('{"client_secret": "sensitive_data"}\n')

        # E. Junk directories
        git_dir = os.path.join(root_dir, ".git")
        os.makedirs(git_dir, exist_ok=True)
        with open(os.path.join(git_dir, "HEAD"), "w", encoding="utf-8") as f:
            f.write("ref: refs/heads/master\n")

        node_dir = os.path.join(root_dir, "node_modules")
        os.makedirs(node_dir, exist_ok=True)
        with open(os.path.join(node_dir, "package.json"), "w", encoding="utf-8") as f:
            f.write('{"name": "junk"}\n')

        # F. Large tree: 35+ files totaling > 300 KB
        large_sub = os.path.join(root_dir, "large_tree")
        os.makedirs(large_sub, exist_ok=True)
        for i in range(35):
            sub_folder = os.path.join(large_sub, f"module_{i // 5}")
            os.makedirs(sub_folder, exist_ok=True)
            fpath = os.path.join(sub_folder, f"file_{i}.txt")
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(f"Payload content for file index {i}\n" * 300)

        # G. Directory Junction
        junction_target = os.path.join(root_dir, "junction_link")
        junction_source = os.path.join(large_sub, "module_0")
        try:
            res = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", junction_target, junction_source],
                capture_output=True,
                text=True
            )
            if res.returncode != 0:
                print(f"FATAL: Failed to create directory junction (mklink /J returned {res.returncode}): {res.stderr.strip()}", file=sys.stderr)
                return 1
            print(f"[OK] Created directory junction: {junction_target} -> {junction_source}")
        except Exception as e:
            print(f"FATAL: Failed to execute mklink /J: {e}", file=sys.stderr)
            return 1

        # H. Symlinks (if permitted on user environment)
        symlink_target = os.path.join(root_dir, "symlink_file.txt")
        try:
            os.symlink(sinhala_doc, symlink_target)
            print(f"[OK] Created symlink: {symlink_target} -> {sinhala_doc}")
        except Exception as e:
            print(f"[INFO] Symlink creation note: {e}")

        total_entries = len(list(Path(root_dir).rglob('*')))
        total_size = sum(f.stat().st_size for f in Path(root_dir).rglob('*') if f.is_file())
        print(f"Populated test tree: {total_entries} entries, {total_size} bytes ({total_size/1024:.1f} KB)\n")

        # 5. EXECUTE OPERATIONS WITH PAI_USE_RUST_CORE=1 and PAI_SHADOW_COMPARE=1
        print("--- Step 1: pai analyze ---")
        rc_analyze = pai.main(["analyze", root_dir, "--model", "stub-model", "--json"])
        if rc_analyze != 0:
            print(f"FATAL: pai analyze failed with exit code {rc_analyze}", file=sys.stderr)
            return 1

        print("\n--- Step 2: pai docs ---")
        rc_docs = pai.main(["docs", sinhala_doc, "--model", "stub-model", "--json"])
        if rc_docs != 0:
            print(f"FATAL: pai docs failed with exit code {rc_docs}", file=sys.stderr)
            return 1

        print("\n--- Step 3: pai_core_bridge.ingest_file ---")
        item, rej = pai_core_bridge.ingest_file(sinhala_doc)
        if not item or rej is not None:
            print(f"FATAL: ingest_file failed: item={item}, rej={rej}", file=sys.stderr)
            return 1

        print("\n--- Step 3b: pai_core_bridge.ingest_file ADS check ---")
        ads_path = ads_base + ":hidden_stream"
        ads_item, ads_rej = pai_core_bridge.ingest_file(ads_path)
        if ads_item is not None or ads_rej is None or ads_rej.reason_code != "INVALID_FILENAME":
            print(f"FATAL: ADS did not reject with INVALID_FILENAME: item={ads_item}, rej={ads_rej}", file=sys.stderr)
            return 1
        print(f"[OK] Verified ADS stream rejected as INVALID_FILENAME: {ads_rej.message}")

        print("\n--- Step 4: pai_core_bridge.ingest_folder ---")
        res_folder = pai_core_bridge.ingest_folder(root_dir)
        if not res_folder.items:
            print(f"FATAL: ingest_folder returned 0 items", file=sys.stderr)
            return 1
        print(f"Ingested {len(res_folder.items)} items, rejected {len(res_folder.rejections)} items.")
        print(f"Rejection counts: {res_folder.rejection_counts}")

        # Assert all expected hazard rejection codes are present in the Rust report
        EXPECTED_REJECTION_CODES = [
            "SYMLINK_DIRECTORY",
            "SPECIAL_FILE",
            "INVALID_FILENAME",
            "SECRET_FILE",
            "JUNK_DIRECTORY",
        ]
        for expected_code in EXPECTED_REJECTION_CODES:
            count = res_folder.rejection_counts.get(expected_code, 0)
            if count < 1:
                print(
                    f"FATAL: Expected rejection code '{expected_code}' not found in folder ingest report: "
                    f"{res_folder.rejection_counts}",
                    file=sys.stderr,
                )
                return 1
            print(f"[OK] Verified expected rejection code '{expected_code}' (count={count}) in report.")

        print("\n--- Step 5: Updater.verify_release ---")
        rel_root = tempfile.mkdtemp(prefix="pai_rel_bundle_")
        try:
            trust_dir = os.path.join(rel_root, "trust")
            install_dir = os.path.join(rel_root, "install")
            src_dir = os.path.join(rel_root, "src")
            os.makedirs(trust_dir, exist_ok=True)
            os.makedirs(install_dir, exist_ok=True)
            os.makedirs(src_dir, exist_ok=True)
            trust_cfg = {
                "keys": [{"id": "rel-1", "public_hex": TEST_PUB.hex(), "revoked": False}],
                "constitution_sha256": TEST_CONST_SHA,
            }
            with open(os.path.join(trust_dir, "trust.json"), "w", encoding="utf-8") as f:
                json.dump(trust_cfg, f)

            rel_dir = make_test_release(src_dir, version="0.3.0")
            u = Updater(trust_dir, install_dir)
            vr = u.verify_release(rel_dir)
            if vr.version != "0.3.0":
                print(f"FATAL: verify_release returned unexpected version: {vr.version}", file=sys.stderr)
                return 1
            print(f"Release verification succeeded: version={vr.version}")
        finally:
            shutil.rmtree(rel_root, ignore_errors=True)

        print("\n--- Step 6: pai doctor ---")
        rc_doctor = pai.main(["doctor", "--json"])
        if rc_doctor != 0:
            print(f"FATAL: pai doctor failed with exit code {rc_doctor}", file=sys.stderr)
            return 1

        # 6. Read shadow comparison logs & assert 0 discrepancies
        comps, discreps, disc_list = pai_core_bridge.get_shadow_stats()
        if discreps > 0:
            print("\nFATAL: DISCREPANCIES DETECTED IN SHADOW LOG:", file=sys.stderr)
            for rec in disc_list:
                print(f"  {rec}", file=sys.stderr)
            return 1

        MIN_SHADOW_COMPARISONS = 15
        if comps < MIN_SHADOW_COMPARISONS:
            print(
                f"FATAL: Insufficient shadow comparisons recorded ({comps} < {MIN_SHADOW_COMPARISONS}). "
                f"Parity gate requires at least {MIN_SHADOW_COMPARISONS} operations.",
                file=sys.stderr,
            )
            return 1

        print("\n================================================================================")
        print("                 WINDOWS SHADOW PARITY RUN FINAL REPORT                         ")
        print("================================================================================")
        print(f"Target tree entries        : {total_entries} entries, {total_size/1024:.1f} KB")
        print(f"Total shadow comparisons   : {comps}")
        print(f"Total shadow discrepancies : {discreps}")
        print("Verdict                    : no mismatches observed on this tree")
        print("================================================================================")
        return 0

    finally:
        server.shutdown()
        # Clean up verbatim path files that standard rmtree might fail on
        if 'reserved_verbatim_paths' in locals():
            for vp in reserved_verbatim_paths:
                try:
                    os.remove(vp)
                except Exception:
                    pass
        if 'surrogate_file' in locals():
            try:
                os.remove(surrogate_file)
            except Exception:
                pass
        shutil.rmtree(root_dir, ignore_errors=True)
        if orig_core is not None:
            os.environ["PAI_USE_RUST_CORE"] = orig_core
            pai_core_bridge.PAI_USE_RUST_CORE = (orig_core == "1")
        else:
            os.environ.pop("PAI_USE_RUST_CORE", None)
            pai_core_bridge.PAI_USE_RUST_CORE = False

        if orig_shadow is not None:
            os.environ["PAI_SHADOW_COMPARE"] = orig_shadow
            pai_core_bridge.PAI_SHADOW_COMPARE = (orig_shadow == "1")
        else:
            os.environ.pop("PAI_SHADOW_COMPARE", None)
            pai_core_bridge.PAI_SHADOW_COMPARE = False

        if orig_model_url is not None:
            os.environ["PAI_MODEL_URL"] = orig_model_url
        else:
            os.environ.pop("PAI_MODEL_URL", None)

        if orig_ollama_url is not None:
            os.environ["OLLAMA_BASE_URL"] = orig_ollama_url
        else:
            os.environ.pop("OLLAMA_BASE_URL", None)

        if orig_shadow_log is not None:
            os.environ["PAI_SHADOW_LOG"] = orig_shadow_log
        else:
            os.environ.pop("PAI_SHADOW_LOG", None)

        if orig_telemetry_source is not None:
            os.environ["PAI_TELEMETRY_SOURCE"] = orig_telemetry_source
        else:
            os.environ.pop("PAI_TELEMETRY_SOURCE", None)
        pai_core_bridge.set_telemetry_source("cli")

        try:
            if os.path.exists(runner_shadow_log):
                os.remove(runner_shadow_log)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(run_windows_parity())
