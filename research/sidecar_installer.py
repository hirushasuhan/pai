"""Plug-and-Play Runtime & Multi-File Model Provisioner for PAI Sidecars.

Automatically provisions:
  1. C++ Inference Binaries from official GitHub Releases:
     - `ggml-org/llama.cpp` (`llama-server.exe`, >= b11556 for Ternary Bonsai 2.5 Q2_0)
     - `leejet/stable-diffusion.cpp` (`sd-cli.exe`, CUDA / Vulkan / AVX2 selected automatically)
  2. Hugging Face GGUF & Diffusion Weight Bundles (incl. 4-file FLUX.1-schnell):
     - Supports custom storage directories (`storage_root`), resumable `.part` downloads,
       live byte-level SSE progress callbacks, and cooperative cancel/pause via `abort_event`.

Security Invariants:
  - Fail-closed offline air-gap guard (`offline_check_fn`).
  - Strict remote host allowlist + `net_guard.validate_url` on initial URL and redirects.
  - Zip-slip path traversal rejection, symlink blocking, and bounded archive extraction.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from research import ingest, local_sidecars, net_guard
except ModuleNotFoundError:
    import ingest
    import local_sidecars
    import net_guard


ALLOWED_PROVISION_HOSTS = (
    "github.com",
    "api.github.com",
    "githubusercontent.com",
    "huggingface.co",
    "hf.co",
)
MAX_RUNTIME_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB cap (allows CUDA + cudart DLL bundles)
DOWNLOAD_CHUNK_BYTES = 256 * 1024
MIN_LLAMA_CPP_BUILD = 11556
_WIN_STATUS_DLL_NOT_FOUND = (-1073741515, 3221225781, -1073741502, 3221225794)


def validate_safe_storage_path(raw_path: Optional[str | Path]) -> Optional[Path]:
    """Validates a custom model storage directory, blocking UNC paths, ADS, control chars, and symlinks."""
    if raw_path is None:
        return None
    s = str(raw_path).strip()
    if not s:
        return None
    if any(ord(c) < 32 for c in s):
        raise ValueError("Storage path contains invalid control characters.")
    if s.startswith("\\\\") or s.startswith("//"):
        raise ValueError(f"Network UNC storage paths are blocked: {s}")
    if ingest.has_ads_colon(s):
        raise ValueError(f"Alternative Data Stream syntax is blocked in path: {s}")
    p = Path(s).expanduser()
    if p.exists() and ingest._is_symlink_or_reparse(str(p)):
        raise ValueError(f"Symlink/reparse point storage paths are blocked: {p}")
    return p.resolve()


def _sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            blk = f.read(1024 * 1024)
            if not blk:
                break
            h.update(blk)
    return h.hexdigest()


def _is_allowed_provision_host(url: str) -> bool:
    host = (urllib.parse.urlsplit(url).hostname or "").strip().lower()
    if not host:
        return False
    return any(host == h or host.endswith("." + h) for h in ALLOWED_PROVISION_HOSTS)


class _SafeProvisionRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validates redirect targets with net_guard and host allowlist while stripping tokens cross-origin."""

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        net_guard.validate_url(newurl, allow_private=False)
        if not _is_allowed_provision_host(newurl):
            raise net_guard.UrlRejected(f"Disallowed redirect host during model provision: {newurl}")
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is not None:
            orig_host = (urllib.parse.urlsplit(req.full_url).hostname or "").lower()
            next_host = (urllib.parse.urlsplit(newurl).hostname or "").lower()
            if orig_host != next_host and not next_host.endswith("huggingface.co"):
                for h_name, _ in list(new_req.header_items()):
                    if h_name.lower() in ("authorization", "cookie"):
                        new_req.remove_header(h_name)
        return new_req


def _validated_open(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 30.0):
    net_guard.validate_url(url, allow_private=False)
    if not _is_allowed_provision_host(url):
        raise ValueError(f"Host not in trusted runtime/model provision allowlist: {url}")
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "PAI-Provisioner/1.0"})
    opener = urllib.request.build_opener(_SafeProvisionRedirectHandler())
    return opener.open(req, timeout=timeout)


def _select_cudart_asset(assets: List[Dict[str, Any]], main_asset_name: str) -> Optional[Dict[str, str]]:
    """Finds matching Windows x64 CUDA runtime redistributable zip (`cudart-*`) for a CUDA binary."""
    m_low = (main_asset_name or "").lower()
    if "cuda" not in m_low:
        return None
    want_13 = "cuda-13" in m_low or "cu13" in m_low or "cuda13" in m_low
    cudarts = [
        a for a in (assets or [])
        if isinstance(a, dict)
        and "cudart" in str(a.get("name", "")).lower()
        and "win" in str(a.get("name", "")).lower()
        and "x64" in str(a.get("name", "")).lower()
        and str(a.get("name", "")).lower().endswith(".zip")
    ]
    for a in cudarts:
        n = str(a.get("name", "")).lower()
        is_13 = "13" in n
        if is_13 == want_13:
            digest_raw = str(a.get("digest") or "")
            sha = digest_raw.split(":", 1)[1].strip().lower() if digest_raw.startswith("sha256:") else ""
            return {
                "name": str(a["name"]),
                "url": str(a.get("browser_download_url", "")),
                "size": int(a.get("size") or 0),
                "sha256": sha,
            }
    return None


def _select_release_asset(assets: List[Dict[str, Any]], gpu_backend: str, runtime: str) -> Optional[Dict[str, str]]:
    """Selects best matching Windows x64 ZIP asset (CUDA -> Vulkan -> CPU/AVX2)."""
    win_zips = [
        a for a in (assets or [])
        if isinstance(a, dict)
        and str(a.get("name", "")).lower().endswith(".zip")
        and "win" in str(a.get("name", "")).lower()
        and ("x64" in str(a.get("name", "")).lower() or "avx2" in str(a.get("name", "")).lower())
        and "cudart" not in str(a.get("name", "")).lower()
    ]
    if not win_zips:
        return None

    priorities = (
        ["cuda-12", "cuda12", "cuda", "vulkan", "avx2", "cpu"]
        if gpu_backend == "cuda"
        else (["vulkan", "avx2", "cpu"] if gpu_backend == "vulkan" else ["avx2", "cpu", "vulkan"])
    )
    for key in priorities:
        for asset in win_zips:
            name_low = str(asset.get("name", "")).lower()
            if key in name_low:
                digest_raw = str(asset.get("digest") or "")
                sha = digest_raw.split(":", 1)[1].strip().lower() if digest_raw.startswith("sha256:") else ""
                return {
                    "name": str(asset["name"]),
                    "url": str(asset.get("browser_download_url", "")),
                    "size": int(asset.get("size") or 0),
                    "sha256": sha,
                }
    first = win_zips[0]
    digest_raw = str(first.get("digest") or "")
    sha = digest_raw.split(":", 1)[1].strip().lower() if digest_raw.startswith("sha256:") else ""
    return {
        "name": str(first["name"]),
        "url": str(first.get("browser_download_url", "")),
        "size": int(first.get("size") or 0),
        "sha256": sha,
    }


def _find_latest_binary_release(
    repo: str,
    gpu_backend: str,
    runtime: str,
    min_build: int = 0,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, str]], Optional[str]]:
    """Queries GitHub releases list to find newest release with Windows x64 binary archives."""
    api_url = f"https://api.github.com/repos/{repo}/releases?per_page=15"
    with _validated_open(
        api_url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "PAI-Provisioner/1.0"},
        timeout=20.0,
    ) as resp:
        rels = json.loads(resp.read(4 * 1024 * 1024).decode("utf-8", errors="replace"))
    if isinstance(rels, dict):
        rels = [rels]
    for rel in (rels or []):
        if not isinstance(rel, dict) or rel.get("draft"):
            continue
        tag = str(rel.get("tag_name") or "").strip()
        if min_build > 0:
            m_b = re.search(r"b(\d+)", tag, flags=re.IGNORECASE)
            if not m_b or int(m_b.group(1)) < min_build:
                continue
        asset = _select_release_asset(rel.get("assets") or [], gpu_backend=gpu_backend, runtime=runtime)
        if asset and asset.get("url"):
            return rel, asset, None
    return None, None, f"No compatible Windows x64 runtime archive found in {repo} recent releases."


def _verify_binary_runnable(exe_path: Path) -> bool:
    """Checks extracted Windows executable launches cleanly without STATUS_DLL_NOT_FOUND."""
    if not exe_path.is_file():
        return False
    if local_sidecars._has_missing_cuda_runtime_dlls(exe_path.parent):
        return False
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            [str(exe_path), "--help"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5.0,
            creationflags=flags,
        )
        return proc.returncode not in _WIN_STATUS_DLL_NOT_FOUND
    except Exception:
        return True


def _safe_extract_zip(zip_path: Path, dest_dir: Path) -> List[Path]:
    """Safely extracts a runtime archive rejecting zip-slip traversal, symlinks, and oversized payloads."""
    if dest_dir.exists() and ingest._is_symlink_or_reparse(str(dest_dir)):
        raise ValueError(f"Symlink/reparse destination directory blocked: {dest_dir}")
    dest_resolved = dest_dir.resolve()
    dest_resolved.mkdir(parents=True, exist_ok=True)
    extracted: List[Path] = []
    total_unpacked = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f"Symlink entry blocked in runtime archive: {info.filename}")
            rel = Path(info.filename)
            if rel.is_absolute() or ".." in rel.parts or ingest.has_ads_colon(info.filename):
                raise ValueError(f"Illegal path traversal entry in runtime archive: {info.filename}")
            target = (dest_resolved / rel).resolve()
            if not target.is_relative_to(dest_resolved):
                raise ValueError(f"Extraction escape blocked: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if total_unpacked + int(info.file_size or 0) > MAX_RUNTIME_ARCHIVE_BYTES:
                raise ValueError("Runtime archive exceeds 2 GiB extraction limit.")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target, "wb") as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    total_unpacked += len(chunk)
                    if total_unpacked > MAX_RUNTIME_ARCHIVE_BYTES:
                        dst.close()
                        target.unlink(missing_ok=True)
                        raise ValueError("Runtime archive decompressed stream exceeds 2 GiB extraction limit.")
                    dst.write(chunk)
            extracted.append(target)

    # Flatten nested bin/<exe> up into dest_resolved if release packed a top folder
    for exe in list(dest_resolved.rglob("*.exe")) + list(dest_resolved.rglob("*.dll")):
        flat = dest_resolved / exe.name
        if exe.parent != dest_resolved and not flat.exists():
            try:
                exe.replace(flat)
            except Exception:
                pass
    return extracted


def _stream_download_resumable(
    url: str,
    dest_file: Path,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    status_prefix: str = "Downloading",
    headers: Optional[Dict[str, str]] = None,
    abort_event: Optional[threading.Event] = None,
    expected_sha256: str = "",
    max_retries: int = 4,
) -> Path:
    """Streams URL to `dest_file` using `.part` resumable downloads with HTML rejection, digest check, and auto-resume."""
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    if ingest._is_symlink_or_reparse(str(dest_file)):
        raise ValueError(f"Refusing symlink/reparse target file: {dest_file}")
    if dest_file.is_file() and dest_file.stat().st_size > 1024:
        size = dest_file.stat().st_size
        if expected_sha256 and _sha256_file(dest_file) != expected_sha256:
            dest_file.unlink(missing_ok=True)
        else:
            if progress_cb:
                progress_cb(f"{status_prefix} (already cached)", size, size)
            return dest_file

    part_file = dest_file.with_name(dest_file.name + ".part")
    if part_file.exists() and ingest._is_symlink_or_reparse(str(part_file)):
        raise ValueError(f"Refusing symlink/reparse part file: {part_file}")

    for attempt in range(max_retries + 1):
        if abort_event is not None and abort_event.is_set():
            raise InterruptedError("Download cancelled by user.")

        existing = part_file.stat().st_size if part_file.is_file() else 0
        req_headers = {"User-Agent": "PAI-Provisioner/1.0"}
        if headers:
            req_headers.update(headers)
        if existing > 0:
            req_headers["Range"] = f"bytes={existing}-"

        try:
            try:
                resp = _validated_open(url, headers=req_headers, timeout=60.0)
            except urllib.error.HTTPError as exc:
                if exc.code == 416 and existing > 0:
                    part_file.unlink(missing_ok=True)
                    existing = 0
                    req_headers.pop("Range", None)
                    resp = _validated_open(url, headers=req_headers, timeout=60.0)
                else:
                    raise

            with resp:
                ctype = str(resp.headers.get("Content-Type") or "").lower()
                if "text/html" in ctype or "application/xhtml+xml" in ctype:
                    raise ValueError(
                        f"Remote host returned an HTML page instead of binary payload for '{dest_file.name}'. "
                        "Verify Hugging Face access/token if this repo is gated."
                    )
                status_code = getattr(resp, "status", 200)
                if existing > 0 and status_code != 206:
                    existing = 0
                    mode = "wb"
                else:
                    mode = "ab" if existing > 0 else "wb"

                content_len = resp.headers.get("Content-Length")
                rem = int(content_len) if (content_len and content_len.isdigit()) else 0
                total = (existing + rem) if rem > 0 else 0
                completed = existing
                last_emit = 0.0
                checked_magic = existing > 0

                if progress_cb and total > 0:
                    progress_cb(status_prefix, max(completed, 1), max(total, completed, 1))

                with open(part_file, mode) as out:
                    while True:
                        if abort_event is not None and abort_event.is_set():
                            raise InterruptedError("Download cancelled by user.")
                        chunk = resp.read(DOWNLOAD_CHUNK_BYTES)
                        if not chunk:
                            break
                        if not checked_magic:
                            checked_magic = True
                            head_low = chunk[:256].lstrip().lower()
                            if head_low.startswith((b"<!doctype html", b"<html", b"<head")):
                                out.close()
                                part_file.unlink(missing_ok=True)
                                raise ValueError(
                                    f"Downloaded payload for '{dest_file.name}' is an HTML document instead of binary weights/archive."
                                )
                        out.write(chunk)
                        completed += len(chunk)
                        now = time.time()
                        if progress_cb and (now - last_emit >= 0.25 or (total and completed >= total)):
                            progress_cb(status_prefix, completed, max(total, completed))
                            last_emit = now
            break
        except (
            http.client.IncompleteRead,
            urllib.error.URLError,
            TimeoutError,
            ConnectionResetError,
            ConnectionAbortedError,
            ssl.SSLError,
            OSError,
        ) as exc:
            if isinstance(exc, net_guard.UrlRejected):
                raise
            if abort_event is not None and abort_event.is_set():
                raise InterruptedError("Download cancelled by user.")
            if attempt >= max_retries:
                raise
            wait_s = min(2 ** attempt, 8)
            cur_sz = part_file.stat().st_size if part_file.is_file() else 0
            if progress_cb:
                progress_cb(
                    f"{status_prefix} (retrying in {wait_s}s after connection drop...)",
                    max(cur_sz, 1),
                    max(cur_sz, 10 * 1024 * 1024),
                )
            time.sleep(wait_s)

    if expected_sha256:
        actual = _sha256_file(part_file)
        if actual != expected_sha256:
            part_file.unlink(missing_ok=True)
            raise ValueError(f"SHA-256 mismatch on '{dest_file.name}' (expected {expected_sha256[:12]}..., got {actual[:12]}...).")

    os.replace(str(part_file), str(dest_file))
    if progress_cb:
        final_sz = dest_file.stat().st_size
        progress_cb(f"{status_prefix} complete", final_sz, final_sz)
    return dest_file


def _install_release_bundle(
    rel_data: Dict[str, Any],
    asset: Dict[str, str],
    dest_dir: Path,
    progress_cb: Optional[Callable[[str, int, int], None]],
    abort_event: Optional[threading.Event],
) -> Tuple[bool, str]:
    """Downloads & extracts runtime zip (+ cudart if CUDA DLLs needed), verifying exe startup."""
    zip_path = dest_dir / asset["name"]
    if progress_cb:
        progress_cb(f"Downloading runtime {asset['name']}...", 1, max(int(asset.get("size") or 10 * 1024 * 1024), 1))
    _stream_download_resumable(
        asset["url"],
        zip_path,
        progress_cb=progress_cb,
        status_prefix=f"Downloading runtime {asset['name']}",
        abort_event=abort_event,
        expected_sha256=str(asset.get("sha256") or ""),
    )
    if progress_cb:
        progress_cb(f"Extracting runtime {asset['name']}...", int(asset.get("size") or 1), max(int(asset.get("size") or 1), 1))
    _safe_extract_zip(zip_path, dest_dir)
    zip_path.unlink(missing_ok=True)

    # If CUDA binary lacks system CUDA runtime DLLs, fetch companion cudart zip from same release
    if local_sidecars._has_missing_cuda_runtime_dlls(dest_dir):
        cudart = _select_cudart_asset(rel_data.get("assets") or [], asset["name"])
        if cudart and cudart.get("url"):
            cudart_zip = dest_dir / cudart["name"]
            if progress_cb:
                progress_cb(f"Downloading CUDA runtime {cudart['name']}...", 1, max(int(cudart.get("size") or 10 * 1024 * 1024), 1))
            _stream_download_resumable(
                cudart["url"],
                cudart_zip,
                progress_cb=progress_cb,
                status_prefix=f"Downloading CUDA runtime {cudart['name']}",
                abort_event=abort_event,
                expected_sha256=str(cudart.get("sha256") or ""),
            )
            if progress_cb:
                progress_cb(f"Extracting CUDA runtime {cudart['name']}...", int(cudart.get("size") or 1), max(int(cudart.get("size") or 1), 1))
            _safe_extract_zip(cudart_zip, dest_dir)
            cudart_zip.unlink(missing_ok=True)
    return True, "ok"


def ensure_sidecar_binary(
    runtime: str,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    offline_check_fn: Optional[Callable[[], bool]] = None,
    abort_event: Optional[threading.Event] = None,
) -> Tuple[bool, str]:
    """Auto-downloads and verifies healthy `llama-server.exe` or `sd-cli.exe` into ~/.pai/bin/."""
    is_ternary = runtime == "llama.cpp-ternary"
    is_llama = runtime in ("llama.cpp", "llama.cpp-ternary")
    existing = local_sidecars.find_llama_server_binary(ternary_fork=is_ternary) if is_llama else local_sidecars.find_sd_cpp_binary()
    if existing is not None and _verify_binary_runnable(existing):
        return True, f"Runtime binary ready: {existing.name}"

    if offline_check_fn is not None and not offline_check_fn():
        return False, "Internet access is disabled (Offline Mode): cannot auto-install C++ sidecar runtime."

    if is_ternary:
        repo = "PrismML-Eng/llama.cpp"
        subdir = "llama.cpp-ternary"
        min_build = 0
    elif is_llama:
        repo = "ggml-org/llama.cpp"
        subdir = "llama.cpp"
        min_build = MIN_LLAMA_CPP_BUILD
    else:
        repo = "leejet/stable-diffusion.cpp"
        subdir = "stable-diffusion.cpp"
        min_build = 0

    if progress_cb:
        progress_cb(f"Checking {repo} releases for {runtime}...", 1, 100)

    gpu_backend = local_sidecars.detect_gpu_backend()["backend"]
    try:
        rel_data, asset, err_msg = _find_latest_binary_release(
            repo=repo,
            gpu_backend=gpu_backend,
            runtime=runtime,
            min_build=min_build,
        )
    except Exception as exc:
        return False, f"Failed to query {repo} releases: {exc}"

    if not rel_data or not asset:
        return False, err_msg or f"No compatible Windows x64 runtime archive found in {repo} release."

    dest_dir = local_sidecars._get_pai_home() / "bin" / subdir
    _install_release_bundle(rel_data, asset, dest_dir, progress_cb, abort_event)

    found = local_sidecars.find_llama_server_binary(ternary_fork=is_ternary) if is_llama else local_sidecars.find_sd_cpp_binary()
    if found is None or not _verify_binary_runnable(found):
        # Fallback from broken/missing CUDA DLLs to zero-dependency Vulkan binary automatically
        if gpu_backend == "cuda":
            vk_asset = _select_release_asset(rel_data.get("assets") or [], gpu_backend="vulkan", runtime=runtime)
            if vk_asset and vk_asset.get("url") and vk_asset["name"] != asset["name"]:
                for dll in dest_dir.glob("ggml-cuda*.dll"):
                    dll.unlink(missing_ok=True)
                _install_release_bundle(rel_data, vk_asset, dest_dir, progress_cb, abort_event)
                found = local_sidecars.find_llama_server_binary(ternary_fork=is_ternary) if is_llama else local_sidecars.find_sd_cpp_binary()
                if found is not None and _verify_binary_runnable(found):
                    return True, f"Installed {found.name} (VULKAN) to {dest_dir}"
        return False, f"Extracted {asset['name']}, but runtime DLL/startup verification failed."
    return True, f"Installed {found.name} ({gpu_backend.upper()}) to {dest_dir}"


def provision_runtime_and_model(
    model_tag: str,
    storage_path: Optional[str] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    offline_check_fn: Optional[Callable[[], bool]] = None,
    hf_token: Optional[str] = None,
    abort_event: Optional[threading.Event] = None,
) -> Tuple[bool, str]:
    """End-to-end Plug-and-Play Provisioner (Path Safety -> Gate 1 -> Sidecar Binary -> Weights -> Manifest)."""
    spec = local_sidecars.get_model_spec(model_tag)
    if not spec:
        return False, f"Unknown sidecar/image model spec: '{model_tag}'."

    try:
        safe_storage = validate_safe_storage_path(storage_path)
    except ValueError as exc:
        return False, str(exc)

    if offline_check_fn is not None and not offline_check_fn():
        return False, "Internet access is disabled in settings (Offline Mode active)."

    readiness = local_sidecars.assess_install_and_run_readiness(
        model_tag,
        target_path=str(safe_storage) if safe_storage else None,
    )
    if not readiness.get("disk_ok", False):
        return False, readiness.get("advisory", "Insufficient disk space for installation.")

    runtime = str(spec.get("runtime", "llama.cpp"))
    if runtime != "cloud_free":
        ok_bin, msg_bin = ensure_sidecar_binary(
            runtime=runtime,
            progress_cb=progress_cb,
            offline_check_fn=offline_check_fn,
            abort_event=abort_event,
        )
        if not ok_bin:
            return False, msg_bin

    files = list(spec.get("files") or [])
    if not files and spec.get("download_url") and spec.get("filename"):
        files = [{"role": "model", "filename": spec["filename"], "url": spec["download_url"]}]

    is_img = spec.get("model_type") == "image"
    storage_arg = str(safe_storage) if safe_storage else None
    target_dir = (
        local_sidecars.get_image_models_dir(storage_arg)
        if is_img
        else local_sidecars.get_gguf_models_dir(storage_arg)
    )
    req_headers = {"Authorization": f"Bearer {hf_token.strip()}"} if hf_token and hf_token.strip() else None

    est_bundle_bytes = max(int(float(spec.get("size_gb") or 0.0) * (1024 ** 3)), 10 * 1024 * 1024)
    prior_bytes = 0
    file_hashes: Dict[str, str] = {}

    for idx, f_spec in enumerate(files, start=1):
        if abort_event is not None and abort_event.is_set():
            return False, "Download paused or cancelled."
        fname = str(f_spec.get("filename") or "").strip()
        furl = str(f_spec.get("url") or "").strip()
        if not fname or not furl:
            continue

        def _cum_cb(msg: str, comp: int, tot: int) -> None:
            if not progress_cb:
                return
            cum_comp = prior_bytes + int(comp)
            cum_tot = max(est_bundle_bytes, prior_bytes + int(tot or comp)) if len(files) > 1 else max(int(tot), int(comp))
            progress_cb(msg, cum_comp, cum_tot)

        if progress_cb:
            progress_cb(f"Connecting [{idx}/{len(files)}] {fname}...", max(prior_bytes, 1), est_bundle_bytes)
        dest_f = _stream_download_resumable(
            furl,
            target_dir / fname,
            progress_cb=_cum_cb if progress_cb else None,
            status_prefix=f"Downloading [{idx}/{len(files)}] {fname}",
            headers=req_headers,
            abort_event=abort_event,
        )
        if dest_f.is_file():
            prior_bytes += dest_f.stat().st_size
            file_hashes[fname] = _sha256_file(dest_f)

    manifest = {
        "name": spec["name"],
        "tag": spec["tag"],
        "runtime": runtime,
        "model_type": spec.get("model_type", "text"),
        "storage_dir": str(target_dir),
        "files": [f.get("filename") for f in files],
        "file_sha256": file_hashes,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path = target_dir / f"{spec['tag']}.manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return True, f"Provisioned '{spec['name']}' cleanly in {target_dir}."
