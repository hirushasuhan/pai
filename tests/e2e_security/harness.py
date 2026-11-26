"""Shared isolation, server, updater, and archive fixtures for E2E security tests.

All helpers in this module are self-contained (Python stdlib + defensive runtime
imports from ``research/`` and ``desktop/``) and avoid mutating the user's real
``~/.pai`` directory, hitting live external APIs, or embedding static secret
literals or unfalsifiable security claims.
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import os
import queue
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
RESEARCH_DIR: Path = REPO_ROOT / "research"
DESKTOP_DIR: Path = REPO_ROOT / "desktop"

_MISSING = object()
_PAI_READY_RE = re.compile(r"PAI_BRIDGE_READY\s+(\{.*\})")

_CLOUD_API_ENV_VARS: Tuple[str, ...] = (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "GROQ_API_KEY",
    "CEREBRAS_API_KEY",
    "OPENROUTER_API_KEY",
    "CLOUDFLARE_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "POLLINATIONS_API_KEY",
    "PAI_API_KEY",
    "ANTHROPIC_API_KEY",
)


def ensure_research_on_path() -> Path:
    """Idempotently prepend ``RESEARCH_DIR`` and ``REPO_ROOT`` to ``sys.path``."""
    for candidate in (str(REPO_ROOT), str(RESEARCH_DIR)):
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    return RESEARCH_DIR


def dynamic_secret(prefix: str, suffix: str = "") -> str:
    """Assemble a synthetic secret at runtime so static repo scanners stay clean."""
    return "".join((prefix, suffix))


def make_dummy_token(kind: str) -> str:
    """Build a synthetic token matching runtime secret scanners without static literals.

    Avoids words like ``fake``, ``mock``, or ``placeholder`` so ``ingest.scan_secret_content``
    and ``tools/check_secrets.py`` recognize the runtime string as secret-shaped.
    """
    k = kind.strip().lower()
    if k in ("gemini", "google"):
        return dynamic_secret("".join(("AI", "za")), "SyD9xQ2mK7pL4vR8tW1nZ6cB3fH5jM0qT9X")
    if k in ("openai", "sk"):
        return dynamic_secret("".join(("sk", "-")), "T9xQp2mK7vL4rW8nZ6cB3fH5jM0qT1yR4uV8wX2z")
    if k == "groq":
        return dynamic_secret("".join(("gsk", "_")), "A9xQp2mK7vL4rW8nZ6cB3fH5jM0qT1yR4uV8wX2z7B")
    if k == "github":
        return dynamic_secret("".join(("ghp", "_")), "9xQp2mK7vL4rW8nZ6cB3fH5jM0qT1yR4uV8w")
    if k == "aws":
        return dynamic_secret("".join(("AK", "IA")), "7X9Q2M4P8R1T6W3Z")
    if k == "slack":
        return dynamic_secret("".join(("xoxb", "-")), "1234567890-abcdef123456")
    if k == "pem":
        header = "".join(("-----BEGIN ", "RSA PRIVATE ", "KEY-----"))
        footer = "".join(("-----END ", "RSA PRIVATE ", "KEY-----"))
        return "\n".join((header, "MIIEowIBAAKCAQEA7xTestSyntheticMaterialOnly99", footer))
    raise ValueError(f"Unsupported dummy token kind: {kind!r}")


class IsolatedPaiHome:
    """Context manager isolating ``~/.pai``, ``LOCALAPPDATA``, env vars, and singletons."""

    def __init__(
        self,
        *,
        preserve_api_env: bool = False,
        extra_env: Optional[Dict[str, str]] = None,
    ) -> None:
        self.preserve_api_env = preserve_api_env
        self.extra_env = dict(extra_env or {})
        self.root = Path(tempfile.mkdtemp(prefix="pai_e2e_home_"))
        self.home_dir = self.root / "home"
        self.pai_dir = self.home_dir / ".pai"
        self.memory_dir = self.pai_dir / "memory"
        self.skills_dir = self.pai_dir / "skills"
        self.sessions_dir = self.pai_dir / "sessions"
        self.cowork_dir = self.pai_dir / "cowork"
        self.cowork_tasks_dir = self.cowork_dir / "tasks"
        self.appdata = self.home_dir / "AppData" / "Roaming"
        self.localappdata = self.home_dir / "AppData" / "Local"
        self.install_dir = self.localappdata / "Programs" / "PAI"
        self.ollama_models_dir = self.home_dir / ".ollama" / "models"
        self.projects_dir = self.root / "projects"
        self.shadow_log = self.root / "shadow.jsonl"
        self.team_config = self.pai_dir / "team_config.json"

        for d in (
            self.home_dir,
            self.pai_dir,
            self.memory_dir,
            self.skills_dir,
            self.sessions_dir,
            self.cowork_tasks_dir,
            self.appdata,
            self.install_dir,
            self.ollama_models_dir,
            self.projects_dir,
        ):
            d.mkdir(parents=True, exist_ok=True)

        drive, tail = os.path.splitdrive(str(self.home_dir))
        self.env_overrides: Dict[str, str] = {
            "USERPROFILE": str(self.home_dir),
            "HOME": str(self.home_dir),
            "HOMEDRIVE": drive or "C:",
            "HOMEPATH": tail or str(self.home_dir),
            "APPDATA": str(self.appdata),
            "LOCALAPPDATA": str(self.localappdata),
            "PAI_HOME": str(self.pai_dir),
            "PAI_DIR": str(self.pai_dir),
            "PAI_CONFIG_DIR": str(self.pai_dir),
            "PAI_MEMORY_DIR": str(self.memory_dir),
            "PAI_SKILLS_DIR": str(self.skills_dir),
            "PAI_TEAM_CONFIG": str(self.team_config),
            "PAI_PROJECTS_DIR": str(self.projects_dir),
            "PAI_SHADOW_LOG": str(self.shadow_log),
            "PAI_SHADOW_MARKER": "1",
            "PAI_TELEMETRY_SOURCE": "test",
            "OLLAMA_MODELS": str(self.ollama_models_dir),
        }
        self.env_overrides.update(self.extra_env)

        self._saved_env: Dict[str, Any] = {}
        self._saved_attrs: List[Tuple[Any, str, Any]] = []
        self._entered = False

    @property
    def env(self) -> Dict[str, str]:
        """Return a copy of the isolated environment override dictionary."""
        return dict(self.env_overrides)

    def subprocess_env(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Build a full child-process ``os.environ`` copy with isolation overrides applied."""
        child_env = os.environ.copy()
        if not self.preserve_api_env:
            for k in _CLOUD_API_ENV_VARS:
                child_env.pop(k, None)
        child_env.update(self.env_overrides)
        if extra:
            child_env.update(extra)
        return child_env

    def _save_and_set_attr(self, obj: Any, attr: str, value: Any) -> None:
        if obj is not None and hasattr(obj, attr):
            self._saved_attrs.append((obj, attr, getattr(obj, attr)))
            setattr(obj, attr, value)

    def _patch_loaded_singletons(self) -> None:
        for mod_name in ("quota_engine", "research.quota_engine"):
            mod = sys.modules.get(mod_name)
            cls = getattr(mod, "QuotaLedger", None) if mod else None
            if cls is not None:
                self._save_and_set_attr(cls, "_instance", None)

        for mod_name in ("service_manager", "research.service_manager"):
            mod = sys.modules.get(mod_name)
            cls = getattr(mod, "OllamaServiceManager", None) if mod else None
            if cls is not None:
                self._save_and_set_attr(cls, "_global_instance", None)

        for mod_name in ("bridge_server", "desktop.bridge_server", "research.desktop.bridge_server"):
            mod = sys.modules.get(mod_name)
            if mod is None:
                continue
            self._save_and_set_attr(
                mod,
                "INSTALLED_IMAGE_MODELS_PATH",
                self.pai_dir / "installed_image_models.json",
            )
            cjm = getattr(mod, "_chat_job_manager", None)
            if cjm is not None:
                self._save_and_set_attr(cjm, "sessions_dir", self.sessions_dir)
            amm = getattr(mod, "_auto_memory_mgr", None)
            if amm is not None:
                self._save_and_set_attr(amm, "base_dir", self.memory_dir)
            cfm = getattr(mod, "_connected_folders_mgr", None)
            if cfm is not None:
                self._save_and_set_attr(cfm, "config_path", self.cowork_dir / "connected_folders.json")
            co = getattr(mod, "_cowork_orchestrator", None)
            if co is not None:
                self._save_and_set_attr(co, "storage_dir", self.cowork_tasks_dir)
                fm = getattr(co, "folders_manager", None)
                if fm is not None:
                    self._save_and_set_attr(fm, "config_path", self.cowork_dir / "connected_folders.json")

    def __enter__(self) -> "IsolatedPaiHome":
        if self._entered:
            return self
        self._entered = True

        keys_to_save = set(self.env_overrides.keys())
        if not self.preserve_api_env:
            keys_to_save.update(_CLOUD_API_ENV_VARS)
        for key in keys_to_save:
            self._saved_env[key] = os.environ.get(key, _MISSING)

        if not self.preserve_api_env:
            for key in _CLOUD_API_ENV_VARS:
                os.environ.pop(key, None)
        for key, val in self.env_overrides.items():
            os.environ[key] = val

        self._patch_loaded_singletons()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            for obj, attr, prev in reversed(self._saved_attrs):
                try:
                    setattr(obj, attr, prev)
                except Exception:
                    pass
            self._saved_attrs.clear()

            for key, prev in self._saved_env.items():
                if prev is _MISSING:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = prev
            self._saved_env.clear()
        finally:
            self._entered = False
            shutil.rmtree(self.root, ignore_errors=True)


@dataclass
class BridgeResponse:
    """Structured HTTP response returned by ``BridgeTestServer.request``."""

    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        target = name.lower()
        for k, v in self.headers:
            if k.lower() == target:
                return v
        return default


@dataclass
class RawHTTPResponse:
    """Structured response returned by ``BridgeTestServer.raw_http``."""

    status: int
    reason: str
    headers: Dict[str, str]
    raw_bytes: bytes
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def json(self) -> Any:
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:
            return None

    def get_header(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(name.lower(), default)


_LEGACY_BRIDGE_SHIM = """
import json
import sys
from http.server import ThreadingHTTPServer
from pathlib import Path

desktop_dir = Path(sys.argv[1])
research_dir = Path(sys.argv[2])
repo_root = Path(sys.argv[3])
requested_port = int(sys.argv[4])

for p in (str(desktop_dir), str(research_dir), str(repo_root)):
    if p not in sys.path:
        sys.path.insert(0, p)

import bridge_server

srv = ThreadingHTTPServer(("127.0.0.1", requested_port), bridge_server.PAIBridgeHandler)
print("PAI_BRIDGE_READY " + json.dumps({"port": srv.server_address[1]}), flush=True)
srv.serve_forever()
""".strip()


class BridgeTestServer:
    """Subprocess-isolated ``desktop/bridge_server.py`` runner bound to ``127.0.0.1:0``."""

    def __init__(
        self,
        *,
        isolated_home: Optional[IsolatedPaiHome] = None,
        token: Optional[str] = None,
        port: int = 0,
        extra_env: Optional[Dict[str, str]] = None,
        startup_timeout: float = 10.0,
        require_native_cli: bool = False,
    ) -> None:
        self._external_home = isolated_home
        self._owned_home: Optional[IsolatedPaiHome] = None
        self.home: Optional[IsolatedPaiHome] = isolated_home
        self.token: str = token or secrets.token_urlsafe(32)
        self.requested_port: int = port
        self.extra_env: Dict[str, str] = dict(extra_env or {})
        self.startup_timeout: float = startup_timeout
        self.require_native_cli: bool = require_native_cli

        self.port: int = 0
        self.proc: Optional[subprocess.Popen[str]] = None
        self.stdout_lines: List[str] = []
        self.stderr_lines: List[str] = []
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None

    @staticmethod
    def supports_native_cli() -> bool:
        bridge_path = DESKTOP_DIR / "bridge_server.py"
        if not bridge_path.is_file():
            return False
        text = bridge_path.read_text(encoding="utf-8", errors="replace")
        return "--port" in text and "PAI_BRIDGE_READY" in text

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def __enter__(self) -> "BridgeTestServer":
        native = self.supports_native_cli()
        if self.require_native_cli and not native:
            raise AssertionError(
                "desktop/bridge_server.py does not implement --port / PAI_BRIDGE_READY yet"
            )

        if self._external_home is None:
            self._owned_home = IsolatedPaiHome()
            self._owned_home.__enter__()
            self.home = self._owned_home
        else:
            self.home = self._external_home

        assert self.home is not None
        env = self.home.subprocess_env(
            {
                "PAI_BRIDGE_TOKEN": self.token,
                "PYTHONUNBUFFERED": "1",
                "PYTHONIOENCODING": "utf-8",
                **self.extra_env,
            }
        )

        if native:
            cmd = [
                sys.executable,
                "-u",
                str(DESKTOP_DIR / "bridge_server.py"),
                "--port",
                str(self.requested_port),
            ]
        else:
            cmd = [
                sys.executable,
                "-u",
                "-c",
                _LEGACY_BRIDGE_SHIM,
                str(DESKTOP_DIR),
                str(RESEARCH_DIR),
                str(REPO_ROOT),
                str(self.requested_port),
            ]

        self.proc = subprocess.Popen(
            cmd,
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        line_queue: queue.Queue[Optional[str]] = queue.Queue()

        def _read_stdout() -> None:
            assert self.proc is not None and self.proc.stdout is not None
            try:
                for line in self.proc.stdout:
                    stripped = line.rstrip("\r\n")
                    self.stdout_lines.append(stripped)
                    line_queue.put(stripped)
            finally:
                line_queue.put(None)

        def _drain_stderr() -> None:
            assert self.proc is not None and self.proc.stderr is not None
            for line in self.proc.stderr:
                self.stderr_lines.append(line.rstrip("\r\n"))

        self._stdout_thread = threading.Thread(target=_read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

        deadline = time.monotonic() + self.startup_timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"Timed out waiting {self.startup_timeout}s for PAI_BRIDGE_READY. "
                        f"stdout={self.stdout_lines!r} stderr={self.stderr_lines[-10:]!r}"
                    )
                try:
                    item = line_queue.get(timeout=remaining)
                except queue.Empty as exc:
                    raise TimeoutError(
                        f"Timed out waiting {self.startup_timeout}s for PAI_BRIDGE_READY. "
                        f"stdout={self.stdout_lines!r} stderr={self.stderr_lines[-10:]!r}"
                    ) from exc

                if item is None:
                    rc = self.proc.poll()
                    raise RuntimeError(
                        f"Bridge server exited prematurely with rc={rc}. "
                        f"stdout={self.stdout_lines!r} stderr={self.stderr_lines[-20:]!r}"
                    )
                m = _PAI_READY_RE.search(item)
                if m:
                    payload = json.loads(m.group(1))
                    self.port = int(payload["port"])
                    break
        except Exception:
            self.__exit__(None, None, None)
            raise

        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        try:
            if self.proc is not None:
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=3.0)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=3.0)
                for pipe in (self.proc.stdout, self.proc.stderr):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except Exception:
                            pass
            for t in (self._stdout_thread, self._stderr_thread):
                if t is not None and t.is_alive():
                    t.join(timeout=1.0)
        finally:
            self.proc = None
            if self._owned_home is not None:
                self._owned_home.__exit__(exc_type, exc, tb)
                self._owned_home = None

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: Optional[Dict[str, str]] = None,
        include_token: bool = True,
        timeout: float = 10.0,
    ) -> BridgeResponse:
        """Send an HTTP request to the isolated bridge using ``http.client``."""
        if not self.port:
            raise RuntimeError("BridgeTestServer is not running")

        req_headers: Dict[str, str] = dict(headers or {})
        lower_keys = {k.lower() for k in req_headers}

        if include_token and "x-pai-token" not in lower_keys:
            req_headers["X-PAI-Token"] = self.token

        raw_body: Optional[bytes] = None
        if body is not None:
            if isinstance(body, (dict, list)):
                raw_body = json.dumps(body).encode("utf-8")
                if "content-type" not in lower_keys:
                    req_headers["Content-Type"] = "application/json"
            elif isinstance(body, str):
                raw_body = body.encode("utf-8")
            elif isinstance(body, (bytes, bytearray)):
                raw_body = bytes(body)
            else:
                raise TypeError(f"Unsupported body type: {type(body)!r}")

            if "content-length" not in lower_keys:
                req_headers["Content-Length"] = str(len(raw_body))

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            has_custom_host = "host" in lower_keys
            conn.putrequest(method.upper(), path, skip_host=has_custom_host)
            for k, v in req_headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            if raw_body is not None:
                conn.send(raw_body)
            resp = conn.getresponse()
            resp_body = resp.read()
            return BridgeResponse(
                status=resp.status,
                reason=resp.reason,
                headers=list(resp.getheaders()),
                body=resp_body,
            )
        finally:
            conn.close()

    def raw_http(self, raw_bytes: bytes, timeout: float = 5.0) -> RawHTTPResponse:
        """Send raw HTTP wire bytes over TCP with Windows-safe early-close handling."""
        if not self.port:
            raise RuntimeError("BridgeTestServer is not running")

        with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendall(raw_bytes)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError):
                # Server may respond (e.g. 413) and close before full payload drains on Winsock.
                pass

            buf = bytearray()
            header_end = -1
            content_length: Optional[int] = None

            while True:
                if header_end != -1 and content_length is not None:
                    if len(buf) >= header_end + 4 + content_length:
                        break
                try:
                    chunk = sock.recv(65536)
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                    break
                except socket.timeout:
                    if header_end != -1:
                        break
                    raise
                if not chunk:
                    break
                buf.extend(chunk)
                if header_end == -1:
                    idx = buf.find(b"\r\n\r\n")
                    if idx != -1:
                        header_end = idx
                        head_text = bytes(buf[:header_end]).decode("latin-1", errors="replace")
                        for line in head_text.split("\r\n")[1:]:
                            if ":" in line:
                                hk, hv = line.split(":", 1)
                                if hk.strip().lower() == "content-length":
                                    try:
                                        content_length = int(hv.strip())
                                    except ValueError:
                                        content_length = None

            raw_resp = bytes(buf)
            if header_end == -1:
                return RawHTTPResponse(0, "", {}, raw_resp, b"")

            head_bytes = raw_resp[:header_end]
            body_bytes = raw_resp[header_end + 4 :]
            if content_length is not None and len(body_bytes) > content_length:
                body_bytes = body_bytes[:content_length]

            lines = head_bytes.decode("latin-1", errors="replace").split("\r\n")
            status_line = lines[0] if lines else ""
            parts = status_line.split(" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            reason = parts[2] if len(parts) >= 3 else ""
            hdrs: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    hk, hv = line.split(":", 1)
                    hdrs[hk.strip().lower()] = hv.strip()

            return RawHTTPResponse(
                status=status_code,
                reason=reason,
                headers=hdrs,
                raw_bytes=raw_resp,
                body=body_bytes,
            )


@dataclass
class RecordedRequest:
    """HTTP request captured by ``LocalMockHTTPServer``."""

    method: str
    path: str
    headers: Dict[str, str]
    body: bytes


RouteHandler = Callable[[str, str, Dict[str, str], bytes], Tuple[int, Dict[str, str], bytes]]


class LocalMockHTTPServer:
    """Ephemeral ``127.0.0.1:0`` HTTP server for offline external/SSRF/updater mocking."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._routes: Dict[str, Tuple[int, Dict[str, str], bytes]] = {}
        self._callbacks: Dict[str, RouteHandler] = {}
        self.requests: List[RecordedRequest] = []
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: int = 0

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def add_route(
        self,
        path: str,
        status: int = 200,
        body: Union[bytes, str, Dict[str, Any], List[Any]] = b"",
        headers: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        handler: Optional[RouteHandler] = None,
    ) -> None:
        if handler is not None:
            with self._lock:
                self._callbacks[path] = handler
            return

        hdrs = dict(headers or {})
        if isinstance(body, (dict, list)):
            payload = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", content_type or "application/json; charset=utf-8")
        elif isinstance(body, str):
            payload = body.encode("utf-8")
            hdrs.setdefault("Content-Type", content_type or "text/plain; charset=utf-8")
        else:
            payload = bytes(body)
            if content_type:
                hdrs.setdefault("Content-Type", content_type)

        with self._lock:
            self._routes[path] = (status, hdrs, payload)

    def add_redirect(self, path: str, target_url: str, status: int = 302) -> None:
        self.add_route(
            path,
            status=status,
            body=b"",
            headers={"Location": target_url},
        )

    def __enter__(self) -> "LocalMockHTTPServer":
        parent = self

        class _MockHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                req_body = self.rfile.read(length) if length > 0 else b""
                hdr_map = {k.lower(): v for k, v in self.headers.items()}
                req_path = self.path.split("?", 1)[0]

                with parent._lock:
                    parent.requests.append(
                        RecordedRequest(
                            method=method,
                            path=self.path,
                            headers=hdr_map,
                            body=req_body,
                        )
                    )
                    cb = parent._callbacks.get(self.path) or parent._callbacks.get(req_path)
                    route = parent._routes.get(self.path) or parent._routes.get(req_path)

                if cb is not None:
                    status, resp_hdrs, resp_body = cb(method, self.path, hdr_map, req_body)
                elif route is not None:
                    status, resp_hdrs, resp_body = route
                else:
                    status, resp_hdrs, resp_body = 404, {"Content-Type": "text/plain"}, b"Not Found"

                self.send_response(status)
                for k, v in resp_hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(resp_body)))
                self.end_headers()
                if resp_body:
                    self.wfile.write(resp_body)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_HEAD(self) -> None:
                self._handle("HEAD")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
            finally:
                self._server.server_close()
                self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


_VALID_BUNDLE_VARIANTS = frozenset(
    {
        "valid",
        "tampered_file",
        "tampered_manifest",
        "wrong_key",
        "revoked_key",
        "unsigned",
        "rolled_back",
        "altered_constitution",
        "unlisted_file",
        "symlink_in_zip",
        "path_traversal_in_manifest",
        "path_traversal_in_zip",
    }
)


def build_signed_update_bundle(
    dest_dir: Union[str, Path],
    version: str = "1.5.0",
    files: Optional[Dict[str, bytes]] = None,
    *,
    product: str = "pai-desktop",
    signing_seed: Optional[bytes] = None,
    trust_seed: Optional[bytes] = None,
    constitution_bytes: Optional[bytes] = None,
    trust_constitution_sha256: Optional[str] = None,
    variant: str = "valid",
    key_revoked: bool = False,
    hex_signature: bool = False,
    include_manifest_in_zip: bool = False,
) -> Dict[str, Any]:
    """Create a synthetic Ed25519-signed release directory, trust root, and ZIP bundle."""
    if variant not in _VALID_BUNDLE_VARIANTS:
        raise ValueError(f"Unknown bundle variant: {variant!r}")

    ensure_research_on_path()
    import ed25519_ref
    from updater import MANIFEST, SIGNATURE, build_manifest

    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    trust_dir = dest / "trust"
    release_dir = dest / "release"
    trust_dir.mkdir(parents=True, exist_ok=True)
    release_dir.mkdir(parents=True, exist_ok=True)

    eff_version = "0.1.0" if (variant == "rolled_back" and version == "1.5.0") else version
    t_seed = trust_seed if trust_seed is not None else bytes(range(32))
    t_pub = ed25519_ref.secret_to_public(t_seed)

    if variant == "wrong_key":
        s_seed = bytes(range(1, 33))
    else:
        s_seed = signing_seed if signing_seed is not None else t_seed

    if constitution_bytes is not None:
        c_bytes = constitution_bytes
    else:
        const_path = REPO_ROOT / "docs" / "CONSTITUTION.md"
        c_bytes = const_path.read_bytes() if const_path.is_file() else b"1. Privacy first.\n"

    trust_const_sha = trust_constitution_sha256 or hashlib.sha256(c_bytes).hexdigest()
    trust_doc = {
        "keys": [
            {
                "id": "rel-test-1",
                "public_hex": t_pub.hex(),
                "revoked": bool(key_revoked or variant == "revoked_key"),
            }
        ],
        "constitution_sha256": trust_const_sha,
    }
    trust_json_path = trust_dir / "trust.json"
    trust_json_path.write_text(json.dumps(trust_doc, indent=2), encoding="utf-8")

    payload_files: Dict[str, bytes] = dict(
        files
        if files is not None
        else {
            "VERSION": eff_version.encode("utf-8"),
            "ui/index.html": b"<!doctype html><html><body>PAI</body></html>\n",
            "bridge_server.py": b"# synthetic bridge payload\n",
        }
    )

    first_rel_path: Optional[Path] = None
    for rel, content in payload_files.items():
        target = release_dir / Path(*rel.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        if first_rel_path is None:
            first_rel_path = target

    manifest_const_sha = (
        hashlib.sha256(b"altered constitution").hexdigest()
        if variant == "altered_constitution"
        else trust_const_sha
    )
    manifest_bytes = build_manifest(str(release_dir), product, eff_version, manifest_const_sha)

    if variant == "path_traversal_in_manifest":
        m_doc = json.loads(manifest_bytes.decode("utf-8"))
        m_doc["files"]["../evil.bin"] = {"sha256": "0" * 64, "size": 1}
        manifest_bytes = json.dumps(m_doc, indent=2, sort_keys=True).encode("utf-8")

    sig_raw = ed25519_ref.sign(s_seed, manifest_bytes)
    sig_payload = (sig_raw.hex() + "\n").encode("ascii") if hex_signature else sig_raw

    manifest_dest = dest / MANIFEST
    manifest_rel = release_dir / MANIFEST
    manifest_dest.write_bytes(manifest_bytes)
    manifest_rel.write_bytes(manifest_bytes)

    sig_dest: Optional[Path] = None
    if variant != "unsigned":
        sig_dest = dest / SIGNATURE
        sig_rel = release_dir / SIGNATURE
        sig_dest.write_bytes(sig_payload)
        sig_rel.write_bytes(sig_payload)

    if variant == "tampered_file" and first_rel_path is not None:
        first_rel_path.write_bytes(first_rel_path.read_bytes() + b"TAMPERED")
    elif variant == "tampered_manifest":
        tampered_m = manifest_bytes + b" "
        manifest_dest.write_bytes(tampered_m)
        manifest_rel.write_bytes(tampered_m)
    elif variant == "unlisted_file":
        (release_dir / "extra_unlisted.dll").write_bytes(b"unlisted")

    zip_path = dest / f"pai-payload-{eff_version}-win-x64.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(payload_files.keys()):
            src = release_dir / Path(*rel.split("/"))
            zf.write(src, arcname=rel)
        if variant == "unlisted_file":
            zf.write(release_dir / "extra_unlisted.dll", arcname="extra_unlisted.dll")
        if include_manifest_in_zip:
            zf.write(manifest_rel, arcname=MANIFEST)
            if sig_dest is not None:
                zf.write(release_dir / SIGNATURE, arcname=SIGNATURE)
        if variant == "symlink_in_zip":
            zi = zipfile.ZipInfo("evil_link.txt")
            zi.create_system = 3
            zi.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(zi, "../../outside.txt")
        if variant == "path_traversal_in_zip":
            zf.writestr("../../evil.txt", b"escaped payload")

    return {
        "dest_dir": dest,
        "trust_dir": trust_dir,
        "trust_json": trust_json_path,
        "release_dir": release_dir,
        "zip_path": zip_path,
        "manifest_path": manifest_dest,
        "signature_path": sig_dest,
        "version": eff_version,
        "public_hex": t_pub.hex(),
        "constitution_sha256": trust_const_sha,
    }


def make_zip_bomb_bytes(
    entry_name: str = "word/document.xml",
    uncompressed_size: int = 12 * 1024 * 1024,
) -> bytes:
    """Create a valid, highly compressed OOXML/ZIP fixture exceeding decompression caps."""
    filler = b"A" * uncompressed_size
    if entry_name == "word/document.xml":
        payload = (
            b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b"<w:body><w:p><w:t>" + filler + b"</w:t></w:p></w:body></w:document>"
        )
    elif entry_name == "xl/sharedStrings.xml":
        payload = b"<sst><si><t>" + filler + b"</t></si></sst>"
    else:
        payload = filler

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(entry_name, payload)
    return buf.getvalue()


def make_zlib_bomb_pdf_bytes(uncompressed_size: int = 12 * 1024 * 1024) -> bytes:
    """Create a syntactically valid PDF with a FlateDecode stream exceeding 10 MiB."""
    inner = b"BT (" + (b"A" * uncompressed_size) + b") Tj ET"
    compressed = zlib.compress(inner, level=9)
    return (
        b"%PDF-1.4\n1 0 obj\n<< /Length "
        + str(len(compressed)).encode("ascii")
        + b" /Filter /FlateDecode >>\nstream\n"
        + compressed
        + b"\nendstream\nendobj\n%%EOF\n"
    )


def make_symlink_zip_bytes(
    link_name: str = "evil_link.txt",
    target_path: str = "../../outside.txt",
    extra_files: Optional[Dict[str, bytes]] = None,
) -> bytes:
    """Create a ZIP archive containing an Info-ZIP Unix symlink entry (``S_IFLNK``)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if extra_files:
            for name, content in extra_files.items():
                zf.writestr(name, content)
        zi = zipfile.ZipInfo(link_name)
        zi.create_system = 3
        zi.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(zi, target_path)
    return buf.getvalue()


def _load_claims_lint() -> Tuple[re.Pattern[str], set[str]]:
    claims_path = RESEARCH_DIR / "tests" / "test_claims.py"
    ensure_research_on_path()
    spec = importlib.util.spec_from_file_location("_pai_claims_lint", str(claims_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load claims lint from {claims_path}")
    mod = importlib.util.module_from_spec(spec)
    # test_claims imports _bootstrap from research/tests
    tests_dir = str(RESEARCH_DIR / "tests")
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    spec.loader.exec_module(mod)
    return mod.BANNED, set(getattr(mod, "SKIP_DIRS", ()))


def assert_no_unfalsifiable_claims_compliant(
    paths: Union[str, Path, Sequence[Union[str, Path]], Iterable[Union[str, Path]]],
) -> None:
    """Assert that given files/directories contain zero ``test_claims.py`` ``BANNED`` matches."""
    banned_re, skip_dirs = _load_claims_lint()
    if isinstance(paths, (str, Path)):
        items: List[Path] = [Path(paths)]
    else:
        items = [Path(p) for p in paths]

    offenders: List[str] = []
    exts = (".md", ".py", ".rs", ".cpp", ".h", ".toml", ".txt")

    def _scan_file(fpath: Path) -> None:
        if fpath.name == "test_claims.py" or fpath.suffix.lower() not in exts:
            return
        with fpath.open("r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                if banned_re.search(line) and "claims-lint: quote" not in line:
                    offenders.append(f"{fpath}:{lineno}: {line.strip()[:110]}")

    for item in items:
        if item.is_file():
            _scan_file(item)
        elif item.is_dir():
            for dirpath, dirnames, filenames in os.walk(item):
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for fn in filenames:
                    _scan_file(Path(dirpath) / fn)
        else:
            raise FileNotFoundError(f"Claims check target does not exist: {item}")

    if offenders:
        raise AssertionError("Unfalsifiable security claims detected:\n" + "\n".join(offenders))
