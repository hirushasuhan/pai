"""Lightweight, pure-stdlib computer and browser automation for PAI Shell.

Handles natural-language (English and Singlish) and slash-command desktop/web
automation without third-party GUI dependencies or ctypes imports:
  - AI-drafted (or offline-template) email composition in Gmail / Outlook / mailto:
  - Google and YouTube searches in the default web browser
  - Opening common web apps, URLs, and user folders (Downloads, Desktop, Documents)
  - Launching safe allowlisted desktop applications (e.g. Notepad, Calculator)
  - Typing/pasting text into Notepad via safe PowerShell stdin + clipboard
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_URL_RE = re.compile(r"\b((?:https?://|www\.)[^\s<>'\"]+)\b", re.IGNORECASE)

_WEB_SHORTCUTS: Dict[str, str] = {
    "gmail": "https://mail.google.com/",
    "mail": "https://mail.google.com/",
    "youtube": "https://www.youtube.com/",
    "yt": "https://www.youtube.com/",
    "google": "https://www.google.com/",
    "github": "https://github.com/",
    "drive": "https://drive.google.com/",
    "google drive": "https://drive.google.com/",
    "calendar": "https://calendar.google.com/",
    "maps": "https://maps.google.com/",
    "google maps": "https://maps.google.com/",
    "translate": "https://translate.google.com/",
    "whatsapp": "https://web.whatsapp.com/",
    "chatgpt": "https://chatgpt.com/",
    "outlook": "https://outlook.live.com/mail/",
    "docs": "https://docs.google.com/",
    "sheets": "https://sheets.google.com/",
}

# Strict allowlist of safe user-facing desktop applications (no shell=True).
_APP_ALLOWLIST: Dict[str, Tuple[str, List[str]]] = {
    "notepad": ("Notepad", ["notepad.exe"]),
    "note pad": ("Notepad", ["notepad.exe"]),
    "calculator": ("Calculator", ["calc.exe"]),
    "calc": ("Calculator", ["calc.exe"]),
    "paint": ("Paint", ["mspaint.exe"]),
    "mspaint": ("Paint", ["mspaint.exe"]),
    "explorer": ("File Explorer", ["explorer.exe"]),
    "file explorer": ("File Explorer", ["explorer.exe"]),
    "task manager": ("Task Manager", ["taskmgr.exe"]),
    "taskmgr": ("Task Manager", ["taskmgr.exe"]),
    "settings": ("Windows Settings", ["explorer.exe", "ms-settings:"]),
    "vscode": ("VS Code", ["code"]),
    "vs code": ("VS Code", ["code"]),
    "terminal": ("Windows Terminal", ["wt.exe"]),
    "powershell": ("PowerShell", ["powershell.exe"]),
}

_FOLDER_MAP: Dict[str, str] = {
    "downloads": "Downloads",
    "download": "Downloads",
    "desktop": "Desktop",
    "documents": "Documents",
    "document": "Documents",
    "pictures": "Pictures",
    "music": "Music",
    "videos": "Videos",
}

_CODE_OR_QUESTION_GUARD = (
    "what is ",
    "how to ",
    "how does ",
    "explain ",
    "define ",
    "index.html",
    "script.js",
    "style.css",
    ".py",
    ".js",
    ".html",
    ".css",
    ".json",
)


def _emit(stream: Any, msg: str) -> None:
    if stream is None:
        return
    try:
        stream.write(msg + "\n")
        stream.flush()
    except Exception:
        pass


def format_automation_help() -> str:
    """Return concise help text for /auto and /mail commands."""
    return (
        "Computer & Browser Automation (/auto, /mail):\n"
        "  /mail <recipient/topic>   - Draft email and open Gmail/Outlook compose with To, Subject & Body\n"
        "  /auto <instruction>       - Automate browser search, web apps, folders, Notepad typing, or safe apps\n"
        "Examples:\n"
        "  mail ekak danna john@example.com ta meeting eka postpone karanna kiyala\n"
        "  youtube eke python tutorial search karanna\n"
        "  notepad open karala Hello Hirusha type karanna\n"
        "  open calculator | open downloads | copy Hello World to clipboard\n"
        "Allowed desktop apps: " + ", ".join(sorted({label for label, _ in _APP_ALLOWLIST.values()}))
    )


def build_compose_url(
    to: str = "",
    subject: str = "",
    body: str = "",
    provider: str = "gmail",
) -> str:
    """Build a browser compose URL with pre-filled To, Subject, and Body."""
    prov = (provider or "gmail").strip().lower()
    if prov == "outlook":
        params: Dict[str, str] = {}
        if to:
            params["to"] = to
        if subject:
            params["subject"] = subject
        if body:
            params["body"] = body
        qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        base = "https://outlook.live.com/mail/0/deeplink/compose"
        return f"{base}?{qs}" if qs else base

    if prov == "mailto":
        params = {}
        if subject:
            params["subject"] = subject
        if body:
            params["body"] = body
        qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        addr = urllib.parse.quote(to.strip()) if to else ""
        return f"mailto:{addr}?{qs}" if qs else f"mailto:{addr}"

    # Default: Gmail web compose
    params = {"view": "cm", "fs": "1"}
    if to:
        params["to"] = to
    if subject:
        params["su"] = subject
    if body:
        params["body"] = body
    qs = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
    return f"https://mail.google.com/mail/?{qs}"


def copy_to_clipboard(text: str) -> bool:
    """Copy text to the OS clipboard using safe stdin (no shell string interpolation)."""
    if not text:
        return False
    try:
        if sys.platform.startswith("win") or os.name == "nt":
            ps_script = "$t = [Console]::In.ReadToEnd(); Set-Clipboard -Value $t"
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                input=text,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=6,
                check=False,
            )
            return proc.returncode == 0
        if sys.platform == "darwin" and shutil.which("pbcopy"):
            proc = subprocess.run(
                ["pbcopy"],
                input=text,
                text=True,
                encoding="utf-8",
                capture_output=True,
                timeout=5,
                check=False,
            )
            return proc.returncode == 0
        for cmd in (["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]):
            if shutil.which(cmd[0]):
                proc = subprocess.run(
                    cmd,
                    input=text,
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                return proc.returncode == 0
    except Exception:
        return False
    return False


def parse_email_intent(prompt: str) -> Dict[str, str]:
    """Extract recipient, provider, subject hint, and topic from natural email text."""
    text = (prompt or "").strip()
    lower = text.lower()

    email_match = _EMAIL_RE.search(text)
    to_addr = email_match.group(1) if email_match else ""

    provider = "gmail"
    if "outlook" in lower or "hotmail" in lower:
        provider = "outlook"
    elif "mailto" in lower or "default mail" in lower:
        provider = "mailto"

    subj_match = re.search(r"(?:subject|sub|title)\s*[:=]\s*[\"']?([^\"'\n;]+)", text, re.IGNORECASE)
    body_match = re.search(r"(?:body|message|msg|content)\s*[:=]\s*[\"']?(.+)$", text, re.IGNORECASE | re.DOTALL)

    explicit_subject = subj_match.group(1).strip() if subj_match else ""
    explicit_body = body_match.group(1).strip() if body_match else ""

    # Clean conversational filler out of topic
    topic = text
    if email_match:
        topic = topic.replace(email_match.group(0), " ")
    topic = re.sub(
        r"\b(mail ekak|email ekak|e-mail|email|mail|danna|yawanna|send|write|compose|karanna|type|auto|browser|eke|open|wela|ta|to|kiyala|please|pls|mata|oni|one)\b",
        " ",
        topic,
        flags=re.IGNORECASE,
    )
    topic = re.sub(r"\s+", " ", topic).strip(" ,.;:-")

    return {
        "to": to_addr,
        "provider": provider,
        "explicit_subject": explicit_subject,
        "explicit_body": explicit_body,
        "topic": topic,
        "raw": text,
    }


def _build_fallback_email(prompt: str, parsed: Dict[str, str]) -> Tuple[str, str]:
    """Build a crisp deterministic subject & body when local AI is unavailable or fails."""
    explicit_subj = parsed.get("explicit_subject", "").strip()
    explicit_body = parsed.get("explicit_body", "").strip()
    topic = parsed.get("topic", "").strip()
    to_addr = parsed.get("to", "").strip()

    if explicit_subj and explicit_body:
        return explicit_subj, explicit_body

    recipient_name = "Team"
    if to_addr and "@" in to_addr:
        local_part = to_addr.split("@", 1)[0]
        cleaned = re.sub(r"[._-]+", " ", local_part).strip()
        if cleaned:
            recipient_name = cleaned.title()

    if explicit_subj:
        subject = explicit_subj
    elif topic:
        words = topic.split()
        short_topic = " ".join(words[:7])
        subject = short_topic[:1].upper() + short_topic[1:] if len(words) > 0 else "Quick Update"
    else:
        subject = "Quick Update"

    if explicit_body:
        body = explicit_body
    elif topic:
        body = (
            f"Hi {recipient_name},\n\n"
            f"I am writing regarding: {topic}.\n\n"
            "Please let me know your thoughts or if you need any further details.\n\n"
            "Best regards,"
        )
    else:
        body = (
            f"Hi {recipient_name},\n\n"
            "I hope you are doing well. Following up with a quick note.\n\n"
            "Best regards,"
        )
    return subject, body


def _parse_ai_email_draft(raw_text: str) -> Optional[Tuple[str, str]]:
    """Parse SUBJECT: ... and BODY: ... from AI output."""
    if not raw_text or not raw_text.strip():
        return None
    subj = ""
    body = ""
    m_subj = re.search(r"(?im)^\s*SUBJECT\s*:\s*(.+)$", raw_text)
    if m_subj:
        subj = m_subj.group(1).strip().strip('"').strip("'")
    m_body = re.search(r"(?ims)^\s*BODY\s*:\s*\n?(.+)$", raw_text)
    if m_body:
        body = m_body.group(1).strip()
    if subj and body:
        return subj[:160], body
    return None


def compose_email_with_model(
    prompt: str,
    parsed: Optional[Dict[str, str]] = None,
    stream: Any = None,
    executor: Optional[Callable[[List[str]], int]] = None,
) -> Tuple[str, str, bool]:
    """Draft email subject and body using local AI when reachable, else fallback.

    Returns (subject, body, used_ai).
    """
    info = parsed or parse_email_intent(prompt)
    if info["explicit_subject"] and info["explicit_body"]:
        return info["explicit_subject"], info["explicit_body"], False

    if executor is None:
        subj, body = _build_fallback_email(prompt, info)
        return subj, body, False

    ai_prompt = (
        "Draft a clear, natural email based on the user's request (which may be in English or Singlish). "
        "Output ONLY two sections in this exact format and nothing else:\n"
        "SUBJECT: <concise subject line>\n"
        "BODY:\n<complete ready-to-send email body>\n\n"
        f"Recipient: {info['to'] or '(unspecified)'}\n"
        f"User request: {prompt}"
    )

    prev_failover = os.environ.get("PAI_DISABLE_CHAT_FAILOVER")
    os.environ["PAI_DISABLE_CHAT_FAILOVER"] = "1"
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = executor(["chat", "--", ai_prompt])
        combined = buf_out.getvalue()
        if rc == 0:
            parsed_draft = _parse_ai_email_draft(combined)
            if parsed_draft:
                subj = info["explicit_subject"] or parsed_draft[0]
                body = info["explicit_body"] or parsed_draft[1]
                return subj, body, True
    except Exception:
        pass
    finally:
        if prev_failover is None:
            os.environ.pop("PAI_DISABLE_CHAT_FAILOVER", None)
        else:
            os.environ["PAI_DISABLE_CHAT_FAILOVER"] = prev_failover

    subj, body = _build_fallback_email(prompt, info)
    return subj, body, False


def open_email_compose(
    to: str = "",
    subject: str = "",
    body: str = "",
    provider: str = "gmail",
    stream: Any = None,
) -> Tuple[bool, str]:
    """Open the user's browser with a pre-filled email compose window."""
    url = build_compose_url(to=to, subject=subject, body=body, provider=provider)
    copied = copy_to_clipboard(body) if body else False
    try:
        opened = webbrowser.open(url, new=2)
    except Exception as exc:
        return False, f"Failed to open browser for email compose: {exc}"

    if not opened:
        # On some Windows setups webbrowser.open can return False even after ShellExecute;
        # attempt explicit cmd/start fallback only on Windows if webbrowser returned False.
        if sys.platform.startswith("win") or os.name == "nt":
            try:
                os.startfile(url)  # type: ignore[attr-defined]
                opened = True
            except Exception as exc:
                return False, f"Could not launch browser compose window: {exc}"

    summary_lines = [
        f"Opened {provider.capitalize()} compose in browser:",
        f"  To      : {to or '(fill in recipient)'}",
        f"  Subject : {subject}",
        f"  Body    : {body.splitlines()[0][:80]}{'...' if len(body) > 80 else ''}",
    ]
    if copied:
        summary_lines.append("  Clipboard: Email body copied to clipboard as backup.")
    summary_lines.append("Review the pre-filled email in your browser and click Send when ready.")
    msg = "\n".join(summary_lines)
    _emit(stream, msg)
    return bool(opened), msg


def _launch_app(app_key: str) -> Tuple[bool, str]:
    """Launch an allowlisted desktop app via subprocess (never shell=True)."""
    entry = _APP_ALLOWLIST.get(app_key)
    if not entry:
        return False, f"Application '{app_key}' is not in the safe automation allowlist."
    label, cmd = entry
    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
        return True, f"Launched {label}."
    except FileNotFoundError:
        return False, f"{label} ({cmd[0]}) was not found on this system."
    except Exception as exc:
        return False, f"Failed to launch {label}: {exc}"


def _open_notepad_and_type(text: str) -> Tuple[bool, str]:
    """Open Notepad and paste/type text safely via clipboard + SendKeys (no shell injection)."""
    copied = copy_to_clipboard(text)
    ok, launch_msg = _launch_app("notepad")
    if not ok:
        return False, launch_msg

    if sys.platform.startswith("win") or os.name == "nt":
        # Non-blocking background PowerShell helper reads nothing from user args;
        # text is already placed on clipboard safely via stdin above.
        ps_paste = (
            "$ws = New-Object -ComObject WScript.Shell; "
            "for ($i = 0; $i -lt 16; $i++) { "
            "Start-Sleep -Milliseconds 250; "
            "$p = Get-Process -Name Notepad -ErrorAction SilentlyContinue | "
            "Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1; "
            "$ok = $false; "
            "if ($p) { $ok = $ws.AppActivate($p.Id) } "
            "if (-not $ok) { $ok = ($ws.AppActivate('Untitled - Notepad') -or $ws.AppActivate('Notepad')) } "
            "if ($ok) { Start-Sleep -Milliseconds 200; $ws.SendKeys('^v'); break } "
            "}"
        )
        try:
            subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", ps_paste],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            pass
    clip_note = " (text copied & auto-pasted into Notepad)" if copied else ""
    return True, f"Opened Notepad{clip_note}."


def _open_user_folder(folder_key: str) -> Tuple[bool, str]:
    rel = _FOLDER_MAP.get(folder_key)
    if not rel:
        return False, f"Unknown folder '{folder_key}'."
    target = Path.home() / rel
    if not target.exists():
        return False, f"Folder not found: {target}"
    try:
        if sys.platform.startswith("win") or os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(target)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True, f"Opened folder: {target}"
    except Exception as exc:
        return False, f"Could not open folder {target}: {exc}"


def _open_url(url: str, label: Optional[str] = None) -> Tuple[bool, str]:
    target = url.strip()
    if target.lower().startswith("www."):
        target = "https://" + target
    try:
        opened = webbrowser.open(target, new=2)
        if not opened and (sys.platform.startswith("win") or os.name == "nt"):
            os.startfile(target)  # type: ignore[attr-defined]
            opened = True
        desc = label or target
        return bool(opened), f"Opened {desc} in browser ({target})."
    except Exception as exc:
        return False, f"Failed to open URL '{target}': {exc}"


def _extract_search_query(text: str, site_kw: str) -> str:
    q = re.sub(rf"\b{re.escape(site_kw)}\b", " ", text, flags=re.IGNORECASE)
    q = re.sub(
        r"\b(eke|in|on|search|find|lookup|open|karanna|balanna|play|watch|browser|mata|kiala)\b",
        " ",
        q,
        flags=re.IGNORECASE,
    )
    return re.sub(r"\s+", " ", q).strip(" ,.;:?!'\"")


def parse_automation_intent(prompt: str, sub_action: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Detect whether a prompt should trigger computer/browser automation.

    Returns an intent dict {'kind': ...} or None if the prompt is normal chat/coding.
    """
    raw = (prompt or "").strip()
    lower = raw.lower()

    if sub_action == "mail":
        return {"kind": "email", "prompt": raw}

    explicit_auto = sub_action == "auto"

    if not explicit_auto:
        # Never hijack coding/file questions or explanations
        if any(guard in lower for guard in _CODE_OR_QUESTION_GUARD):
            return None
        # Do not hijack if user is explicitly referring to a local project file preview handled elsewhere
        if re.search(r"\b[\w./\\-]+\.(?:html?|css|js|py|md|txt|json)\b", lower):
            return None

    # 1. Email automation ("mail ekak danna", "email ekak yawanna", "send email to ...")
    email_phrase = any(
        p in lower
        for p in (
            "mail ekak",
            "email ekak",
            "e-mail",
            "send mail",
            "send email",
            "send an email",
            "compose email",
            "compose mail",
            "write an email",
            "write a mail",
            "draft email",
            "mail danna",
            "mail yawanna",
            "email danna",
            "email yawanna",
            "email type",
            "mail type",
        )
    )
    if email_phrase or (_EMAIL_RE.search(raw) and any(k in lower for k in ("mail", "email", "yawanna", "danna", "send", "write"))):
        return {"kind": "email", "prompt": raw}

    # 2. Clipboard copy
    if "clipboard" in lower and any(k in lower for k in ("copy", "danna", "save")):
        m = re.search(r"copy\s+[\"']?(.+?)[\"']?\s+(?:to|ekata)\s+clipboard", raw, re.IGNORECASE)
        clip_text = m.group(1).strip() if m else re.sub(r"(?i)\b(copy|to|clipboard|ekata|danna)\b", "", raw).strip()
        if clip_text:
            return {"kind": "clipboard", "text": clip_text}

    # 3. Notepad + typing ("notepad open karala hello type karanna")
    if "notepad" in lower and any(k in lower for k in ("type", "write", "liyan", "paste", "danna")):
        m = re.search(
            r"(?:notepad\s+(?:open\s+karala|open\s+and|eka\s+open\s+karala)?\s*)(.+?)(?:\s+(?:type|write|paste)\s*(?:karanna)?$)",
            raw,
            re.IGNORECASE,
        )
        typed_text = ""
        if m:
            typed_text = m.group(1).strip(" \"'")
        if not typed_text:
            m2 = re.search(r"[\"']([^\"']+)[\"']", raw)
            if m2:
                typed_text = m2.group(1)
        if not typed_text:
            typed_text = re.sub(
                r"(?i)\b(notepad|eka|open|karala|and|type|write|paste|karanna|danna|please)\b",
                " ",
                raw,
            )
            typed_text = re.sub(r"\s+", " ", typed_text).strip(" ,.;:")
        if typed_text:
            return {"kind": "notepad_type", "text": typed_text}

    # 4. Web searches (YouTube / Google)
    if "youtube" in lower and any(k in lower for k in ("search", "play", "balanna", "hoyanna", "find")):
        q = _extract_search_query(raw, "youtube")
        if q:
            return {"kind": "web_search", "engine": "youtube", "query": q}
    if "google" in lower and any(k in lower for k in ("search", "hoyanna", "find", "lookup")):
        q = _extract_search_query(raw, "google")
        if q:
            return {"kind": "web_search", "engine": "google", "query": q}

    # 5. Explicit URL opening
    url_m = _URL_RE.search(raw)
    if url_m and (explicit_auto or any(k in lower for k in ("open", "browse", "visit", "yanna", "load"))):
        return {"kind": "open_url", "url": url_m.group(1)}

    # 6. Action verb required for implicit app/web/folder opens so normal questions never trigger
    has_open_action = explicit_auto or any(
        k in lower for k in ("open ", "open karanna", "launch ", "start ", "aranna", "patanganna")
    )
    if has_open_action:
        for folder_key in sorted(_FOLDER_MAP, key=len, reverse=True):
            if re.search(rf"\b{re.escape(folder_key)}\b", lower):
                return {"kind": "open_folder", "folder": folder_key}
        for app_key in sorted(_APP_ALLOWLIST, key=len, reverse=True):
            if re.search(rf"\b{re.escape(app_key)}\b", lower):
                return {"kind": "open_app", "app": app_key}
        for site_key, site_url in sorted(_WEB_SHORTCUTS.items(), key=lambda kv: len(kv[0]), reverse=True):
            if re.search(rf"\b{re.escape(site_key)}\b", lower):
                return {"kind": "open_url", "url": site_url, "label": site_key.title()}

    if explicit_auto:
        return {"kind": "unsupported", "prompt": raw}
    return None


def execute_automation_task(
    prompt: str,
    sub_action: Optional[str] = None,
    stream: Any = sys.stdout,
    executor: Optional[Callable[[List[str]], int]] = None,
) -> Tuple[bool, str]:
    """Execute a computer or browser automation instruction safely."""
    raw = (prompt or "").strip()
    if not raw or raw.lower() in ("help", "--help", "-h", "?"):
        help_txt = format_automation_help()
        _emit(stream, help_txt)
        return True, help_txt

    intent = parse_automation_intent(raw, sub_action=sub_action)
    if intent is None:
        help_txt = "Could not recognize a supported automation action.\n\n" + format_automation_help()
        _emit(stream, help_txt)
        return False, help_txt

    kind = intent["kind"]
    if kind == "email":
        parsed = parse_email_intent(intent["prompt"])
        _emit(stream, "Drafting email and opening browser compose window...")
        subject, body, used_ai = compose_email_with_model(
            intent["prompt"],
            parsed=parsed,
            stream=stream,
            executor=executor,
        )
        if used_ai:
            _emit(stream, "  (Subject & body drafted using local AI)")
        else:
            _emit(stream, "  (Using fast built-in email template)")
        return open_email_compose(
            to=parsed["to"],
            subject=subject,
            body=body,
            provider=parsed["provider"],
            stream=stream,
        )

    if kind == "web_search":
        engine = intent["engine"]
        query = intent["query"]
        encoded = urllib.parse.quote_plus(query)
        if engine == "youtube":
            url = f"https://www.youtube.com/results?search_query={encoded}"
            ok, msg = _open_url(url, label=f"YouTube search '{query}'")
        else:
            url = f"https://www.google.com/search?q={encoded}"
            ok, msg = _open_url(url, label=f"Google search '{query}'")
        _emit(stream, msg)
        return ok, msg

    if kind == "open_url":
        ok, msg = _open_url(intent["url"], label=intent.get("label"))
        _emit(stream, msg)
        return ok, msg

    if kind == "open_folder":
        ok, msg = _open_user_folder(intent["folder"])
        _emit(stream, msg)
        return ok, msg

    if kind == "notepad_type":
        ok, msg = _open_notepad_and_type(intent["text"])
        _emit(stream, msg)
        return ok, msg

    if kind == "open_app":
        ok, msg = _launch_app(intent["app"])
        _emit(stream, msg)
        return ok, msg

    if kind == "clipboard":
        ok = copy_to_clipboard(intent["text"])
        msg = "Copied text to clipboard." if ok else "Clipboard copy is unavailable on this environment."
        _emit(stream, msg)
        return ok, msg

    msg = (
        f"Unsupported automation request: '{raw}'. For safety, PAI only runs browser actions, "
        "email compose, folder opens, clipboard copy, and allowlisted desktop apps.\n\n"
        + format_automation_help()
    )
    _emit(stream, msg)
    return False, msg
