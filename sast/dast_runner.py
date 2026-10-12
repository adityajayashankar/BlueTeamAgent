import subprocess
import tempfile
import json
import os
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

_HEADER_KEY_RE = re.compile(r"^[A-Za-z0-9-]+$")


def _validate_target_url(target_url: str) -> str:
    """Validate target_url to prevent CLI argument injection (CWE-78).

    Raises ValueError on any unsafe input; never silently sanitizes.
    """
    if not isinstance(target_url, str) or not target_url:
        raise ValueError("target_url must be a non-empty string")
    if any(ord(c) < 32 or ord(c) == 127 for c in target_url):
        raise ValueError("target_url contains control characters")
    if any(c.isspace() for c in target_url):
        raise ValueError("target_url contains whitespace")
    if target_url.startswith("-"):
        raise ValueError("target_url must not start with '-'")
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("target_url must use http or https scheme")
    if not parsed.hostname:
        raise ValueError("target_url must include a hostname")
    return target_url


def _validate_headers(headers: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    """Validate header keys/values to prevent CLI argument injection (CWE-78).

    Raises ValueError on any unsafe input; never silently sanitizes.
    """
    if headers is None:
        return None
    if not isinstance(headers, dict):
        raise ValueError("headers must be a dict")
    for k, v in headers.items():
        if not isinstance(k, str) or not _HEADER_KEY_RE.match(k):
            raise ValueError(f"invalid header key: {k!r}")
        if not isinstance(v, str) or not v:
            raise ValueError(f"invalid header value for key {k!r}")
        if v.startswith("-"):
            raise ValueError(f"header value for key {k!r} must not start with '-'")
        if any(ord(c) < 32 or ord(c) == 127 for c in v):
            raise ValueError(f"header value for key {k!r} contains control characters")
        if any(c.isspace() for c in v):
            raise ValueError(f"header value for key {k!r} contains whitespace")
    return headers


def run_nuclei(
    target_url: str,
    headers: Optional[Dict[str, str]] = None,
    profile: str = "ci",  # ci | deep
) -> Dict[str, Any]:
    """
    Run Nuclei DAST scan (safe by default).
    """

    # ---- INPUT VALIDATION (fail closed, CWE-78) ----
    target_url = _validate_target_url(target_url)
    headers = _validate_headers(headers)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
        output_path = tmp.name

    # ---- SAFE DEFAULT FLAGS (CI / PROD) ----
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-o", output_path,

        # 🚦 SEVERITY (no low in CI)
        "-severity", "medium,high,critical",

        # 🎯 REAL WEB ISSUES ONLY
        "-tags", "xss,sqli,auth,misconfig,exposure",

        # ⚡ PERFORMANCE CONTROLS
        "-timeout", "10",
        "-retries", "1",
        "-rl", "100",        # rate limit
        "-c", "50",          # concurrency
        "-max-host-error", "30",

        "-disable-update-check",
        "-silent",
    ]

    # ---- OPTIONAL DEEP SCAN (explicit only) ----
    if profile == "deep":
        cmd.extend([
            "-tags", "xss,sqli,auth,misconfig,exposure,cves",
            "-timeout", "20",
            "-rl", "200",
        ])

    # ---- AUTH HEADERS ----
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])

    print(f"🚀 Running Nuclei ({profile}) on {target_url}...")

    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode > 1:
        print("⚠️ Nuclei execution issue:")
        print(proc.stderr[:500])

    results: List[dict] = []

    try:
        if os.path.exists(output_path):
            with open(output_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
    finally:
        try:
            os.remove(output_path)
        except OSError:
            pass

    return {
        "tool": "nuclei",
        "target": target_url,
        "profile": profile,
        "results": results,
        "count": len(results),
    }
