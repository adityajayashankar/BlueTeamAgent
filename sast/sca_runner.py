from pathlib import Path
import re
import subprocess
import json

class SCARunnerError(RuntimeError):
    pass

# Allowed SBOM file extensions
_ALLOWED_SBOM_SUFFIXES = (".json", ".cdx.json", ".spdx.json", ".syft.json")

# Characters that could enable shell or argument-parsing abuse if ever
# interpreted by a downstream consumer of the path.
_SHELL_METACHARACTERS = re.compile(r"[';`$&|<>\n\r\\]")

def _validate_sbom_path(sbom_path: Path) -> Path:
    """Canonicalize and validate the SBOM path before it is used in a command."""
    # Reject option-like paths that could be parsed as CLI flags.
    raw = str(sbom_path)
    if raw.startswith("-"):
        raise SCARunnerError(f"Invalid SBOM path (option-like): {raw}")

    # Reject shell metacharacters as defense-in-depth.
    if _SHELL_METACHARACTERS.search(raw):
        raise SCARunnerError(f"Invalid SBOM path (illegal characters): {raw}")

    # Canonicalize: must resolve to an absolute, existing, regular file.
    try:
        resolved = sbom_path.resolve(strict=True)
    except (OSError, RuntimeError) as e:
        raise SCARunnerError(f"SBOM not found at {sbom_path}") from e

    if not resolved.is_file():
        raise SCARunnerError(f"SBOM not found at {sbom_path}")

    # Require a plausible SBOM extension.
    name = resolved.name.lower()
    if not any(name.endswith(suffix) for suffix in _ALLOWED_SBOM_SUFFIXES):
        raise SCARunnerError(
            f"Invalid SBOM file extension (expected one of {_ALLOWED_SBOM_SUFFIXES}): {resolved}"
        )

    return resolved

def run_osv_scan(sbom_path: Path) -> dict:
    """
    Execute Grype against a CycloneDX SBOM.
    (Function name kept as 'run_osv_scan' to maintain compatibility with Orchestrator)
    """
    resolved_sbom = _validate_sbom_path(sbom_path)

    # Grype command: Scan the SBOM file and output JSON.
    # The SBOM reference is a single argv element; no shell interpolation.
    cmd = [
        "grype",
        f"sbom:{resolved_sbom}",
        "-o", "json"
    ]

    try:
        print(f"🔍 Scanning SBOM with Grype: {resolved_sbom}")
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            shell=False,
        )
        return json.loads(result.stdout)

    except subprocess.CalledProcessError as e:
        raise SCARunnerError(f"Grype failed: {e.stderr.strip()}")
    except json.JSONDecodeError as e:
        raise SCARunnerError(f"Invalid JSON returned by Grype: {str(e)}")




