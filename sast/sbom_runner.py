from pathlib import Path
import subprocess
import re

class SBOMGenerationError(RuntimeError):
    pass

# Characters that could enable argument injection if they appear in a path.\_SHELL_METACHARACTERS = re.compile(r"[;&|`$<>\\'\"\n\r\t]|")

def _validate_project_root(project_root: str) -> Path:
    """Normalize and validate the user-supplied project root.

    Rejects values that could be abused for argument injection
    (leading dashes, shell metacharacters) or that do not point at
    an existing directory.
    """
    if not isinstance(project_root, str) or not project_root.strip():
        raise SBOMGenerationError("project_root must be a non-empty string.")

    if project_root.lstrip().startswith("-"):
        raise SBOMGenerationError("project_root must not start with a dash.")

    if _SHELL_METACHARACTERS.search(project_root):
        raise SBOMGenerationError("project_root contains forbidden characters.")

    try:
        resolved = Path(project_root).resolve(strict=True)
    except (OSError, RuntimeError):
        raise SBOMGenerationError("project_root could not be resolved.")

    if not resolved.is_dir():
        raise SBOMGenerationError("project_root must be an existing directory.")

    return resolved

def generate_sbom(project_root: str) -> Path:
    """
    Generate a CycloneDX SBOM using Syft.
    Syft is universal (Python, JS, Go, Rust, Java, etc.).
    """
    resolved_root = _validate_project_root(project_root)
    sbom_path = resolved_root / "sbom.json"
    
    # Syft command: Scan directory and output CycloneDX JSON.
    # The scan target is a single positional argument built from the
    # validated, resolved path; the output path is derived from the
    # resolved root, never from raw user input.
    cmd = [
        "syft",
        f"dir:{resolved_root}",
        "-o", f"cyclonedx-json={sbom_path}"
    ]

    try:
        print("📦 Generating SBOM with Syft...")
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if sbom_path.exists() and sbom_path.stat().st_size > 0:
            return sbom_path
            
    except subprocess.CalledProcessError as e:
        raise SBOMGenerationError(f"Syft failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise SBOMGenerationError("Syft timed out (limit: 120s)")
    except SBOMGenerationError:
        raise
    except Exception as e:
        raise SBOMGenerationError(f"SBOM generation failed: {str(e)}")

    raise SBOMGenerationError("Syft produced an empty SBOM.")