from typing import Dict, Any, List, Optional
import tempfile
import subprocess
import shutil
import os

from agents.contracts import ExecutionPlan, AgentContext
from agents.planner.planner_fallback import FallbackPlanner

from sast.runner import run_semgrep
from sast.normalize import normalize_semgrep

from sast.dast_runner import run_nuclei
from sast.normalize_dast import normalize_nuclei

from sast.sbom_runner import generate_sbom
# Imports kept as 'osv' for compatibility, but they now point to Grype logic
from sast.sca_runner import run_osv_scan
from sast.normalize_sca import normalize_osv

from sast.config_runner import run_config_checks
from sast.dedup import dedup_findings 

from sast.schema import Finding
from sast.scope import (
    ScopePolicy,
    validate_repo_scope,
    validate_target_url,
    ScopeViolation,
)

import re

# Allowlist: https:// git URLs or git@ SSH refs only. No whitespace, no
# option-like leading dashes, no shell metacharacters.
_REPO_URL_RE = re.compile(
    r"^(https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\-]+"
    r"|git@[A-Za-z0-9._\-]+:[A-Za-z0-9._~/\-]+)$"
)


def validate_repo_input(repo_input: str) -> None:
    """
    Validate a repository reference before it is used in a git clone or as a
    filesystem path. Raises ValueError on any input that could enable git
    argument injection (CWE-78) or path traversal (CWE-22).
    """
    if not isinstance(repo_input, str) or not repo_input.strip():
        raise ValueError("repo_input must be a non-empty string")
    if repo_input != repo_input.strip():
        raise ValueError("repo_input must not have leading/trailing whitespace")
    if any(c.isspace() for c in repo_input):
        raise ValueError("repo_input must not contain whitespace")
    if repo_input.startswith("-"):
        raise ValueError("repo_input must not start with a dash (option injection)")
    if not _REPO_URL_RE.match(repo_input):
        raise ValueError(
            "repo_input must be a valid https:// git URL or git@ SSH reference"
        )


def ensure_path_containment(repo_path: str, workspace_root: str) -> str:
    """
    Canonicalize repo_path and verify it remains inside workspace_root.
    Blocks path traversal ('..') and symlink escapes (CWE-22). Returns the
    canonicalized path on success; raises ValueError otherwise.
    """
    real = os.path.realpath(repo_path)
    root = os.path.realpath(workspace_root)
    if real != root and not real.startswith(root + os.sep):
        raise ValueError(f"path escapes workspace root: {repo_path}")
    return real

# ============================================================
# Workspace resolution (TEMP local execution adapter)
# ============================================================
def resolve_repo(repo_input: str) -> tuple[str, bool]:
    """
    TEMP: Local execution adapter.
    In prod, code will already be checked out by CI.
    """
    # [FIX CWE-78] Validate repo_input before it reaches the git subprocess.
    validate_repo_input(repo_input)
    if repo_input.startswith("http"):
        temp_dir = tempfile.mkdtemp(prefix="deplai-repo-")
        try:
            # [FIX] Removed DEVNULL, added capture_output=True to see errors
            # [FIX CWE-78] '--' terminates git option parsing for the URL.
            subprocess.run(
                ["git", "clone", "--depth=1", "--", repo_input, temp_dir],
                check=True,
                capture_output=True, # Captures stdout/stderr
                text=True            # Decodes to string
            )
        except subprocess.CalledProcessError as e:
            # Clean up if clone fails
            shutil.rmtree(temp_dir, ignore_errors=True)
            # [FIX] Return the actual error message from Git
            raise RuntimeError(f"Failed to clone repository: {repo_input}\nGit Error: {e.stderr}")

        return temp_dir, True

    return repo_input, False


# ============================================================
# Dependency detection (Multi-language)
# ============================================================
def has_dependencies(repo_path: str) -> bool:
    """
    Checks for the existence of dependency manifest files for various languages.
    """
    # List of common dependency files for Python, Node, Go, Java, Rust, PHP
    supported_files = {
        "requirements.txt", "pyproject.toml", "poetry.lock", 
        "package.json", "package-lock.json", "yarn.lock",
        "go.mod", "go.sum",
        "pom.xml", "build.gradle",
        "Cargo.toml", "composer.json"
    }
    
    # Check top-level directory only for speed
    try:
        for f in os.listdir(repo_path):
            if f in supported_files:
                return True
    except OSError:
        pass
        
    return False


# ============================================================
# MAIN ENTRYPOINT — PLAN-DRIVEN EXECUTION
# ============================================================
def run_security_checks(
    input: Dict[str, Any],
    plan: Optional[ExecutionPlan] = None,
    scope: Optional[ScopePolicy] = None,
) -> Dict[str, Any]:
    """
    Orchestrates all security checks based on the provided plan.
    Now includes fault tolerance for individual tool failures.
    """

    # --------------------------------------------------------
    # 🛡️ DEFENSIVE ARG NORMALIZATION (BACKWARD COMPAT)
    # --------------------------------------------------------
    if isinstance(plan, ScopePolicy) and scope is None:
        scope = plan
        plan = None

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------
    if "run_id" not in input:
        raise ValueError("run_id is required")

    run_id: str = input["run_id"]
    repo_input: Optional[str] = input.get("repo_path")
    dast_cfg: Dict[str, Any] = input.get("dast", {})
    languages: List[str] = input.get("languages", ["python"])

    # --------------------------------------------------------
    # [FIX CWE-78/CWE-22] EARLY REPO INPUT VALIDATION
    # Reject malformed/option-like repo inputs before any scope,
    # clone, or path resolution happens.
    # --------------------------------------------------------
    if repo_input:
        try:
            validate_repo_input(repo_input)
        except ValueError as e:
            return {
                "run_id": run_id,
                "status": "blocked",
                "tools": [],
                "findings": [
                    Finding(
                        category="SYSTEM",
                        tool="scope",
                        rule_id="repo-input-validation-failed",
                        title="Repository input failed validation",
                        severity="LOW",
                        confidence="HIGH",
                        file="scope",
                        line_start=0,
                        line_end=None,
                        fingerprint=f"scope:repo-input:{hash(str(e))}",
                        occurrences=1,
                        evidence={"error": str(e)},
                    )
                ],
            }

    # --------------------------------------------------------
    # BACKWARD COMPATIBILITY (legacy / tests)
    # --------------------------------------------------------
    if plan is None:
        ctx = AgentContext(
            repo=repo_input or "",
            languages=languages,
            frameworks=input.get("frameworks", []),
            dependencies=input.get("dependencies", []),
            is_pr=input.get("is_pr", False),
            changed_files=input.get("changed_files", []),
            has_public_endpoint=bool(dast_cfg.get("target_url")),
        )
        plan = FallbackPlanner().plan(ctx)

    # --------------------------------------------------------
    # DEFAULT SCOPE (local / tests)
    # --------------------------------------------------------
    if scope is None:
        # [CRITICAL FIX] "The Nuclear Option"
        # Allowed Domains = ["*"] means allow EVERYTHING.
        # Safe Mode = False means disable strict checks.
        # [FIX] Safe default: strict mode, no wildcard domains. An omitted
        # scope must not silently disable validation.
        scope = ScopePolicy(
            allowed_repo_prefixes=[""],
            allowed_domains=[],
            safe_mode=True,
        )

    # --------------------------------------------------------
    # SCOPE VALIDATION (REPO)
    # --------------------------------------------------------
    if repo_input:
        try:
            validate_repo_scope(repo_input, scope)
        except ScopeViolation as e:
            return {
                "run_id": run_id,
                "status": "blocked",
                "tools": [],
                "findings": [
                    Finding(
                        category="SYSTEM",
                        tool="scope",
                        rule_id="repo-scope-violation",
                        title="Repository blocked by scope policy",
                        severity="LOW",
                        confidence="HIGH",
                        file="scope",
                        line_start=0,
                        line_end=None,
                        fingerprint=f"scope:repo:{hash(str(e))}",
                        occurrences=1,
                        evidence={"error": str(e)},
                    )
                ],
            }

    # --------------------------------------------------------
    # WORKSPACE RESOLUTION
    # --------------------------------------------------------
    repo_path: Optional[str] = None
    is_temp_clone = False

    if repo_input:
        try:
            repo_path, is_temp_clone = resolve_repo(repo_input)
            # [FIX CWE-22] Enforce workspace containment on the resolved path
            # before it is used for listdir / tool invocations.
            if repo_path:
                if is_temp_clone:
                    repo_path = ensure_path_containment(repo_path, tempfile.gettempdir())
                else:
                    normalized = repo_path.replace("\\", "/").split("/")
                    if ".." in normalized:
                        raise ValueError("repo_path must not contain '..' segments")
                    if os.path.realpath(repo_path) != os.path.abspath(repo_path):
                        raise ValueError("repo_path must not traverse symlinks")
        except (RuntimeError, ValueError) as e:
             return {
                "run_id": run_id,
                "status": "failed",
                "tools": [],
                "findings": [
                    Finding(
                        category="SYSTEM",
                        tool="git",
                        rule_id="clone-failed",
                        title="Failed to clone repository",
                        severity="HIGH",
                        confidence="HIGH",
                        file="git",
                        line_start=0,
                        line_end=None,
                        fingerprint=f"git:clone-error:{hash(str(e))}",
                        occurrences=1,
                        evidence={"error": str(e)},
                    )
                ],
            }

    signals: List[Finding] = []
    tools_run: List[str] = []

    try:
        # ====================================================
        # SAST (Semgrep)
        # ====================================================
        if repo_path and plan.run_sast:
            try:
                # [FIX] Pass languages to runner
                raw = run_semgrep(repo_path, languages)
                signals.extend(normalize_semgrep(raw))
                tools_run.append("semgrep")
            except Exception as e:
                tools_run.append("semgrep-error")
                signals.append(
                    Finding(
                        category="SYSTEM",
                        tool="semgrep",
                        rule_id="semgrep-execution-error",
                        title="SAST execution failed",
                        severity="LOW",
                        confidence="HIGH",
                        file="semgrep",
                        line_start=0,
                        line_end=None,
                        fingerprint=f"sast-error:{type(e).__name__}",
                        occurrences=1,
                        evidence={"error": str(e)},
                    )
                )

        # ====================================================
        # SCA (Syft + Grype)
        # ====================================================
        if repo_path and plan.run_sca:
            # [FIX] Use generic dependency checker
            if not has_dependencies(repo_path):
                tools_run.append("sca-skipped")
            else:
                try:
                    sbom_path = generate_sbom(repo_path)
                    # [FIX] Changed variable names and logs to reflect Grype usage
                    grype_raw = run_osv_scan(sbom_path) 
                    signals.extend(normalize_osv(grype_raw, run_id))
                    tools_run.append("sca-grype") # [FIX] Correct tool label
                except Exception as e:
                    tools_run.append("sca-error")
                    signals.append(
                        Finding(
                            category="SYSTEM",
                            tool="sca",
                            rule_id="grype-execution-error", # [FIX] Correct rule ID
                            title="SCA execution failed",
                            severity="LOW",
                            confidence="HIGH",
                            file="dependency-resolution",
                            line_start=0,
                            line_end=None,
                            fingerprint=f"sca-grype-error:{type(e).__name__}", # [FIX] Correct fingerprint
                            occurrences=1,
                            evidence={"error": str(e)},
                        )
                    )

        # ====================================================
        # DAST + CONFIG
        # ====================================================
        if plan.run_dast:
            target_url = dast_cfg.get("target_url")
            dast_headers = dast_cfg.get("headers", {})
            
            if not target_url:
                signals.append(Finding(
                     category="SYSTEM", tool="planner", rule_id="dast-missing-url",
                     title="DAST enabled but no target URL provided", severity="LOW",
                     confidence="HIGH", file="orchestrator", line_start=0, line_end=0,
                     fingerprint="dast-missing-url", occurrences=1
                ))
            else:
                # 1. Scope Check
                try:
                    validate_target_url(target_url, scope)
                    
                    # 2. Nuclei (DAST)
                    try:
                        raw = run_nuclei(target_url, headers=dast_headers)
                        signals.extend(normalize_nuclei(raw))
                        tools_run.append("nuclei")
                    except Exception as e:
                        tools_run.append("nuclei-error")
                        signals.append(Finding(
                            category="SYSTEM", tool="nuclei", rule_id="nuclei-execution-error",
                            title="DAST (Nuclei) failed", severity="LOW", fingerprint=f"nuclei-error:{type(e).__name__}",
                            evidence={"error": str(e)}
                        ))

                    # 3. Config Checks
                    try:
                        signals.extend(run_config_checks(target_url))
                        tools_run.append("config")
                    except Exception as e:
                        tools_run.append("config-error")

                except ScopeViolation as e:
                    signals.append(
                        Finding(
                            category="SYSTEM",
                            tool="scope",
                            rule_id="dast-scope-violation",
                            title="DAST target blocked by scope policy",
                            severity="LOW",
                            confidence="HIGH",
                            file="scope",
                            line_start=0,
                            line_end=None,
                            fingerprint=f"scope:dast:{hash(str(e))}",
                            occurrences=1,
                            evidence={"error": str(e)},
                        )
                    )

        # [FIX] Deduplicate Findings
        deduped_findings = dedup_findings(signals)

        return {
            "run_id": run_id,
            "status": "completed",
            "tools": tools_run,
            "findings": deduped_findings,
        }

    finally:
        # --------------------------------------------------------
        # CLEANUP
        # --------------------------------------------------------
        if is_temp_clone and repo_path and os.path.exists(repo_path):
            try:
                shutil.rmtree(repo_path, ignore_errors=True)
            except OSError:
                pass