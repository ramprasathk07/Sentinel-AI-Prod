from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


# ── Base Request / Response (existing) ────────────────────────

class AgentRequest(BaseModel):
    agent_id: str
    task: str
    context: Optional[dict] = None


class AgentResponse(BaseModel):
    agent_id: str
    status: str
    output: str


# ── Archeologist-specific schemas ─────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class CVEFinding(BaseModel):
    """A single CVE / vulnerability finding for a package."""
    cve_id: str = ""
    package_name: str
    version: str
    ecosystem: str = ""
    summary: str = ""
    cvss_score: Optional[float] = None
    severity: Severity = Severity.UNKNOWN
    source: str = ""                      # "osv" | "nvd"
    references: List[str] = Field(default_factory=list)


class OneWeekFlag(BaseModel):
    """Flag raised when a package maintainer account is < 7 days old."""
    package_name: str
    maintainer: str
    account_created: Optional[datetime] = None
    account_age_days: Optional[int] = None
    registry: str = ""                    # "npm" | "pypi"
    flagged: bool = True
    reason: str = "Maintainer account is less than 7 days old"


class MaintainerInfo(BaseModel):
    """Reputation / metadata for a package maintainer."""
    username: str
    registry: str
    account_created: Optional[datetime] = None
    account_age_days: Optional[int] = None
    package_count: Optional[int] = None
    reputation_score: Optional[float] = None   # 0.0 – 1.0 (from Graphiti, future)
    one_week_flag: bool = False


class PackageDependency(BaseModel):
    """A single parsed dependency from a lockfile."""
    name: str
    version: str
    ecosystem: str                        # "npm" | "pypi" | "go" | "cargo"


class ArcheologistReport(BaseModel):
    """Complete output of an Archeologist scan."""
    dependencies: List[PackageDependency] = Field(default_factory=list)
    cve_findings: List[CVEFinding] = Field(default_factory=list)
    one_week_flags: List[OneWeekFlag] = Field(default_factory=list)
    maintainers: List[MaintainerInfo] = Field(default_factory=list)
    summary: str = ""
    risk_score: Optional[float] = None    # aggregate 0.0 – 10.0


# ── Shadow Stalker-specific schemas ───────────────────────────

class ObfuscationTechnique(str, Enum):
    """Classification of detected obfuscation techniques."""
    HOMOGLYPH = "homoglyph"
    BASE64_PAYLOAD = "base64_payload"
    DYNAMIC_EXECUTION = "dynamic_execution"
    STRING_CONCAT_EVAL = "string_concat_eval"
    HIDDEN_IN_EXCEPT = "hidden_in_except"
    DEAD_CODE_PAYLOAD = "dead_code_payload"
    TAINT_PROPAGATION = "taint_propagation"
    INSTALL_HOOK = "install_hook"
    OBFUSCATED_IMPORT = "obfuscated_import"
    ENCODED_SHELL = "encoded_shell"


class StaticFinding(BaseModel):
    """A single static analysis finding from the Shadow Stalker."""
    file: str
    line: int
    column: int = 0
    severity: Severity = Severity.UNKNOWN
    technique: ObfuscationTechnique
    description: str
    evidence: str = ""              # matched code snippet / context
    confidence: float = 1.0         # 0.0 – 1.0
    stage: str = "stage1"           # stage1 | stage2 | stage3


class ShadowStalkerReport(BaseModel):
    """Complete output of a Shadow Stalker deep static scan."""
    findings: List[StaticFinding] = Field(default_factory=list)
    files_analyzed: int = 0
    lines_analyzed: int = 0
    risk_score: float = 0.0         # aggregate 0.0 – 10.0
    summary: str = ""


# ── Lead Warden-specific schemas ──────────────────────────────

class VerdictDecision(str, Enum):
    """Lead Warden verdict outcomes."""
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"
    APPROVE = "APPROVE"


class VerdictOutput(BaseModel):
    """Structured verdict from the Lead Warden."""
    verdict: VerdictDecision
    confidence: float = 0.0             # 0.0 – 1.0
    severity: Severity = Severity.UNKNOWN
    risk_score: float = 0.0             # aggregate 0.0 – 50.0
    summary: str = ""
    reasoning: List[str] = Field(default_factory=list)
    attack_classification: str = "none"
    agent_scores: dict = Field(default_factory=dict)
    timestamp: Optional[datetime] = None
    engine_version: str = "stage1"


# ── Sentinel Watcher-specific schemas ─────────────────────────

class RegistryChange(BaseModel):
    """A single detected change in a package registry."""
    type: str                               # maintainer_added, new_version, etc.
    severity: Severity = Severity.UNKNOWN
    details: str = ""
    package_name: str = ""
    registry: str = ""                      # npm | pypi | crates.io


class WatcherAlert(BaseModel):
    """An alert dispatched by the Sentinel Watcher."""
    alert_type: str
    severity: Severity
    title: str
    details: str = ""
    package_name: str = ""
    registry: str = ""
    channel: str = "slack"
    timestamp: Optional[datetime] = None


class WatcherReport(BaseModel):
    """Complete output of a Sentinel Watcher monitoring cycle."""
    packages_checked: int = 0
    total_dependencies: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    alerts: List[WatcherAlert] = Field(default_factory=list)
    changes: List[RegistryChange] = Field(default_factory=list)
    summary: str = ""


# ── Detonator-specific schemas ────────────────────────────────

class SandboxTelemetry(BaseModel):
    """Behavioral telemetry from sandbox execution."""
    container_id: str = ""
    exit_code: Optional[int] = None
    duration_ms: Optional[int] = None
    network_connections: List[str] = Field(default_factory=list)
    file_modifications: List[str] = Field(default_factory=list)
    spawned_processes: List[str] = Field(default_factory=list)
    env_var_reads: List[str] = Field(default_factory=list)
    sandbox_escape_attempted: bool = False


class DetonationReport(BaseModel):
    """Complete output of a Detonator sandbox run."""
    detonated: bool = False
    telemetry: Optional[SandboxTelemetry] = None
    threats: List[dict] = Field(default_factory=list)
    risk_level: str = "LOW"
    risk_score: float = 0.0
    summary: str = ""


# ── PatchForge-specific schemas ───────────────────────────────

class FixCandidate(BaseModel):
    """A single fix candidate generated by PatchForge."""
    id: str
    strategy: str
    description: str = ""
    confidence: float = 0.0
    risk: str = "LOW"
    breaking_change: bool = False
    shannon_verdict: str = ""       # PASS | FAIL | pending


class ShannonResult(BaseModel):
    """Shannon PoC verification result."""
    candidate_id: str
    shannon_verdict: str            # PASS | FAIL
    verification_method: str = ""
    details: str = ""
    confidence: float = 0.0
    timestamp: Optional[datetime] = None


class RemediationReport(BaseModel):
    """Complete output of a PatchForge remediation cycle."""
    success: bool = False
    selected_fix: Optional[FixCandidate] = None
    all_candidates: List[FixCandidate] = Field(default_factory=list)
    shannon_results: List[ShannonResult] = Field(default_factory=list)
    pr_url: str = ""
    summary: str = ""


# ── Ghost Detector-specific schemas ───────────────────────────

class GhostDependency(BaseModel):
    """A phantom dependency installed but not declared."""
    name: str
    version: str = "unknown"
    installed_by: str = "unknown"
    severity: Severity = Severity.MEDIUM
    reason: str = ""
    similar_to: Optional[str] = None
    typosquat_matches: List[dict] = Field(default_factory=list)


class TyposquatFinding(BaseModel):
    """A detected typosquat package."""
    legitimate_package: str
    suspicious_package: str
    levenshtein_similarity: float
    normalized_similarity: float
    soundex_match: bool
    combined_score: float
    technique: str


class GhostDetectorReport(BaseModel):
    """Complete output of a Ghost Detector scan."""
    ecosystem: str
    ghost_deps: List[GhostDependency] = Field(default_factory=list)
    ghost_count: int = 0
    typosquat_findings: List[dict] = Field(default_factory=list)
    typosquat_count: int = 0
    declared_count: int = 0
    installed_count: int = 0
    risk_level: str = "LOW"
    summary: str = ""


# ── SBOM Generator-specific schemas ───────────────────────────

class SBOMReport(BaseModel):
    """Output of an SBOM generation cycle."""
    cyclonedx: dict = Field(default_factory=dict)
    spdx: dict = Field(default_factory=dict)
    merge_result: Optional[dict] = None
    upload_cyclonedx: Optional[dict] = None
    upload_spdx: Optional[dict] = None
    component_count: int = 0
    summary: str = ""


# ── Pentest-specific schemas ──────────────────────────────────

class VulnCategory(str, Enum):
    AUTH = "auth"
    AUTHZ = "authz"
    XSS = "xss"
    INJECTION = "injection"
    SSRF = "ssrf"


class PentestPhase(str, Enum):
    PENDING = "pending"
    PHASE_1_SOURCE = "phase_1_source"
    PHASE_1_5_CPG = "phase_1_5_cpg"
    PHASE_2_RECON = "phase_2_recon"
    PHASE_3_HUNT = "phase_3_hunt"
    PHASE_4_EXPLOIT = "phase_4_exploit"
    PHASE_5_REPORT = "phase_5_report"
    COMPLETED = "completed"
    FAILED = "failed"


class VulnHypothesis(BaseModel):
    id: str
    category: VulnCategory
    title: str
    vulnerable_location: str
    overview: str
    severity: Severity = Severity.UNKNOWN
    prerequisites: List[str] = Field(default_factory=list)
    hypothesis_evidence: str = ""
    suggested_exploit: str = ""


class ExploitProof(BaseModel):
    hypothesis_id: str
    proven: bool = False
    exploit_steps: List[str] = Field(default_factory=list)
    raw_request: str = ""
    raw_response_excerpt: str = ""
    impact_description: str = ""
    notes: str = ""
    duration_ms: int = 0


class PentestFinding(BaseModel):
    """Merged hypothesis + proof, ready for report rendering."""
    id: str
    category: VulnCategory
    title: str
    severity: Severity
    vulnerable_location: str
    overview: str
    prerequisites: List[str] = Field(default_factory=list)
    exploit_steps: List[str] = Field(default_factory=list)
    raw_request: str = ""
    raw_response_excerpt: str = ""
    impact: str = ""
    notes: str = ""
    proven: bool = False


class PentestReport(BaseModel):
    session_id: str
    target_url: str
    repo: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    phase: PentestPhase = PentestPhase.PENDING
    findings: List[PentestFinding] = Field(default_factory=list)
    markdown: str = ""
    duration_seconds: float = 0.0
    error: Optional[str] = None
    phase_timings: dict = Field(default_factory=dict)
    phase_data: dict = Field(default_factory=dict)


# ── V2 Extensions ─────────────────────────────────────────────

class PentestSeed(BaseModel):
    source: str = "scan"  # scan | manual
    repo_url: str
    target_url: Optional[str] = None
    hypotheses: List[VulnHypothesis] = Field(default_factory=list)
    truncation_meta: dict = Field(default_factory=dict)


class ReasoningTrace(BaseModel):
    root_cause: str
    exploit_path: List[str] = Field(default_factory=list)
    why_patch_fixes: str
    residual_risks: List[str] = Field(default_factory=list)
    lesson: str = ""
    tags: List[str] = Field(default_factory=list)


class ReasoningGenerator(BaseModel):
    model: str
    backend: str
    prompt_sha256: str
    temperature: float = 0.3
    tokens_in: int = 0
    tokens_out: int = 0


class ReasoningBlock(BaseModel):
    generated_at: datetime
    generator: ReasoningGenerator
    trace: ReasoningTrace
    human_edits: Optional[ReasoningTrace] = None
    confidence_self_reported: float = 0.0
