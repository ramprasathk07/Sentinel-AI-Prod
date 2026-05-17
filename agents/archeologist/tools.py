import json
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from core.config import settings

# ─────────────────────────────────────────────────────────────
# HTTP client (shared, reusable)
# ─────────────────────────────────────────────────────────────
_http = httpx.AsyncClient(timeout=30.0, follow_redirects=True)


# ═════════════════════════════════════════════════════════════
# TOOL 1 — OSV.dev Vulnerability Query
# ═════════════════════════════════════════════════════════════

def query_osv(package_name: str, version: str, ecosystem: str) -> dict:
    """
    Query the OSV.dev vulnerability database for a specific package.

    Args:
        package_name: Name of the package (e.g. 'requests', 'lodash').
        version:      Installed version string (e.g. '2.28.1').
        ecosystem:    Package ecosystem — one of 'PyPI', 'npm', 'Go', 'crates.io'.

    Returns:
        A dict with 'vulnerabilities' (list of CVE findings) and 'count'.
    """
    import httpx as _httpx  # sync inside tool for ADK compatibility

    url = f"{settings.OSV_API_URL}/query"
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": ecosystem},
    }

    try:
        resp = _httpx.post(url, json=payload, timeout=20.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "vulnerabilities": [], "count": 0}

    vulns = []
    for v in data.get("vulns", []):
        severity_score = None
        severity_label = "UNKNOWN"

        # Extract CVSS from severity array
        for sev in v.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                try:
                    score_str = sev["score"]
                    # CVSS vector string — parse base score from metrics
                    severity_score = _extract_cvss_base(score_str)
                    severity_label = _cvss_to_label(severity_score)
                except Exception:
                    pass

        vulns.append({
            "cve_id": _first_alias(v, prefix="CVE-"),
            "osv_id": v.get("id", ""),
            "summary": v.get("summary", "")[:300],
            "severity": severity_label,
            "cvss_score": severity_score,
            "source": "osv",
            "references": [r.get("url", "") for r in v.get("references", [])[:5]],
        })

    return {
        "package": package_name,
        "version": version,
        "ecosystem": ecosystem,
        "vulnerabilities": vulns,
        "count": len(vulns),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 2 — NVD (National Vulnerability Database) Query
# ═════════════════════════════════════════════════════════════

def query_nvd(cve_id: str) -> dict:
    """
    Look up a specific CVE ID in the NIST NVD database for detailed scoring.

    Args:
        cve_id: A CVE identifier, e.g. 'CVE-2023-12345'.

    Returns:
        A dict with CVSS v3.1 base score, severity, description, and references.
    """
    import httpx as _httpx

    headers = {}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY

    url = f"{settings.NVD_API_URL}"
    params = {"cveId": cve_id}

    try:
        resp = _httpx.get(url, params=params, headers=headers, timeout=20.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "cve_id": cve_id}

    items = data.get("vulnerabilities", [])
    if not items:
        return {"cve_id": cve_id, "found": False}

    cve_data = items[0].get("cve", {})
    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0
    cvss_v3 = (
        metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31")
        else metrics.get("cvssMetricV30", [{}])[0] if metrics.get("cvssMetricV30")
        else {}
    )
    cvss_data = cvss_v3.get("cvssData", {})

    descriptions = cve_data.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    return {
        "cve_id": cve_id,
        "found": True,
        "description": desc_en[:500],
        "cvss_score": cvss_data.get("baseScore"),
        "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
        "attack_vector": cvss_data.get("attackVector", ""),
        "exploitability_score": cvss_v3.get("exploitabilityScore"),
        "impact_score": cvss_v3.get("impactScore"),
        "references": [
            r.get("url", "") for r in cve_data.get("references", [])[:5]
        ],
    }


# ═════════════════════════════════════════════════════════════
# TOOL 3 — npm Maintainer Check + One-Week Rule
# ═════════════════════════════════════════════════════════════

def check_npm_maintainer(package_name: str) -> dict:
    """
    Check an npm package's maintainer information and enforce the One-Week Rule.
    If any maintainer account was created less than 7 days ago, the package is
    flagged as CRITICAL regardless of CVE status.

    Args:
        package_name: The npm package name (e.g. 'express', 'lodash').

    Returns:
        A dict with maintainer details, account ages, and any one_week_rule flags.
    """
    import httpx as _httpx

    # Step 1: Get package metadata for maintainers list
    pkg_url = f"{settings.NPM_REGISTRY_URL}/{package_name}"

    try:
        resp = _httpx.get(pkg_url, timeout=15.0)
        resp.raise_for_status()
        pkg_data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "package": package_name}

    maintainers = pkg_data.get("maintainers", [])
    latest_version = pkg_data.get("dist-tags", {}).get("latest", "unknown")

    results = []
    one_week_flags = []

    for m in maintainers:
        username = m.get("name", "")
        if not username:
            continue

        # Step 2: Get user profile for account creation date
        user_url = f"{settings.NPM_REGISTRY_URL}/-/user/org.couchdb.user:{username}"
        account_created = None
        account_age_days = None
        flagged = False

        try:
            user_resp = _httpx.get(user_url, timeout=10.0)
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                created_str = user_data.get("created")
                if created_str:
                    account_created = datetime.fromisoformat(
                        created_str.replace("Z", "+00:00")
                    )
                    account_age_days = (
                        datetime.now(timezone.utc) - account_created
                    ).days
                    if account_age_days < settings.ONE_WEEK_DAYS:
                        flagged = True
        except Exception:
            pass

        entry = {
            "username": username,
            "email": m.get("email", ""),
            "account_created": str(account_created) if account_created else None,
            "account_age_days": account_age_days,
            "one_week_rule_flag": flagged,
        }
        results.append(entry)

        if flagged:
            one_week_flags.append({
                "package": package_name,
                "maintainer": username,
                "account_age_days": account_age_days,
                "severity": "CRITICAL",
                "reason": (
                    f"Maintainer '{username}' account is only "
                    f"{account_age_days} days old (< {settings.ONE_WEEK_DAYS} day threshold). "
                    f"This is a supply-chain risk indicator."
                ),
            })

    return {
        "package": package_name,
        "latest_version": latest_version,
        "registry": "npm",
        "maintainers": results,
        "one_week_flags": one_week_flags,
        "total_maintainers": len(results),
        "flagged_count": len(one_week_flags),
    }


# ═════════════════════════════════════════════════════════════
# TOOL 4 — PyPI Package + Maintainer Check + One-Week Rule
# ═════════════════════════════════════════════════════════════

def check_pypi_package(package_name: str) -> dict:
    """
    Check a PyPI package's metadata and release history for supply-chain risk.
    Applies the One-Week Rule: if the package was first released less than
    7 days ago by a new author, it is flagged CRITICAL.

    Args:
        package_name: The PyPI package name (e.g. 'requests', 'flask').

    Returns:
        A dict with author info, release timeline, and any one_week_rule flags.
    """
    import httpx as _httpx

    url = f"{settings.PYPI_API_URL}/pypi/{package_name}/json"

    try:
        resp = _httpx.get(url, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return {"error": str(exc), "package": package_name}

    info = data.get("info", {})
    releases = data.get("releases", {})

    author = info.get("author", "") or info.get("maintainer", "")
    author_email = info.get("author_email", "") or info.get("maintainer_email", "")
    latest_version = info.get("version", "unknown")

    # Find first-ever release date
    first_release_date = None
    for version_key in sorted(releases.keys()):
        files = releases[version_key]
        if files:
            upload_time = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
            if upload_time:
                try:
                    first_release_date = datetime.fromisoformat(
                        upload_time.replace("Z", "+00:00")
                    )
                except Exception:
                    pass
                break

    # Find latest release date
    latest_release_date = None
    latest_files = releases.get(latest_version, [])
    if latest_files:
        upload_time = latest_files[0].get("upload_time_iso_8601") or latest_files[0].get("upload_time")
        if upload_time:
            try:
                latest_release_date = datetime.fromisoformat(
                    upload_time.replace("Z", "+00:00")
                )
            except Exception:
                pass

    # One-Week Rule: flag if first release is < 7 days old
    one_week_flags = []
    package_age_days = None
    if first_release_date:
        now = datetime.now(timezone.utc)
        if first_release_date.tzinfo is None:
            first_release_date = first_release_date.replace(tzinfo=timezone.utc)
        package_age_days = (now - first_release_date).days

        if package_age_days < settings.ONE_WEEK_DAYS:
            one_week_flags.append({
                "package": package_name,
                "maintainer": author,
                "package_age_days": package_age_days,
                "severity": "CRITICAL",
                "reason": (
                    f"Package '{package_name}' first appeared on PyPI only "
                    f"{package_age_days} days ago (< {settings.ONE_WEEK_DAYS} day threshold). "
                    f"Combined with author '{author}', this is a supply-chain risk indicator."
                ),
            })

    return {
        "package": package_name,
        "latest_version": latest_version,
        "registry": "pypi",
        "author": author,
        "author_email": author_email,
        "total_releases": len(releases),
        "first_release_date": str(first_release_date) if first_release_date else None,
        "latest_release_date": str(latest_release_date) if latest_release_date else None,
        "package_age_days": package_age_days,
        "project_urls": info.get("project_urls", {}),
        "one_week_flags": one_week_flags,
        "flagged": len(one_week_flags) > 0,
    }


# ═════════════════════════════════════════════════════════════
# TOOL 5 — Lockfile Parser
# ═════════════════════════════════════════════════════════════

def parse_lockfile(lockfile_content: str, lockfile_type: str) -> dict:
    """
    Parse a lockfile / dependency manifest to extract package names and versions.

    Supports: package.json (npm), requirements.txt (pip), go.sum (Go), Cargo.lock (Rust).

    Args:
        lockfile_content: The raw text content of the lockfile.
        lockfile_type:    One of 'package.json', 'requirements.txt', 'go.sum', 'Cargo.lock'.

    Returns:
        A dict with 'dependencies' — a list of {name, version, ecosystem} objects.
    """
    parsers = {
        "package.json": _parse_package_json,
        "requirements.txt": _parse_requirements_txt,
        "go.sum": _parse_go_sum,
        "Cargo.lock": _parse_cargo_lock,
    }

    parser = parsers.get(lockfile_type)
    if not parser:
        return {
            "error": f"Unsupported lockfile type: {lockfile_type}. "
                     f"Supported: {', '.join(parsers.keys())}",
            "dependencies": [],
        }

    try:
        deps = parser(lockfile_content)
    except Exception as exc:
        return {"error": str(exc), "dependencies": []}

    return {
        "lockfile_type": lockfile_type,
        "dependencies": deps,
        "count": len(deps),
    }


# ─────────────────────────────────────────────────────────────
# Lockfile parser helpers (private)
# ─────────────────────────────────────────────────────────────

def _parse_package_json(content: str) -> list[dict]:
    data = json.loads(content)
    deps = {}
    deps.update(data.get("dependencies", {}))
    deps.update(data.get("devDependencies", {}))
    return [
        {"name": name, "version": ver.lstrip("^~>=<"), "ecosystem": "npm"}
        for name, ver in deps.items()
    ]


def _parse_requirements_txt(content: str) -> list[dict]:
    results = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.2.3, package>=1.2.3, package~=1.2.3
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*[=~><!]+\s*([^\s,;]+)", line)
        if match:
            results.append({
                "name": match.group(1),
                "version": match.group(2),
                "ecosystem": "PyPI",
            })
        else:
            # Bare package name without version
            pkg = re.match(r"^([a-zA-Z0-9_\-\.]+)", line)
            if pkg:
                results.append({
                    "name": pkg.group(1),
                    "version": "latest",
                    "ecosystem": "PyPI",
                })
    return results


def _parse_go_sum(content: str) -> list[dict]:
    seen = set()
    results = []
    for line in content.strip().splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            module = parts[0]
            version = parts[1].split("/")[0]  # strip /go.mod suffix
            key = (module, version)
            if key not in seen:
                seen.add(key)
                results.append({
                    "name": module,
                    "version": version.lstrip("v"),
                    "ecosystem": "Go",
                })
    return results


def _parse_cargo_lock(content: str) -> list[dict]:
    results = []
    current_name = None
    current_version = None
    for line in content.strip().splitlines():
        line = line.strip()
        if line.startswith("name = "):
            current_name = line.split('"')[1] if '"' in line else None
        elif line.startswith("version = ") and current_name:
            current_version = line.split('"')[1] if '"' in line else None
            results.append({
                "name": current_name,
                "version": current_version,
                "ecosystem": "crates.io",
            })
            current_name = None
            current_version = None
    return results


# ─────────────────────────────────────────────────────────────
# CVSS helper utilities (private)
# ─────────────────────────────────────────────────────────────

def _extract_cvss_base(vector_or_score: str) -> Optional[float]:
    """Try to parse a CVSS base score from a vector string or raw float."""
    try:
        return float(vector_or_score)
    except (ValueError, TypeError):
        pass
    # Try to extract from CVSS:3.1/AV:N/AC:L/... format — score not in vector,
    # so return None and let NVD lookup provide the actual score.
    return None


def _cvss_to_label(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _first_alias(vuln: dict, prefix: str = "CVE-") -> str:
    """Extract the first alias matching a prefix (e.g. CVE-) from an OSV vuln."""
    for alias in vuln.get("aliases", []):
        if alias.startswith(prefix):
            return alias
    return vuln.get("id", "")
