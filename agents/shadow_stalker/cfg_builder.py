"""
Shadow Stalker — Stage 2: Control Flow Graph Builder

Builds a lightweight CFG from tree-sitter concrete syntax trees.
Supports Python, JavaScript, Go, and Rust.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

# tree-sitter import with graceful fallback
_TREE_SITTER_AVAILABLE = False
try:
    from tree_sitter_languages import get_parser
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    try:
        import tree_sitter  # noqa: F401
        _TREE_SITTER_AVAILABLE = True
    except ImportError:
        pass

_LANG_MAP = {
    "python": "python", "javascript": "javascript", "js": "javascript",
    "go": "go", "golang": "go", "rust": "rust", "rs": "rust",
}

_BRANCH_NODES = {
    "python": {"if_statement", "elif_clause", "else_clause", "for_statement",
               "while_statement", "try_statement", "except_clause", "finally_clause",
               "with_statement", "match_statement", "case_clause"},
    "javascript": {"if_statement", "else_clause", "for_statement", "for_in_statement",
                    "while_statement", "try_statement", "catch_clause", "finally_clause",
                    "switch_statement", "switch_case"},
    "go": {"if_statement", "for_statement", "select_statement", "switch_statement",
            "case_clause", "default_case"},
    "rust": {"if_expression", "else_clause", "for_expression", "while_expression",
             "loop_expression", "match_expression", "match_arm"},
}

_ERROR_HANDLER_NODES = {
    "python": {"except_clause", "finally_clause"},
    "javascript": {"catch_clause", "finally_clause"},
    "go": set(), "rust": set(),
}

_CALL_NODES = {
    "python": {"call"}, "javascript": {"call_expression"},
    "go": {"call_expression"}, "rust": {"call_expression", "macro_invocation"},
}

_FUNCTION_DEF_NODES = {
    "python": {"function_definition", "async_function_definition"},
    "javascript": {"function_declaration", "arrow_function", "method_definition"},
    "go": {"function_declaration", "method_declaration"},
    "rust": {"function_item"},
}


@dataclass
class BasicBlock:
    """A basic block in the CFG."""
    id: str
    start_line: int
    end_line: int
    node_type: str
    text_preview: str = ""
    is_error_handler: bool = False
    is_dead_code: bool = False
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)


@dataclass
class CFG:
    """Control Flow Graph for a single function or module."""
    function_name: str
    language: str
    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    entry_block: Optional[str] = None
    exit_blocks: list[str] = field(default_factory=list)

    @property
    def block_count(self) -> int:
        return len(self.blocks)

    def get_error_handler_blocks(self) -> list[BasicBlock]:
        return [b for b in self.blocks.values() if b.is_error_handler]

    def get_dead_code_blocks(self) -> list[BasicBlock]:
        return [b for b in self.blocks.values() if b.is_dead_code]

    def get_blocks_with_calls(self, call_names: set[str]) -> list[BasicBlock]:
        return [b for b in self.blocks.values() if any(c in call_names for c in b.calls)]


@dataclass
class CallGraphEntry:
    """An edge in the call graph: caller -> callee."""
    caller: str
    callee: str
    line: int
    in_error_handler: bool = False
    in_dead_code: bool = False


# ═══════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════

def build_cfg(source_code: str, language: str) -> list[CFG]:
    """Parse source code with tree-sitter and build CFGs per function."""
    lang_key = _LANG_MAP.get(language.lower(), language.lower())
    if not _TREE_SITTER_AVAILABLE:
        return [_build_fallback_cfg(source_code, lang_key)]
    try:
        parser = get_parser(lang_key)
    except Exception:
        return [_build_fallback_cfg(source_code, lang_key)]

    tree = parser.parse(source_code.encode("utf-8"))
    root = tree.root_node
    cfgs = []
    func_def_types = _FUNCTION_DEF_NODES.get(lang_key, set())

    for node in _walk(root):
        if node.type in func_def_types:
            name = _func_name(node)
            cfgs.append(_cfg_from_node(node, name, lang_key, source_code))

    mod = _module_cfg(root, lang_key, source_code, func_def_types)
    if mod.block_count > 0:
        cfgs.insert(0, mod)
    return cfgs


def find_unreachable_blocks(cfgs: list[CFG]) -> list[BasicBlock]:
    """Return blocks only reachable via error handlers or marked dead."""
    return [b for cfg in cfgs for b in cfg.blocks.values()
            if b.is_dead_code or b.is_error_handler]


def extract_call_graph(cfgs: list[CFG]) -> list[CallGraphEntry]:
    """Extract call graph edges from CFGs."""
    entries = []
    for cfg in cfgs:
        for block in cfg.blocks.values():
            for callee in block.calls:
                entries.append(CallGraphEntry(
                    caller=cfg.function_name, callee=callee,
                    line=block.start_line,
                    in_error_handler=block.is_error_handler,
                    in_dead_code=block.is_dead_code,
                ))
    return entries


# ═══════════════════════════════════════════════════════════
# Internal helpers
# ═══════════════════════════════════════════════════════════

def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _bid(ntype, sl, el):
    return hashlib.md5(f"{ntype}:{sl}:{el}".encode()).hexdigest()[:10]


def _func_name(node) -> str:
    for child in node.children:
        if child.type in ("identifier", "name", "property_identifier"):
            t = child.text
            return t.decode("utf-8") if isinstance(t, bytes) else t
    return "<anonymous>"


def _extract_calls(node, lang_key):
    ct = _CALL_NODES.get(lang_key, {"call_expression"})
    calls = []
    for child in _walk(node):
        if child.type in ct:
            n = _call_target(child)
            if n:
                calls.append(n)
    return calls


def _call_target(call_node) -> str:
    if not call_node.children:
        return ""
    fn = call_node.children[0]
    if fn.type in ("identifier", "name"):
        t = fn.text
        return t.decode("utf-8") if isinstance(t, bytes) else t
    if fn.type in ("attribute", "member_expression", "selector_expression",
                    "field_expression", "scoped_identifier"):
        t = fn.text
        full = t.decode("utf-8") if isinstance(t, bytes) else t
        return full.split(".")[-1] if "." in full else full
    return ""


def _is_dead(node, lang_key) -> bool:
    if lang_key == "python" and node.type == "if_statement":
        for child in node.children:
            if child.type in ("false", "none"):
                return True
            if child.type == "integer" and child.text in (b"0", b"00"):
                return True
    return False


def _node_text(node, limit=120) -> str:
    t = node.text
    s = t.decode("utf-8") if isinstance(t, bytes) else t
    return s[:limit]


def _cfg_from_node(func_node, func_name, lang_key, source_code):
    cfg = CFG(function_name=func_name, language=lang_key)
    bt = _BRANCH_NODES.get(lang_key, set())
    et = _ERROR_HANDLER_NODES.get(lang_key, set())
    _proc_children(func_node, cfg, bt, et, lang_key, False, False)
    if cfg.blocks:
        sb = sorted(cfg.blocks.values(), key=lambda b: b.start_line)
        cfg.entry_block = sb[0].id
        cfg.exit_blocks = [sb[-1].id]
        for i in range(len(sb) - 1):
            if sb[i + 1].id not in sb[i].successors:
                sb[i].successors.append(sb[i + 1].id)
            if sb[i].id not in sb[i + 1].predecessors:
                sb[i + 1].predecessors.append(sb[i].id)
    return cfg


def _module_cfg(root, lang_key, source_code, func_defs):
    cfg = CFG(function_name="<module>", language=lang_key)
    bt = _BRANCH_NODES.get(lang_key, set())
    et = _ERROR_HANDLER_NODES.get(lang_key, set())
    for child in root.children:
        if child.type not in func_defs:
            _proc_node(child, cfg, bt, et, lang_key, False, False)
    return cfg


def _proc_children(node, cfg, bt, et, lk, p_err, p_dead):
    for child in node.children:
        _proc_node(child, cfg, bt, et, lk, p_err, p_dead)


def _proc_node(node, cfg, bt, et, lk, p_err, p_dead):
    sl = node.start_point[0] + 1
    el = node.end_point[0] + 1
    is_err = p_err or node.type in et
    is_dead = p_dead or _is_dead(node, lk)

    if node.type in bt:
        block_id = _bid(node.type, sl, el)
        calls = _extract_calls(node, lk)
        cfg.blocks[block_id] = BasicBlock(
            id=block_id, start_line=sl, end_line=el, node_type=node.type,
            text_preview=_node_text(node), is_error_handler=is_err,
            is_dead_code=is_dead, calls=calls,
        )
        _proc_children(node, cfg, bt, et, lk, is_err, is_dead)
    elif node.type in _CALL_NODES.get(lk, set()):
        block_id = _bid(node.type, sl, el)
        calls = _extract_calls(node, lk)
        cfg.blocks[block_id] = BasicBlock(
            id=block_id, start_line=sl, end_line=el, node_type=node.type,
            text_preview=_node_text(node), is_error_handler=is_err,
            is_dead_code=is_dead, calls=calls,
        )
    else:
        _proc_children(node, cfg, bt, et, lk, is_err, is_dead)


def _build_fallback_cfg(source_code, lang_key):
    """Fallback CFG when tree-sitter is unavailable — regex-based."""
    lines = source_code.splitlines()
    cfg = CFG(function_name="<module>", language=lang_key)
    if not lines:
        return cfg
    call_pat = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_.]*)\s*\(')
    calls = list({m.group(1).split(".")[-1] for line in lines for m in call_pat.finditer(line)})
    block_id = _bid("module", 1, len(lines))
    cfg.blocks[block_id] = BasicBlock(
        id=block_id, start_line=1, end_line=len(lines), node_type="module",
        text_preview=source_code[:120], calls=calls,
    )
    cfg.entry_block = block_id
    cfg.exit_blocks = [block_id]
    return cfg
