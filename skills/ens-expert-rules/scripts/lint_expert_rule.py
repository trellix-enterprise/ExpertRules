#!/usr/bin/env python3
"""Deterministic quality checker for Trellix ENS Exploit Prevention Expert Rules.

Standard-library only, Python 3.8+. Offline. Report-only (no auto-fix).
Run `python lint_expert_rule.py --help` for usage.
"""
from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import re
import sys
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

if sys.version_info < (3, 8):  # pragma: no cover - friendly message for old interpreters
    sys.stderr.write("lint_expert_rule.py needs Python 3.8 or newer "
                     f"(this is {sys.version.split()[0]}); try 'python3' or 'py -3'.\n")
    sys.exit(2)

TOOL_NAME = "ens-expert-rule-lint"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/trellix-enterprise/ExpertRules/tree/main/skills"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
class Severity(enum.IntEnum):
    INFO = 1
    WARNING = 2
    ERROR = 3


@dataclasses.dataclass
class Finding:
    code: str
    severity: Severity
    line: int
    message: str
    hint: str = ""

    def format(self, path: str) -> str:
        sev = self.severity.name
        out = f"{path}:{self.line}: {sev} [{self.code}] {self.message}"
        return out + (f"\n    hint: {self.hint}" if self.hint else "")


# --------------------------------------------------------------------------- #
# Compiler-derived data tables
# --------------------------------------------------------------------------- #
MAX_CMD_LEVEL = 12

# Stable catalogue of every finding this tool can emit, for the SARIF rules
# section. Order is the reporting order used in the driver.rules array.
RULE_CATALOGUE: List[Tuple[str, Severity, str]] = [
    ("E101", Severity.ERROR, "Unbalanced braces or quotes"),
    ("E102", Severity.ERROR, "Command nesting too deep"),
    ("E110", Severity.ERROR, "Invalid command hierarchy"),
    ("E121", Severity.ERROR, "Unknown Reaction or Severity value"),
    ("E122", Severity.ERROR, "Text before the first Rule breaks console Reaction"),
    ("E130", Severity.ERROR, "Unknown Match object type"),
    ("E131", Severity.ERROR, "Initiator Match must be PROCESS"),
    ("E140", Severity.ERROR, "Invalid number of arguments"),
    ("E141", Severity.ERROR, "Several -v/-l entries on one line never match"),
    ("E150", Severity.ERROR, "Unknown or unsupported access token"),
    ("E151", Severity.ERROR, "Smart match requires a -type option"),
    ("E152", Severity.ERROR, "Unknown -type value"),
    ("E153", Severity.ERROR, "Both -name and -key specified"),
    ("E154", Severity.ERROR, "Unknown match type"),
    ("E155", Severity.ERROR, "Unknown symbolic value for a bitmask match type"),
    ("E160", Severity.ERROR, "Next_Process_Behavior requires a Target"),
    ("E170", Severity.ERROR, "Duplicate Rule or Policy id"),
    ("W201", Severity.WARNING, "Unscoped initiator matches every process"),
    ("W202", Severity.WARNING, "READ access is high-frequency and costly"),
    ("W203", Severity.WARNING, "Single backslash in a quoted path"),
    ("W205", Severity.WARNING, "Token requires a newer ENS version"),
    ("W206", Severity.WARNING, "Duplicate AggregateMatch -xtype"),
    ("W207", Severity.WARNING, "nt_access mask has undefined bits"),
    ("W208", Severity.WARNING, "Wildcard inside a registry root"),
    ("W209", Severity.WARNING, "NUL (\\0) in a value: only the first string is compared"),
    ("I301", Severity.INFO, "Trailing whitespace"),
    ("I302", Severity.INFO, "nt_access mask decoded to named rights"),
]

# Parent command -> permitted direct child commands.
HIERARCHY: Dict[str, Set[str]] = {
    "Policy": {"Description", "Aggregate", "Rule", "Severity"},
    "Rule": {
        "Description", "Group", "Reaction", "Severity",
        "Process", "Target", "Initiator",
    },
    "Process": {"Include", "Exclude"},
    "Initiator": {"Match"},
    "Target": {"Match", "Next_Process_Behavior"},
    "Match": {"Include", "Exclude"},
    "Aggregate": {"Description", "Include", "Exclude"},
    "AggregateMatch": {"Include", "Exclude"},
}

OBJECT_TYPES: Set[str] = {
    "FILE", "KEY", "VALUE", "PROCESS", "THREAD",
    "SECTION", "NAMEDSECTION", "DISK", "SERVICE",
}

AAC_ACCESS: Set[str] = {
    "CREATE", "WRITE", "DELETE", "READ", "EXECUTE", "ENUM", "START_DEVICE",
    "LOAD_KEY", "REPLACE_KEY", "RESTORE_KEY", "LOAD_IMAGE", "TERMINATING",
    "OPEN_NAMEDSECTION", "WRITE_ATTRIBUTE", "OBJECT_EXISTS", "CLEANUP",
    "SET_REPARSE", "CLOSE", "CONNECT_NAMED_PIPE", "QUERY", "SET_SECURITY",
    "LOCK_RANGE", "WRITE_DATA", "READ_DATA", "RENAME", "SET_FILE_LENGTH",
    "CREATE_BINDLINK", "POST", "ALL",
}

REACTIONS: Set[str] = {
    "ALLOW", "ASK_PP", "ASK_KERNEL", "BLOCK", "BREAK",
    "TERMINATE_PROCESS", "EXCEPTIONAL_ALLOW", "SCAN",
}

SEVERITIES: Dict[str, int] = {
    "CRITICAL": 5, "MAJOR": 4, "MINOR": 3,
    "WARNING": 2, "WARN": 2, "INFO": 1, "INFORMATIONAL": 1,
}

DATA_TYPES: Set[str] = {
    "INT8", "INT16", "INT32", "INT64", "STRING", "BLOB", "BINARY",
    "BITMASK", "MULTI_SZ", "MULTI_STRING", "EXPANDABLE_STRING",
    "VARIABLE", "PATH",
}

# Match types that require an explicit -type option.
TYPE_REQUIRED: Set[str] = {"REGVAL_DATA"}

# Match types the rule compiler accepts after Include/Exclude (hostips ApRc
# g_XMatchTypes, case-sensitive; the AAC_MATCH_ long form is also accepted).
# USER_NAME / GROUP_NAME / DRIVE_TYPE are compiler aliases for USER_SID /
# GROUP_SID / FILE_PROPERTIES.
MATCH_TYPES: Set[str] = {
    "OBJECT_NAME", "DESCRIPTION", "VERSION", "CERT_NAME", "CERT_NAME_CHAINED",
    "CERT_HASH", "VTP_TRUST", "VTP_VALIDATION_STATE", "PROCESS_CMD_LINE", "USER_SID",
    "LBA", "ACCESS_MASK", "OS_VERSION", "ENV_VAR", "OBJECT_EXISTS", "GROUP_SID", "MD5",
    "SHA1", "SHA2_256", "SHA2_384", "SHA2_512", "PE_MD5", "PE_SHA1", "PE_SHA2_256",
    "PE_SHA2_384", "PE_SHA2_512", "STORAGE_BUS_TYPE", "PARTITION_STYLE", "LBA_FROM_END",
    "DISK_REGION", "THREAD_ID", "AUTHENTICATION_ID", "PROCESSOR_MODE", "PROCESS_ID",
    "IMAGE_BASE_ADDRESS", "IMAGE_PROPERTIES", "IMAGE_ENTRY_POINT", "IS_DIRECTORY",
    "REMOTE_MACHINE_ADDRESS", "PROCESS_STATE_BITS", "SESSION_ID", "WOW64", "PE",
    "DISKIO_HOOK", "LBA2FILE", "DLL_LOADED", "OPERATION_STATUS", "CACHE_ATTRIBUTE",
    "PRODUCT_NAME", "KERNEL_CALLER_NAME", "OBJECT_SIZE", "FILE_ATTRIBUTES", "FILE_CTIME",
    "FILE_MTIME", "FILE_ATIME", "VERSION_RESOURCE", "NT_ACCESS_MASK",
    "TARGET_OBJECT_NAME", "VTP_PRIVILEGES", "FILE_PROPERTIES", "IS_TRANSACTED",
    "REGVAL_DATA", "USER_NAME", "GROUP_NAME", "DRIVE_TYPE",
}

# Symbolic names the compiler's bitmask converters accept (ApRc AacHelpers.cpp
# To* functions). Numbers (decimal, 0x hex, 0B binary) are always accepted.
BITMASK_VALUE_NAMES: Dict[str, Set[str]] = {
    "FILE_ATTRIBUTES": {
        "ARCHIVE", "HIDDEN", "NORMAL", "NOT_CONTENT_INDEXED", "OFFLINE", "READONLY",
        "SYSTEM", "TEMPORARY", "DIRECTORY", "DEVICE", "SPARSE_FILE", "REPARSE_POINT",
        "COMPRESSED", "ENCRYPTED", "VIRTUAL",
    },
    "FILE_PROPERTIES": {
        "FILE_NETWORK", "FILE_REMOVABLE", "FILE_FLOPPY", "FILE_CD", "FILE_DFS",
        "FILE_REDIRECTOR",
    },
    "DRIVE_TYPE": {"DT_FLOPPY", "DT_CD_DVD", "DT_REMOVABLE", "DT_FIXED", "DT_NETWORK"},
    "DISK_REGION": {"UNKNOWN", "MBR", "VBR", "PARTITION", "NOT_PARTITIONED",
                    "MULTI_PARTITION"},
    "IMAGE_PROPERTIES": {"64_BIT", "SYSTEM_MODE", "MAPPED_TO_ALL_PROCESSES", "MANAGED",
                         "DLL"},
    "VTP_PRIVILEGES": {"NONE", "IOCTL", "ISG"},
    "VTP_VALIDATION_STATE": {"TAINTED_MODULE", "TAINTED_PROTECT"},
    "VTP_TRUST": {"TRUE", "T", "FALSE", "F"},
    "PROCESSOR_MODE": {"USER", "U", "KERNEL", "K"},
}
_BITMASK_OPTIONS: Dict[str, str] = {
    "-file_properties": "FILE_PROPERTIES", "-file_attributes": "FILE_ATTRIBUTES",
    "-vtp_privileges": "VTP_PRIVILEGES", "-disk_region": "DISK_REGION",
    "-image_properties": "IMAGE_PROPERTIES", "-vtp_trust": "VTP_TRUST",
    "-processor_mode": "PROCESSOR_MODE",
}
_BITMASK_NUMBER = re.compile(r"^(0[xX][0-9a-fA-F]+|0[bB][01]+|[0-9]+)$")

# Token -> minimum ENS version that introduced it.
VERSION_GATED: Dict[str, str] = {
    "LOCK_RANGE": "15.5", "WRITE_DATA": "15.5", "READ_DATA": "15.5",
    "RENAME": "15.5", "SET_FILE_LENGTH": "15.5", "TARGET_OBJECT_NAME": "15.5",
    "VTP_PRIVILEGES": "15.5", "FILE_PROPERTIES": "15.5",
    "IS_TRANSACTED": "15.8", "REGVAL_DATA": "18.6", "CREATE_BINDLINK": "26.5",
}

# Standard + generic ACCESS_MASK bits (identical for every object type).
_STANDARD_BITS: Dict[int, str] = {
    0x00010000: "DELETE",
    0x00020000: "READ_CONTROL",
    0x00040000: "WRITE_DAC",
    0x00080000: "WRITE_OWNER",
    0x00100000: "SYNCHRONIZE",
    0x01000000: "ACCESS_SYSTEM_SECURITY",
    0x02000000: "MAXIMUM_ALLOWED",
    0x10000000: "GENERIC_ALL",
    0x20000000: "GENERIC_EXECUTE",
    0x40000000: "GENERIC_WRITE",
    0x80000000: "GENERIC_READ",
}

# Object-type-specific low-word (specific rights) ACCESS_MASK bits.
_NT_ACCESS_SPECIFIC: Dict[str, Dict[int, str]] = {
    "PROCESS": {
        0x0001: "PROCESS_TERMINATE",
        0x0002: "PROCESS_CREATE_THREAD",
        0x0004: "PROCESS_SET_SESSIONID",
        0x0008: "PROCESS_VM_OPERATION",
        0x0010: "PROCESS_VM_READ",
        0x0020: "PROCESS_VM_WRITE",
        0x0040: "PROCESS_DUP_HANDLE",
        0x0080: "PROCESS_CREATE_PROCESS",
        0x0100: "PROCESS_SET_QUOTA",
        0x0200: "PROCESS_SET_INFORMATION",
        0x0400: "PROCESS_QUERY_INFORMATION",
        0x0800: "PROCESS_SUSPEND_RESUME",
        0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
        0x2000: "PROCESS_SET_LIMITED_INFORMATION",
    },
    "THREAD": {
        0x0001: "THREAD_TERMINATE",
        0x0002: "THREAD_SUSPEND_RESUME",
        0x0008: "THREAD_GET_CONTEXT",
        0x0010: "THREAD_SET_CONTEXT",
        0x0020: "THREAD_SET_INFORMATION",
        0x0040: "THREAD_QUERY_INFORMATION",
        0x0080: "THREAD_SET_THREAD_TOKEN",
        0x0100: "THREAD_IMPERSONATE",
        0x0200: "THREAD_DIRECT_IMPERSONATION",
        0x0400: "THREAD_SET_LIMITED_INFORMATION",
        0x0800: "THREAD_QUERY_LIMITED_INFORMATION",
        0x1000: "THREAD_RESUME",
    },
    "FILE": {
        0x0001: "FILE_READ_DATA",
        0x0002: "FILE_WRITE_DATA",
        0x0004: "FILE_APPEND_DATA",
        0x0008: "FILE_READ_EA",
        0x0010: "FILE_WRITE_EA",
        0x0020: "FILE_EXECUTE",
        0x0040: "FILE_DELETE_CHILD",
        0x0080: "FILE_READ_ATTRIBUTES",
        0x0100: "FILE_WRITE_ATTRIBUTES",
    },
    "KEY": {
        0x0001: "KEY_QUERY_VALUE",
        0x0002: "KEY_SET_VALUE",
        0x0004: "KEY_CREATE_SUB_KEY",
        0x0008: "KEY_ENUMERATE_SUB_KEYS",
        0x0010: "KEY_NOTIFY",
        0x0020: "KEY_CREATE_LINK",
        0x0100: "KEY_WOW64_64KEY",
        0x0200: "KEY_WOW64_32KEY",
    },
    "SECTION": {
        0x0001: "SECTION_QUERY",
        0x0002: "SECTION_MAP_WRITE",
        0x0004: "SECTION_MAP_READ",
        0x0008: "SECTION_MAP_EXECUTE",
        0x0010: "SECTION_EXTEND_SIZE",
        0x0020: "SECTION_MAP_EXECUTE_EXPLICIT",
    },
}

# Object types for which -nt_access is not interpreted.
NT_ACCESS_UNSUPPORTED: Set[str] = {"VALUE"}
# Object types the compiler's Cvt2AccessBits rejects outright for -nt_access
# (verified on ENS: "unknown object type for NT_ACCESS_MASK AAC_OBJECT_SECTION").
NT_ACCESS_INVALID_TYPES: Set[str] = {"SECTION", "NAMEDSECTION", "DISK"}


def nt_access_bits_for(obj_type: str) -> Optional[Dict[int, str]]:
    specific = _NT_ACCESS_SPECIFIC.get(obj_type)
    if specific is None:
        return None
    merged: Dict[int, str] = dict(specific)
    merged.update(_STANDARD_BITS)
    return merged


# --------------------------------------------------------------------------- #
# Tokenizer + node tree
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Node:
    name: str
    args: List[str]
    line: int
    children: List["Node"]
    has_body: bool = False

    def find_all(self, name: str) -> List["Node"]:
        out: List["Node"] = []
        for child in self.children:
            if child.name == name:
                out.append(child)
            out.extend(child.find_all(name))
        return out

    def find_child(self, name: str) -> Optional["Node"]:
        for child in self.children:
            if child.name == name:
                return child
        return None

    def find_children(self, name: str) -> List["Node"]:
        return [c for c in self.children if c.name == name]

    def iter_values(self) -> List[str]:
        vals: List[str] = []
        for child in self.children:
            if child.name == "-v":
                vals.extend(unquote(a) for a in child.args)
            elif child.name == "-l":
                for a in child.args:
                    vals.extend(unquote(a).split())
        return vals

    def option(self, name: str) -> Optional[str]:
        for i, arg in enumerate(self.args):
            if arg == name and i + 1 < len(self.args):
                return unquote(self.args[i + 1])
        return None

    def has_option(self, name: str) -> bool:
        return name in self.args


class _Token:
    __slots__ = ("kind", "text", "line", "quoted")

    def __init__(self, kind: str, text: str, line: int, quoted: bool = False) -> None:
        self.kind = kind          # "word" | "{" | "}" | "sep"
        self.text = text
        self.line = line
        self.quoted = quoted


def _tokenize(text: str) -> List[_Token]:
    tokens: List[_Token] = []
    i = 0
    n = len(text)
    line = 1
    at_cmd_start = True

    def push(kind: str, txt: str, ln: int, quoted: bool = False) -> None:
        tokens.append(_Token(kind, txt, ln, quoted))

    while i < n:
        ch = text[i]
        if ch == "\n":
            push("sep", "\n", line)
            line += 1
            i += 1
            at_cmd_start = True
            continue
        if ch in " \t\r":
            i += 1
            continue
        if ch == ";":
            push("sep", ";", line)
            i += 1
            at_cmd_start = True
            continue
        if ch == "#" and at_cmd_start:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "{":
            push("{", "{", line)
            i += 1
            at_cmd_start = True
            continue
        if ch == "}":
            push("}", "}", line)
            i += 1
            at_cmd_start = False
            continue
        if ch == '"':
            start_line = line
            j = i + 1
            buf = ['"']
            while j < n:
                cj = text[j]
                if cj == "\\" and j + 1 < n:
                    buf.append(text[j])
                    buf.append(text[j + 1])
                    if text[j + 1] == "\n":
                        line += 1
                    j += 2
                    continue
                buf.append(cj)
                if cj == '"':
                    j += 1
                    break
                if cj == "\n":
                    line += 1
                j += 1
            push("word", "".join(buf), start_line, quoted=True)
            i = j
            at_cmd_start = False
            continue
        # bare word
        start_line = line
        j = i
        buf = []
        while j < n and text[j] not in " \t\r\n;{}\"":
            buf.append(text[j])
            j += 1
        push("word", "".join(buf), start_line)
        i = j
        at_cmd_start = False

    push("sep", "", line)
    return tokens


def parse(text: str) -> Node:
    tokens = _tokenize(text)
    pos = 0

    def parse_block(depth: int) -> Tuple[List[Node], bool]:
        nonlocal pos
        nodes: List[Node] = []
        closed = False
        while pos < len(tokens):
            tok = tokens[pos]
            if tok.kind == "}":
                pos += 1
                closed = True
                break
            if tok.kind == "sep":
                pos += 1
                continue
            if tok.kind == "{":
                # brace with no leading command word: parse and discard structure
                pos += 1
                parse_block(depth + 1)
                continue
            # tok.kind == "word": start of a command
            name = tok.text
            cmd_line = tok.line
            pos += 1
            args: List[str] = []
            children: List[Node] = []
            has_body = False
            while pos < len(tokens):
                nt = tokens[pos]
                if nt.kind == "sep":
                    pos += 1
                    break
                if nt.kind == "}":
                    break
                if nt.kind == "{":
                    pos += 1
                    children, _ = parse_block(depth + 1)
                    has_body = True
                    # a command ends at its body
                    break
                args.append(nt.text)
                pos += 1
            nodes.append(Node(name, args, cmd_line, children, has_body))
        return nodes, closed

    top, _ = parse_block(0)
    return Node("<root>", [], 0, top, True)


def unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    if len(token) >= 2 and token[0] == "{" and token[-1] == "}":
        return token[1:-1]
    return token


# --------------------------------------------------------------------------- #
# Check registry
# --------------------------------------------------------------------------- #
CheckFn = Callable[["Context"], List[Finding]]
_CHECKS: List[CheckFn] = []


class Context:
    def __init__(self, text: str, root: Node) -> None:
        self.text = text
        self.root = root
        self.lines = text.splitlines()


def check(fn: CheckFn) -> CheckFn:
    _CHECKS.append(fn)
    return fn


# --------------------------------------------------------------------------- #
# Check helpers
# --------------------------------------------------------------------------- #
_STRUCTURAL: Set[str] = set(HIERARCHY) | {
    c for children in HIERARCHY.values() for c in children
}
_ACCESS_SPLIT = re.compile(r"[\s,|]+")
_OPTION_TOKENS = {
    "-access", "-nt_access", "-file_properties", "-file_attributes",
    "-vtp_privileges", "-disk_region", "-image_properties", "-vtp_trust",
    "-processor_mode", "-type", "-name", "-key", "-xtype", "-ref",
    "-v", "-l", "-pfx", "-sfx",
}


def _walk(node: Node, parent: Optional[Node], depth: int
          ) -> List[Tuple[Node, Optional[Node], int]]:
    out: List[Tuple[Node, Optional[Node], int]] = []
    for child in node.children:
        out.append((child, node, depth + 1))
        out.extend(_walk(child, node, depth + 1))
    return out


def _effective_argc(node: Node) -> int:
    return 1 + len(node.args) + (1 if node.has_body else 0)


def _match_name(node: Node) -> Optional[str]:
    if node.args and not node.args[0].startswith("-"):
        return node.args[0]
    return None


def _strip_type_prefix(obj_type: str) -> str:
    up = obj_type.upper()
    if up.startswith("AAC_OBJECT_"):
        return up[len("AAC_OBJECT_"):]
    return up


def _access_tokens(value: str) -> List[str]:
    return [t for t in _ACCESS_SPLIT.split(value.strip()) if t]


def _strip_access_prefix(token: str) -> str:
    return token.lstrip("!+*")


def _parse_mask(token: str) -> Optional[int]:
    tok = token.strip()
    if not tok:
        return None
    try:
        low = tok.lower()
        if low.startswith("0x"):
            return int(tok, 16)
        if low.startswith("0b"):
            return int(tok, 2)
        return int(tok, 10)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Checks — errors (E1xx)
# --------------------------------------------------------------------------- #
@check
def check_e101_balance(ctx: Context) -> List[Finding]:
    depth = 0
    line = 1
    in_quote = False
    at_cmd_start = True
    i = 0
    text = ctx.text
    n = len(text)
    open_lines: List[int] = []
    findings: List[Finding] = []
    while i < n:
        ch = text[i]
        if in_quote:
            if ch == "\\" and i + 1 < n:
                if text[i + 1] == "\n":
                    line += 1
                i += 2
                continue
            if ch == '"':
                in_quote = False
            elif ch == "\n":
                line += 1
            i += 1
            continue
        if ch == "\n":
            line += 1
            at_cmd_start = True
            i += 1
            continue
        if ch in " \t\r":
            i += 1
            continue
        if ch == ";":
            at_cmd_start = True
            i += 1
            continue
        if ch == "#" and at_cmd_start:
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == '"':
            in_quote = True
            at_cmd_start = False
            i += 1
            continue
        if ch == "{":
            depth += 1
            open_lines.append(line)
            at_cmd_start = True
            i += 1
            continue
        if ch == "}":
            if depth == 0:
                findings.append(Finding(
                    "E101", Severity.ERROR, line,
                    "unbalanced '}' with no matching '{'",
                    "check brace nesting",
                ))
            else:
                depth -= 1
                open_lines.pop()
            at_cmd_start = False
            i += 1
            continue
        at_cmd_start = False
        i += 1
    if in_quote:
        findings.append(Finding(
            "E101", Severity.ERROR, line,
            "unterminated double-quoted string",
            'add the closing "',
        ))
    if depth > 0:
        findings.append(Finding(
            "E101", Severity.ERROR, open_lines[0] if open_lines else line,
            f"unbalanced '{{' — {depth} block(s) never closed",
            "add the missing '}'",
        ))
    return findings


@check
def check_e102_depth(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, depth in _walk(ctx.root, None, 0):
        if depth > MAX_CMD_LEVEL:
            findings.append(Finding(
                "E102", Severity.ERROR, node.line,
                f"{node.name}: nesting exceeds MAX_CMD_LEVEL ({MAX_CMD_LEVEL})",
                "flatten the rule structure",
            ))
            break
    return findings


@check
def check_e110_hierarchy(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in [(ctx.root, None, 0)] + _walk(ctx.root, None, 0):
        allowed = HIERARCHY.get(node.name)
        if allowed is None:
            continue
        if node.name in ("Include", "Exclude") and _match_name(node) == "AggregateMatch":
            allowed = allowed | {"Include", "Exclude"}
        for child in node.children:
            if child.name in _STRUCTURAL and child.name not in allowed:
                findings.append(Finding(
                    "E110", Severity.ERROR, child.line,
                    f"{child.name} is not a valid child of {node.name}",
                    f"allowed here: {', '.join(sorted(allowed))}",
                ))
    return findings


@check
def check_e122_text_before_rule(ctx: Context) -> List[Finding]:
    # Verified on ENS 10.7: the console's Expert Rule form supplies the Reaction
    # only when the rule content starts with the Rule (or Policy) command. Any
    # line before it (even a # comment) makes the compile fail with
    # "Rule: Reaction was not set" unless the text sets its own Reaction.
    if ctx.root.find_all("Reaction"):
        return []
    for idx, line in enumerate(ctx.lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if re.match(r"(Rule|Policy)\b", stripped):
            return []
        return [Finding(
            "E122", Severity.ERROR, idx,
            "content before the first Rule: the console will not insert the "
            "form's Reaction (compiles as 'Rule: Reaction was not set')",
            "start the rule content with 'Rule {' and move comments inside "
            "the Rule block, or add an explicit Reaction",
        )]
    return []


@check
def check_e121_reaction_severity_values(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name == "Reaction" and node.args:
            if node.args[0] not in REACTIONS:
                findings.append(Finding(
                    "E121", Severity.ERROR, node.line,
                    f"Reaction: Unknown value {node.args[0]}",
                    f"valid: {', '.join(sorted(REACTIONS))}",
                ))
        elif node.name == "Severity" and node.args:
            if node.args[0].upper() not in SEVERITIES:
                findings.append(Finding(
                    "E121", Severity.ERROR, node.line,
                    f"Unknown Severity level {node.args[0]}",
                    "valid: CRITICAL, MAJOR, MINOR, WARNING, INFORMATIONAL",
                ))
    return findings


@check
def check_e130_e131_object_type(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, parent, _depth in _walk(ctx.root, None, 0):
        if node.name != "Match" or not node.args:
            continue
        raw = node.args[0]
        obj = _strip_type_prefix(raw)
        if obj not in OBJECT_TYPES:
            findings.append(Finding(
                "E130", Severity.ERROR, node.line,
                f"Match: Unknown object type {raw}",
                f"valid: {', '.join(sorted(OBJECT_TYPES))}",
            ))
            continue
        if parent is not None and parent.name == "Initiator" and obj != "PROCESS":
            findings.append(Finding(
                "E131", Severity.ERROR, node.line,
                f"Match: Object type can only be PROCESS for Initiators {raw}",
                "use Match PROCESS under Initiator",
            ))
    return findings


@check
def check_e140_argc(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        argc = _effective_argc(node)
        name = node.name
        if name == "Match" and argc != 3:
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                "Match: Invalid number of arguments",
                "expected: Match <TYPE> { ... }",
            ))
        elif name in ("Process", "Initiator", "Target") and argc != 2:
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                f"{name}: Invalid number of arguments",
                f"expected: {name} {{ ... }}",
            ))
        elif name in ("Include", "Exclude") and argc not in (3, 5, 7):
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                f"{name}: Invalid number of arguments",
                "expected 3, 5, or 7 arguments",
            ))
        elif name == "Rule" and argc < 2:
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                "Rule: Invalid number of arguments",
                "expected: Rule { ... }",
            ))
        elif name == "Reaction" and argc < 2:
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                "Reaction: Invalid number of arguments",
                "expected: Reaction <VALUE>",
            ))
        elif name == "-v" and argc < 2:
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                "-v: Invalid number of arguments",
                "-v must be given at least one value",
            ))
        elif name in ("-v", "-l") and any(a in ("-v", "-l") for a in node.args):
            # verified on ENS 10.7: `-v "a" -v "b"` on one line compiles but never
            # matches anything; each entry must start its own line.
            findings.append(Finding(
                "E141", Severity.ERROR, node.line,
                f"{name}: several -v/-l entries on one line (compiles, but never matches)",
                "put each -v / -l entry on its own line inside the { } body",
            ))
        elif name == "-v" and any("\\0" in a for a in node.args):
            # verified on ENS 10.7: TCL 7.6 strings stop at NUL, so "a\0b\0\0"
            # only ever compares "a" (e.g. against a MULTI_STRING value).
            findings.append(Finding(
                "W209", Severity.WARNING, node.line,
                "-v value contains \\0: only the text before the first NUL is compared",
                "for MULTI_STRING data use one -v line per string (any string matches)",
            ))
        elif name in ("-sfx", "-pfx") and argc != 2:
            # verified on ENS: "-sfx: Invalid number of arguments"
            findings.append(Finding(
                "E140", Severity.ERROR, node.line,
                f"{name}: Invalid number of arguments",
                f"{name} takes exactly one value; put it on its own line "
                f"before the -v / -l entries it applies to",
            ))
    return findings


@check
def check_e150_access(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude"):
            continue
        access = node.option("-access")
        if access is not None:
            for token in _access_tokens(access):
                bare = _strip_access_prefix(token).upper()
                if not bare:
                    continue
                if bare in AAC_ACCESS:
                    continue
                if _parse_mask(bare) is not None:
                    continue
                findings.append(Finding(
                    "E150", Severity.ERROR, node.line,
                    f"{node.name}: unknown access token {token}",
                    "see references/syntax.md for valid -access tokens",
                ))
    return findings


@check
def check_e151_e152_type(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude"):
            continue
        mname = _match_name(node)
        type_val = node.option("-type")
        if mname is not None and mname.upper() in TYPE_REQUIRED and type_val is None:
            findings.append(Finding(
                "E151", Severity.ERROR, node.line,
                f"Smart {mname} not supported yet, add -type option",
                "add e.g. -type STRING",
            ))
        if type_val is not None and type_val.upper() not in DATA_TYPES:
            findings.append(Finding(
                "E152", Severity.ERROR, node.line,
                f"{node.name}: unknown -type {type_val}",
                f"valid: {', '.join(sorted(DATA_TYPES))}",
            ))
    return findings


@check
def check_e153_name_key(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name in ("Include", "Exclude"):
            if node.has_option("-name") and node.has_option("-key"):
                findings.append(Finding(
                    "E153", Severity.ERROR, node.line,
                    f"{node.name}: can not specify both -name and -key",
                    "use one of -name or -key",
                ))
    return findings


@check
def check_e154_unknown_match_type(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude"):
            continue
        mname = _match_name(node)
        if mname is None or mname == "AggregateMatch":
            continue
        bare = unquote(mname)
        if bare.startswith("AAC_MATCH_"):
            bare = bare[len("AAC_MATCH_"):]
        if bare not in MATCH_TYPES:
            hint = "see references/syntax.md for valid match types"
            if bare.upper() in MATCH_TYPES:
                hint = f"match types are case-sensitive: use {bare.upper()}"
            findings.append(Finding(
                "E154", Severity.ERROR, node.line,
                f"{node.name}: unknown match type {mname}", hint,
            ))
    return findings


@check
def check_e155_bitmask_values(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude") or not node.args:
            continue
        first = unquote(node.args[0])
        mtype = _BITMASK_OPTIONS.get(first)
        if mtype is None:
            mtype = first[len("AAC_MATCH_"):] if first.startswith("AAC_MATCH_") else first
        names = BITMASK_VALUE_NAMES.get(mtype)
        if names is None:
            continue
        # value: bare 3-arg form (Include VTP_TRUST true / Include -disk_region "MBR")
        # or -v entries inside a body
        if node.children:
            raw = node.iter_values()
        elif len(node.args) >= 2 and not node.args[-1].startswith("-"):
            raw = [unquote(node.args[-1])]
        else:
            raw = []
        for value in raw:
            for token in re.split(r"[\s,|]+", value.strip()):
                tok = token.lstrip("!+")
                if not tok or tok == "*" or _BITMASK_NUMBER.match(tok):
                    continue
                if tok.upper() not in names:
                    findings.append(Finding(
                        "E155", Severity.ERROR, node.line,
                        f"{node.name}: {mtype} value {token} is not recognised",
                        f"valid names: {', '.join(sorted(names))} (or a number)",
                    ))
    return findings


@check
def check_e160_next_process_behavior(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for rule in ctx.root.find_all("Rule"):
        npb = rule.find_all("Next_Process_Behavior")
        if npb and rule.find_child("Target") is None:
            findings.append(Finding(
                "E160", Severity.ERROR, npb[0].line,
                "Next_Process_Behavior requires a Target section",
                "add a Target { ... } to the Rule",
            ))
    return findings


@check
def check_e170_duplicate_ids(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    seen: Dict[str, int] = {}
    for node in ctx.root.find_all("Rule") + ctx.root.find_all("Policy"):
        rid = node.option("-id")
        if rid is None or rid == "":
            continue
        if rid in seen:
            findings.append(Finding(
                "E170", Severity.ERROR, node.line,
                f"Duplicate {node.name} id found: {rid}",
                f"first used on line {seen[rid]}",
            ))
        else:
            seen[rid] = node.line
    return findings


# --------------------------------------------------------------------------- #
# Checks — warnings (W2xx)
# --------------------------------------------------------------------------- #
@check
def check_w201_unscoped_initiator(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include",):
            continue
        if parent is None or parent.name not in ("Process", "Initiator"):
            continue
        if _match_name(node) != "OBJECT_NAME":
            continue
        # "everyone except ..." (** narrowed by an Exclude) is a deliberate pattern
        if parent.find_children("Exclude"):
            continue
        for val in node.iter_values():
            if val.strip() in ("**", "*", "**\\*", "*.*"):
                findings.append(Finding(
                    "W201", Severity.WARNING, node.line,
                    f"unscoped initiator matches every process ({val})",
                    "name the actor process(es), or keep the target specific",
                ))
                break
    return findings


@check
def check_w202_read_cost(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude"):
            continue
        access = node.option("-access")
        if access is None:
            continue
        tokens = {_strip_access_prefix(t).upper() for t in _access_tokens(access)}
        if tokens & {"READ", "READ_DATA"}:
            findings.append(Finding(
                "W202", Severity.WARNING, node.line,
                "READ/READ_DATA access is high-frequency and costly",
                "only guard reads when the target is narrow",
            ))
    return findings


@check
def check_w203_single_backslash(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name != "-v":
            continue
        for arg in node.args:
            if not (arg.startswith('"') and arg.endswith('"')):
                continue
            inner = arg[1:-1]
            i = 0
            flagged = False
            while i < len(inner):
                if inner[i] == "\\":
                    nxt = inner[i + 1] if i + 1 < len(inner) else ""
                    if nxt == "\\":
                        i += 2
                        continue
                    # deliberate TCL escapes: \" quote, \$ \[ \] block substitution,
                    # \0 NUL separator in MULTI_STRING registry data
                    if nxt in ('"', "$", "[", "]", "0"):
                        i += 2
                        continue
                    flagged = True
                    break
                i += 1
            if flagged:
                findings.append(Finding(
                    "W203", Severity.WARNING, node.line,
                    f"single backslash in quoted path {arg}",
                    "double backslashes: TCL consumes one level",
                ))
    return findings


@check
def check_w205_version_gated(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    seen: Set[Tuple[str, int]] = set()
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        candidates: List[str] = [node.name] + list(node.args)
        access = node.option("-access")
        if access is not None:
            candidates.extend(_access_tokens(access))
        for raw in candidates:
            token = _strip_access_prefix(unquote(raw)).upper()
            ver = VERSION_GATED.get(token)
            if ver is not None and (token, node.line) not in seen:
                seen.add((token, node.line))
                findings.append(Finding(
                    "W205", Severity.WARNING, node.line,
                    f"{token} requires ENS {ver}+",
                    "ensure target clients are new enough, or avoid the token",
                ))
    return findings


@check
def check_w206_duplicate_xtype(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    seen: Dict[str, int] = {}
    for node, _parent, _depth in _walk(ctx.root, None, 0):
        if node.name not in ("Include", "Exclude"):
            continue
        if _match_name(node) != "AggregateMatch":
            continue
        xtype = node.option("-xtype")
        if xtype is None:
            continue
        if xtype in seen:
            findings.append(Finding(
                "W206", Severity.WARNING, node.line,
                f"duplicate AggregateMatch -xtype {xtype}",
                f"first used on line {seen[xtype]}; -xtype must be unique",
            ))
        else:
            seen[xtype] = node.line
    return findings


@check
def check_w208_registry_root_wildcard(ctx: Context) -> List[Finding]:
    # Official reference: if the root of a registry name contains a wildcard
    # (H*L*\..., HK*\...) AAC skips name normalisation and the rule most likely
    # never matches. A leading "**\..." (no root at all) is fine.
    findings: List[Finding] = []
    for match in ctx.root.find_all("Match"):
        obj = _match_name(match)
        if obj is None or _strip_type_prefix(obj) not in ("KEY", "VALUE"):
            continue
        for inc in match.find_all("Include") + match.find_all("Exclude"):
            if _match_name(inc) not in ("OBJECT_NAME", "TARGET_OBJECT_NAME"):
                continue
            for val in inc.iter_values():
                root = val.replace("/", "\\").split("\\", 1)[0]
                if re.search(r"[*?]", root) and re.search(r"[A-Za-z0-9]", root):
                    findings.append(Finding(
                        "W208", Severity.WARNING, inc.line,
                        f"wildcard inside registry root '{root}': the name is not "
                        f"normalised and will most likely never match",
                        "spell the root out (HKLM, HKCU, HKLMS, HKCCS, HKALL, ...) or "
                        "start the path with **",
                    ))
    return findings


@check
def check_w207_i302_nt_access(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    _nt_access_walk(ctx.root, None, findings)
    return findings


def _nt_access_walk(node: Node, obj_type: Optional[str],
                    findings: List[Finding]) -> None:
    current = obj_type
    if node.name == "Match" and node.args:
        current = _strip_type_prefix(node.args[0])
    if node.name in ("Include", "Exclude"):
        nt_access = node.option("-nt_access")
        if nt_access is not None:
            _check_nt_access_value(node, current, nt_access, findings)
    for child in node.children:
        _nt_access_walk(child, current, findings)


def _check_nt_access_value(node: Node, obj_type: Optional[str], nt_access: str,
                           findings: List[Finding]) -> None:
    if obj_type in NT_ACCESS_INVALID_TYPES:
        findings.append(Finding(
            "E150", Severity.ERROR, node.line,
            f"Include: Unknown -nt_access entry (unknown object type for "
            f"NT_ACCESS_MASK {obj_type})",
            "-nt_access only works on FILE, KEY, PROCESS and THREAD; "
            "use -access for this target",
        ))
        return
    if obj_type in NT_ACCESS_UNSUPPORTED:
        findings.append(Finding(
            "E150", Severity.ERROR, node.line,
            f"-nt_access is not supported for object type {obj_type}",
            "use -access for VALUE targets",
        ))
        return
    bits = nt_access_bits_for(obj_type) if obj_type else None
    if bits is None:
        return
    defined_low = 0
    for bit_name in bits:
        if bit_name <= 0xFFFF:
            defined_low |= bit_name
    for token in _access_tokens(nt_access):
        mask = _parse_mask(_strip_access_prefix(token))
        if mask is None:
            continue
        undefined = mask & 0x0000FFFF & ~defined_low
        if undefined:
            findings.append(Finding(
                "W207", Severity.WARNING, node.line,
                f"-nt_access {token}: bits 0x{undefined:X} are not defined "
                f"for {obj_type}",
                "verify the mask against the target object type",
            ))
        named = _decode_mask(mask, bits)
        if named:
            findings.append(Finding(
                "I302", Severity.INFO, node.line,
                f"-nt_access {token} = {', '.join(named)}",
                "",
            ))


def _decode_mask(mask: int, bits: Dict[int, str]) -> List[str]:
    names: List[str] = []
    for bit in sorted(bits):
        if mask & bit == bit and bit != 0:
            names.append(bits[bit])
    return names


# --------------------------------------------------------------------------- #
# Checks — info (I3xx)
# --------------------------------------------------------------------------- #
@check
def check_i301_whitespace(ctx: Context) -> List[Finding]:
    findings: List[Finding] = []
    for idx, line in enumerate(ctx.lines, start=1):
        if line != line.rstrip():
            findings.append(Finding(
                "I301", Severity.INFO, idx,
                "trailing whitespace",
                "",
            ))
    return findings


# --------------------------------------------------------------------------- #
# Driver + emitters
# --------------------------------------------------------------------------- #
def lint(
    text: str,
    select: Optional[Set[str]] = None,
    ignore: Optional[Set[str]] = None,
    min_severity: Severity = Severity.INFO,
) -> List[Finding]:
    root = parse(text)
    ctx = Context(text, root)
    findings: List[Finding] = []
    for fn in _CHECKS:
        findings.extend(fn(ctx))
    if select:
        findings = [f for f in findings if f.code in select]
    if ignore:
        findings = [f for f in findings if f.code not in ignore]
    findings = [f for f in findings if f.severity >= min_severity]
    findings.sort(key=lambda f: (f.line, f.code))
    return findings


def emit_text(findings: List[Finding], path: str, quiet: bool) -> str:
    lines = [f.format(path) for f in findings]
    if not quiet:
        errors = sum(1 for f in findings if f.severity == Severity.ERROR)
        warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
        infos = sum(1 for f in findings if f.severity == Severity.INFO)
        if findings:
            lines.append("")
        lines.append(f"{len(findings)} finding(s): "
                     f"{errors} error, {warnings} warning, {infos} info")
    return "\n".join(lines)


def emit_json(findings: List[Finding], path: str) -> str:
    payload = {
        "path": path,
        "findings": [
            {
                "code": f.code,
                "severity": f.severity.name,
                "line": f.line,
                "message": f.message,
                "hint": f.hint,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL: Dict[Severity, str] = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def emit_sarif(findings: List[Finding], path: str) -> str:
    rule_index = {code: idx for idx, (code, _s, _t)
                  in enumerate(RULE_CATALOGUE)}
    rules: List[Dict[str, object]] = [
        {
            "id": code,
            "name": code,
            "shortDescription": {"text": title},
            "defaultConfiguration": {"level": _SARIF_LEVEL[severity]},
        }
        for code, severity, title in RULE_CATALOGUE
    ]
    results: List[Dict[str, object]] = []
    for f in findings:
        result: Dict[str, object] = {
            "ruleId": f.code,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message + (f" ({f.hint})" if f.hint else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": max(f.line, 1)},
                },
            }],
        }
        if f.code in rule_index:
            result["ruleIndex"] = rule_index[f.code]
        results.append(result)
    sarif: Dict[str, object] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": TOOL_URI,
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _has_errors(findings: List[Finding]) -> bool:
    return any(f.severity == Severity.ERROR for f in findings)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _parse_codes(value: Optional[str]) -> Optional[Set[str]]:
    if not value:
        return None
    return {c.strip().upper() for c in value.split(",") if c.strip()}


_SEVERITY_BY_NAME = {s.name: s for s in Severity}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lint_expert_rule.py",
        description="Lint Trellix ENS Exploit Prevention Expert Rules.",
    )
    parser.add_argument("paths", nargs="+", metavar="path",
                        help="rule file(s) to lint, or - for stdin")
    parser.add_argument("--format", choices=("text", "json", "sarif"),
                        default="text")
    parser.add_argument("--select", help="comma-separated codes to report")
    parser.add_argument("--ignore", help="comma-separated codes to skip")
    parser.add_argument("--min-severity", choices=tuple(_SEVERITY_BY_NAME),
                        default="INFO",
                        help="only report findings at or above this severity "
                             "(default INFO = report everything)")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress the summary line (text format)")
    args = parser.parse_args(argv)

    status = 0
    json_docs: List[Dict[str, object]] = []
    sarif_doc: Optional[Dict[str, object]] = None
    for path in args.paths:
        try:
            if path == "-":
                text = sys.stdin.read()
                display_path = "<stdin>"
            else:
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
                display_path = path
        except OSError as exc:
            sys.stderr.write(f"error: cannot read {path}: {exc}\n")
            status = 2
            continue
        except UnicodeDecodeError as exc:
            sys.stderr.write(f"error: {path} is not valid UTF-8: {exc}\n")
            status = 2
            continue

        findings = lint(
            text,
            select=_parse_codes(args.select),
            ignore=_parse_codes(args.ignore),
            min_severity=_SEVERITY_BY_NAME[args.min_severity],
        )
        if _has_errors(findings) and status == 0:
            status = 1

        if args.format == "json":
            json_docs.append(json.loads(emit_json(findings, display_path)))
        elif args.format == "sarif":
            doc = json.loads(emit_sarif(findings, display_path))
            if sarif_doc is None:
                sarif_doc = doc
            else:
                sarif_doc["runs"][0]["results"].extend(  # type: ignore[index]
                    doc["runs"][0]["results"])  # type: ignore[index]
        else:
            out = emit_text(findings, display_path, args.quiet)
            if out:
                print(out)

    if args.format == "json" and json_docs:
        # one file keeps the original single-object shape; several give an array
        print(json.dumps(json_docs[0] if len(json_docs) == 1 else json_docs, indent=2))
    elif args.format == "sarif" and sarif_doc is not None:
        print(json.dumps(sarif_doc, indent=2))

    return status

if __name__ == "__main__":
    sys.exit(main())
