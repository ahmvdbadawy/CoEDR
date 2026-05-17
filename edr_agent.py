"""
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

CoEDR v3.0.0  —  Advanced Endpoint Detection & Response
MITRE ATT&CK–mapped · Behavioral chaining · Risk scoring · Threat hunting
"""

from __future__ import annotations

import argparse
import collections
import functools
import hashlib
import hmac
import ipaddress
import json
import math
import os
import platform
import queue
import re
import signal
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

import psutil
try:
    import yara
    import pefile
    import win32evtlog
    import win32evtlogutil
    import win32con
    import wmi
    import ctypes
    import requests
    import win32security
    import win32api
except ImportError:
    print("Warning: Advanced dependencies (yara, pefile, pywin32, wmi) are not fully installed. Some features may be disabled.")

# ─────────────────────────────── Constants ────────────────────────────────────

VERSION      = "3.0.0"
AGENT_NAME   = "CoEDR"
AGENT_ID     = str(uuid.uuid4())          # unique per host restart
DEFAULT_CONFIG = Path("config/watch_config.json")

# Severity numeric weights for scoring
SEV_WEIGHT = {"critical": 100, "high": 50, "medium": 20, "low": 5}

# MITRE tactic ordering
MITRE_TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Well-known high-risk port sets
HIGH_RISK_PORTS = {21, 22, 23, 25, 53, 80, 443, 445, 1080, 3389,
                   4444, 4445, 5555, 6666, 7777, 8080, 8443, 8888,
                   9001, 9002, 9090, 31337, 50050, 60000}

SIGNED_SYSTEM_PATHS = {
    r"c:\windows\system32", r"c:\windows\syswow64",
    r"c:\program files", r"c:\program files (x86)",
}

# ─────────────────────────────── Utilities ────────────────────────────────────

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def utc_ts() -> float:
    return datetime.now(timezone.utc).timestamp()

def norm(value: str | None) -> str:
    return (value or "").lower().strip()

def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

def enable_self_protection() -> None:
    """Modifies the process DACL to deny termination even from Administrators."""
    if "win32security" not in sys.modules:
        return
    try:
        import win32security
        import win32con
        import win32api
        
        # Get handle to current process
        h_proc = win32api.GetCurrentProcess()
        
        # Get current DACL
        sec_info = win32security.DACL_SECURITY_INFORMATION
        sd = win32security.GetSecurityInfo(h_proc, win32security.SE_KERNEL_OBJECT, sec_info)
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            dacl = win32security.ACL()
        
        # Create a new DACL
        new_dacl = win32security.ACL()
        
        # Add Deny ACE for "Everyone" (SID: S-1-1-0) for terminate rights
        everyone_sid, domain, type = win32security.LookupAccountName("", "Everyone")
        new_dacl.AddAccessDeniedAce(dacl.GetAclRevision(), win32con.PROCESS_TERMINATE | win32con.PROCESS_SUSPEND_RESUME, everyone_sid)
        
        # Copy existing ACEs to the new DACL
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            new_dacl.AddAce(dacl.GetAclRevision(), i + 1, ace[0], ace[1])
            
        # Set the new DACL
        win32security.SetSecurityInfo(h_proc, win32security.SE_KERNEL_OBJECT, sec_info, None, None, new_dacl, None)
        print("[+] Self-Protection enabled. Process cannot be terminated.")
    except Exception as e:
        print(f"[-] Failed to enable self-protection: {e}")


def safe_cmdline(proc: psutil.Process) -> str:
    try:
        return " ".join(proc.cmdline())
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return ""

def safe_exe(proc: psutil.Process) -> str | None:
    try:
        return proc.exe()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None

def safe_name(proc: psutil.Process) -> str | None:
    try:
        return proc.name()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None

def sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None

def md5_file(path: Path) -> str | None:
    try:
        digest = hashlib.md5()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None

def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_loopback or addr.is_private
                    or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False

def is_path_in_system_dirs(exe: str | None) -> bool:
    if not exe:
        return False
    e = exe.replace("/", "\\").lower()
    return any(e.startswith(p) for p in SIGNED_SYSTEM_PATHS)

def entropy(data: bytes) -> float:
    """Shannon entropy of byte sequence."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def cmdline_entropy(cmd: str) -> float:
    return entropy(cmd.encode())

def sign_event(event: dict[str, Any], secret: str) -> str:
    """HMAC-SHA256 signature for tamper-evidence."""
    payload = json.dumps(event, sort_keys=True, ensure_ascii=False, default=str)
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()

def hostname() -> str:
    return socket.gethostname()

def get_os_info() -> dict[str, str]:
    return {
        "platform": platform.system(),
        "release":  platform.release(),
        "version":  platform.version(),
        "machine":  platform.machine(),
        "processor": platform.processor(),
    }


# ────────────────────────── Behavioral Scoring ────────────────────────────────

@dataclass
class RiskScore:
    """Aggregate risk score for a process lineage or session."""
    base: float = 0.0
    modifiers: list[tuple[str, float]] = field(default_factory=list)

    def add(self, reason: str, delta: float) -> None:
        self.modifiers.append((reason, delta))
        self.base += delta

    @property
    def total(self) -> float:
        return round(self.base, 2)

    def to_dict(self) -> dict[str, Any]:
        return {"total": self.total, "modifiers": self.modifiers}


class BehavioralChain:
    """
    Tracks per-process sequences of events to detect multi-stage attack chains.
    Example: (office_spawns_shell) → (shell_runs_powershell) → (PS downloads file)
    """

    def __init__(self, ttl_seconds: float = 300.0) -> None:
        self._lock = threading.Lock()
        # pid → list of (ts, event_type, rule_id)
        self._chains: dict[int, list[tuple[float, str, str]]] = {}
        self._ttl = ttl_seconds

    def record(self, pid: int, event_type: str, rule_id: str) -> None:
        ts = utc_ts()
        with self._lock:
            chain = self._chains.setdefault(pid, [])
            chain.append((ts, event_type, rule_id))
            # Expire old entries
            cutoff = ts - self._ttl
            self._chains[pid] = [(t, e, r) for t, e, r in chain if t >= cutoff]

    def get_chain(self, pid: int) -> list[tuple[float, str, str]]:
        with self._lock:
            return list(self._chains.get(pid, []))

    def detect_chains(self, pid: int, patterns: list[list[str]]) -> list[str]:
        """Return list of matched chain pattern names."""
        chain = self.get_chain(pid)
        rule_ids = [r for _, _, r in chain]
        matched = []
        for pattern in patterns:
            if all(any(step in r for r in rule_ids) for step in pattern):
                matched.append("+".join(pattern))
        return matched

    def purge_expired(self) -> None:
        ts = utc_ts()
        cutoff = ts - self._ttl
        with self._lock:
            to_del = []
            for pid, chain in self._chains.items():
                pruned = [(t, e, r) for t, e, r in chain if t >= cutoff]
                if pruned:
                    self._chains[pid] = pruned
                else:
                    to_del.append(pid)
            for pid in to_del:
                del self._chains[pid]


# ───────────────────────── Network Baseline ───────────────────────────────────

class NetworkBaseline:
    """
    Learns normal outbound connections per process over a warm-up period
    then flags anomalies.
    """
    def __init__(self, warmup_seconds: float = 120.0) -> None:
        self._lock = threading.Lock()
        self._baseline: dict[str, collections.Counter] = {}   # proc → port counter
        self._start = utc_ts()
        self.warmup = warmup_seconds
        self._anomaly_threshold = 3   # port seen < N times during warm-up = anomaly

    @property
    def is_warmed_up(self) -> bool:
        return (utc_ts() - self._start) >= self.warmup

    def record(self, proc_name: str, port: int) -> None:
        with self._lock:
            self._baseline.setdefault(proc_name, collections.Counter())[port] += 1

    def is_anomalous(self, proc_name: str, port: int) -> bool:
        if not self.is_warmed_up:
            return False
        with self._lock:
            counter = self._baseline.get(norm(proc_name), collections.Counter())
            return counter[port] < self._anomaly_threshold


# ────────────────────────────── Rule Engine ───────────────────────────────────

@dataclass
class Rule:
    raw: dict[str, Any]

    @property
    def rule_id(self) -> str:
        return str(self.raw.get("id", "unknown"))

    @property
    def rule_type(self) -> str:
        return str(self.raw.get("type", ""))

    @property
    def severity(self) -> str:
        return str(self.raw.get("severity", "medium"))

    @property
    def tags(self) -> list[str]:
        return as_list(self.raw.get("tags", []))

    @property
    def tactics(self) -> list[str]:
        """Extract MITRE tactics from tags."""
        return [t for t in self.tags if t.lower() in MITRE_TACTICS]

    @property
    def mitre_ids(self) -> list[str]:
        """Extract Txxxx.xxx IDs from tags."""
        return [t for t in self.tags if re.match(r"t\d{4}(\.\d{3})?$", t.lower())]

    @property
    def false_positive_filters(self) -> list[str]:
        return as_list(self.raw.get("false_positive_filters", []))

    def matches(self, event: dict[str, Any]) -> bool:
        if self.rule_type != event.get("event_type"):
            return False

        checks = [
            self._match_any("process_any",              event.get("process_name")),
            self._match_any("parent_process_any",       event.get("parent_process_name")),
            self._contains_any("commandline_contains_any", event.get("command_line")),
            self._contains_any("path_contains_any",     event.get("path")),
            self._contains_any("registry_path_contains_any", event.get("registry_path")),
            self._match_any("remote_port_any",          event.get("remote_port")),
            self._match_any("username_any",             event.get("username")),
            self._match_regex("commandline_regex",      event.get("command_line")),
            self._match_regex("path_regex",             event.get("path")),
            self._check_entropy("commandline_min_entropy", event.get("command_line")),
            self._check_unsigned("require_unsigned",    event.get("process_exe")),
        ]
        all_passed = all(c for c in checks if c is not None)
        if not all_passed:
            return False

        # False-positive suppression
        for fp_filter in self.false_positive_filters:
            haystack = norm(json.dumps(event, default=str))
            if norm(fp_filter) in haystack:
                return False

        return True

    # ── Matchers ───────────────────────────────────────────────────────────────

    def _match_any(self, key: str, actual: Any) -> bool | None:
        expected = as_list(self.raw.get(key))
        if not expected:
            return None
        if isinstance(actual, str):
            return norm(actual) in {norm(str(i)) for i in expected}
        return actual in expected

    def _contains_any(self, key: str, actual: Any) -> bool | None:
        expected = as_list(self.raw.get(key))
        if not expected:
            return None
        haystack = norm(str(actual))
        return any(norm(str(i)) in haystack for i in expected)

    def _match_regex(self, key: str, actual: Any) -> bool | None:
        pattern = self.raw.get(key)
        if not pattern:
            return None
        try:
            return bool(re.search(pattern, str(actual or ""), re.IGNORECASE))
        except re.error:
            return None

    def _check_entropy(self, key: str, actual: Any) -> bool | None:
        min_ent = self.raw.get(key)
        if min_ent is None:
            return None
        return cmdline_entropy(str(actual or "")) >= float(min_ent)

    def _check_unsigned(self, key: str, exe: Any) -> bool | None:
        if not self.raw.get(key):
            return None
        # On Linux/Mac skip; on Windows check signature via WINTRUST would go here
        if sys.platform != "win32":
            return None
        return not is_path_in_system_dirs(str(exe or ""))


# ──────────────────────── YARA-style Pattern Scanner ─────────────────────────

class PatternScanner:
    """
    Lightweight YARA-inspired pattern matching for command lines, paths, and
    string content — uses precompiled regexes with confidence weights.
    """

    BUILT_IN_PATTERNS: list[dict[str, Any]] = [
        # Obfuscation signals
        {"id": "OBFUS-BASE64-LONG",
         "desc": "Long Base64 blob in command line (>100 chars)",
         "regex": r"[A-Za-z0-9+/]{100,}={0,2}",
         "weight": 15, "field": "command_line"},
        {"id": "OBFUS-HEX-SHELLCODE",
         "desc": "Hex-encoded shellcode pattern",
         "regex": r"(\\x[0-9a-fA-F]{2}){10,}",
         "weight": 30, "field": "command_line"},
        {"id": "OBFUS-CHAR-CONCAT",
         "desc": "Char() concatenation evasion",
         "regex": r"char\(\d+\)\s*[+&]\s*char\(\d+\)",
         "weight": 20, "field": "command_line"},
        {"id": "OBFUS-BACKTICK",
         "desc": "PowerShell backtick obfuscation",
         "regex": r"[a-zA-Z]`[a-zA-Z]",
         "weight": 15, "field": "command_line"},
        {"id": "OBFUS-STRING-REVERSE",
         "desc": "String reversal via -join technique",
         "regex": r"\[\s*-1\s*\.\.\s*-\(",
         "weight": 20, "field": "command_line"},
        # Download cradles
        {"id": "CRADLE-WEBCLIENT",
         "desc": "WebClient download cradle",
         "regex": r"(New-Object|\.Download(String|File|Data))\s.{0,50}(http|ftp)",
         "weight": 25, "field": "command_line"},
        {"id": "CRADLE-INVOKE-WR",
         "desc": "Invoke-WebRequest cradle",
         "regex": r"(iwr|Invoke-WebRequest|curl|wget)\s.{0,100}(http|ftp)",
         "weight": 20, "field": "command_line"},
        {"id": "CRADLE-BITSADMIN",
         "desc": "BITSAdmin download",
         "regex": r"bitsadmin.{0,50}/transfer",
         "weight": 25, "field": "command_line"},
        # Memory injection
        {"id": "INJECT-VIRTUALALLOC",
         "desc": "VirtualAlloc/WriteProcessMemory in cmdline",
         "regex": r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreate)",
         "weight": 40, "field": "command_line"},
        # Lateral movement
        {"id": "LATERAL-UNC-PATH",
         "desc": "UNC path execution",
         "regex": r"\\\\[a-zA-Z0-9._-]{2,}\\[a-zA-Z$][^\"'\s]{3,}",
         "weight": 15, "field": "command_line"},
        # C2 / beaconing
        {"id": "C2-SLEEP-LOOP",
         "desc": "Sleep loop in command line (beaconing pattern)",
         "regex": r"(Start-Sleep|sleep|timeout)\s.{0,20}(while|loop|-t\s*\d+)",
         "weight": 20, "field": "command_line"},
        # Suspicious file paths
        {"id": "PATH-TEMP-EXEC",
         "desc": "Executable in temp/appdata",
         "regex": r"(\\temp\\|\\appdata\\|\\programdata\\|/tmp/).+\.(exe|dll|bat|ps1|vbs|js|hta|scr|com|pif)",
         "weight": 25, "field": "command_line"},
        {"id": "PATH-DOUBLE-EXT",
         "desc": "Double extension (e.g. .pdf.exe)",
         "regex": r"\.\w{2,5}\.(exe|dll|bat|scr|com|pif)[\"'\s]",
         "weight": 30, "field": "command_line"},
        # Credential theft strings
        {"id": "CRED-NTLM-HASH",
         "desc": "NTLM hash pattern",
         "regex": r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}",
         "weight": 35, "field": "command_line"},
        # Advanced Evasion Patterns
        {"id": "EVASION-AMSI-REFLECTION",
         "desc": "AMSI bypass via .NET reflection",
         "regex": r"System\.Management\.Automation\.AmsiUtils.*amsiInitFailed",
         "weight": 40, "field": "command_line"},
        {"id": "EVASION-ETW-PATCH",
         "desc": "ETW patching via reflection or memory editing",
         "regex": r"EtwEventWrite.*(VirtualProtect|WriteProcessMemory)",
         "weight": 40, "field": "command_line"},
        {"id": "EVASION-SUSP-PIPES",
         "desc": "Suspicious named pipes commonly used by C2s (Cobalt Strike, etc)",
         "regex": r"\\\\\\.\\pipe\\(msagent.*|mojo.*|postex.*|status.*)",
         "weight": 35, "field": "command_line"},
        {"id": "RANSOMWARE-FILE-EXT",
         "desc": "Common ransomware extensions in path",
         "regex": r"\.(locked|encrypted|wannacry|crypt|kuku|wnry)$",
         "weight": 45, "field": "path"},
        {"id": "RANSOMWARE-NOTE",
         "desc": "Common ransomware note filenames",
         "regex": r"(HOW_TO_DECRYPT|readme_for_decrypt|DECRYPT_INFO)\.(txt|html|hta)",
         "weight": 45, "field": "path"},
        {"id": "LOLBIN-XSL",
         "desc": "WMIC loading XSL from URL",
         "regex": r"wmic.*format.*http",
         "weight": 30, "field": "command_line"}
    ]

    def __init__(self, extra_patterns: list[dict[str, Any]] | None = None, yara_rules_path: str = "rules/yara") -> None:
        self._patterns: list[tuple[dict[str, Any], re.Pattern]] = []
        all_patterns = self.BUILT_IN_PATTERNS + (extra_patterns or [])
        for p in all_patterns:
            try:
                compiled = re.compile(p["regex"], re.IGNORECASE)
                self._patterns.append((p, compiled))
            except re.error:
                pass
        
        # Load real YARA rules
        self.yara_rules = None
        if "yara" in sys.modules:
            yara_files = {}
            if os.path.exists(yara_rules_path):
                for f in os.listdir(yara_rules_path):
                    if f.endswith(".yar") or f.endswith(".yara"):
                        yara_files[f] = os.path.join(yara_rules_path, f)
            if yara_files:
                try:
                    self.yara_rules = yara.compile(filepaths=yara_files)
                except Exception as e:
                    print(f"Failed to compile YARA rules: {e}")

    def scan(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        hits = []
        for meta, pattern in self._patterns:
            field_val = str(event.get(meta.get("field", "command_line"), "") or "")
            if pattern.search(field_val):
                hits.append({
                    "pattern_id": meta["id"],
                    "description": meta["desc"],
                    "weight": meta.get("weight", 10),
                })
        
        # True YARA scanning
        if self.yara_rules:
            cmdline = str(event.get("command_line", "") or "")
            if cmdline:
                try:
                    yara_matches = self.yara_rules.match(data=cmdline)
                    for match in yara_matches:
                        hits.append({
                            "pattern_id": f"YARA_{match.rule}",
                            "description": match.meta.get("description", "YARA Rule Match"),
                            "weight": 50 if match.meta.get("severity") == "Critical" else 30,
                        })
                except Exception:
                    pass

        return hits


# ─────────────────────────── Threat Intelligence ──────────────────────────────

class ThreatIntelCache:
    """
    In-memory IOC cache: hashes, IPs, domains.
    Can be loaded from a JSON file or fed via API.
    """

    def __init__(self, ioc_path: Path | None = None, vt_api_key: str | None = None) -> None:
        self._lock = threading.RLock()
        self._hashes:  set[str] = set()
        self._ips:     set[str] = set()
        self._domains: set[str] = set()
        self._metadata: dict[str, dict[str, Any]] = {}
        self.vt_api_key = vt_api_key
        self._vt_cache: dict[str, dict[str, Any]] = {}  # Local cache to prevent VT rate limits
        if ioc_path and ioc_path.exists():
            self._load(ioc_path)

    def _load(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for entry in data:
                ioc_type = entry.get("type", "")
                value    = norm(entry.get("value", ""))
                if not value:
                    continue
                if ioc_type == "hash":
                    self._hashes.add(value)
                elif ioc_type == "ip":
                    self._ips.add(value)
                elif ioc_type == "domain":
                    self._domains.add(value)
                self._metadata[value] = entry
        except Exception:
            pass

    def check_hash(self, h: str | None) -> dict[str, Any] | None:
        if not h:
            return None
        v = norm(h)
        with self._lock:
            if v in self._hashes:
                return self._metadata.get(v)
            if v in self._vt_cache:
                return self._vt_cache[v]
        
        # Check VirusTotal if API key is provided
        if self.vt_api_key and "requests" in sys.modules:
            try:
                import requests
                headers = {"x-apikey": self.vt_api_key}
                resp = requests.get(f"https://www.virustotal.com/api/v3/files/{v}", headers=headers, timeout=3)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                    if malicious > 3:  # Threshold for VT positive
                        result = {"type": "hash", "value": v, "source": "VirusTotal", "malicious_hits": malicious}
                        with self._lock:
                            self._vt_cache[v] = result
                        return result
                    else:
                        with self._lock:
                            self._vt_cache[v] = None # Cache clean result
            except Exception:
                pass
        return None

    def check_ip(self, ip: str | None) -> dict[str, Any] | None:
        if not ip:
            return None
        with self._lock:
            return self._metadata.get(ip) if ip in self._ips else None

    def check_domain(self, domain: str | None) -> dict[str, Any] | None:
        if not domain:
            return None
        with self._lock:
            v = norm(domain)
            return self._metadata.get(v) if v in self._domains else None

    def add_ioc(self, ioc_type: str, value: str, metadata: dict[str, Any] | None = None) -> None:
        v = norm(value)
        with self._lock:
            if ioc_type == "hash":
                self._hashes.add(v)
            elif ioc_type == "ip":
                self._ips.add(v)
            elif ioc_type == "domain":
                self._domains.add(v)
            if metadata:
                self._metadata[v] = metadata


# ──────────────────────────── Telemetry ───────────────────────────────────────

class TelemetryLogger:
    """
    Thread-safe NDJSON logger with optional HMAC signing and size-based rotation.
    """

    def __init__(self, path: Path, sign_secret: str | None = None,
                 max_mb: float = 100.0) -> None:
        self.path = path
        self.sign_secret = sign_secret
        self.max_bytes = int(max_mb * 1024 * 1024)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._rotate_index = 0

    def write(self, event: dict[str, Any]) -> None:
        event.setdefault("timestamp", utc_now())
        event.setdefault("agent_id",  AGENT_ID)
        event.setdefault("hostname",  hostname())
        if self.sign_secret:
            event["_sig"] = sign_event(event, self.sign_secret)
        line = json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n"
        with self._lock:
            self._maybe_rotate()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    def _maybe_rotate(self) -> None:
        try:
            if self.path.stat().st_size < self.max_bytes:
                return
            self._rotate_index += 1
            rotated = self.path.with_suffix(f".{self._rotate_index}.json")
            self.path.rename(rotated)
        except (OSError, FileNotFoundError):
            pass


EventSink = Callable[[dict[str, Any]], None]


# ──────────────────────────── Alert Deduplication ─────────────────────────────

class AlertDeduplicator:
    """
    Suppress identical rule+process alerts within a rolling TTL window.
    Prevents alert storms during noisy activity.
    """

    def __init__(self, ttl_seconds: float = 60.0, max_entries: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}
        self._ttl = ttl_seconds
        self._max = max_entries

    def is_duplicate(self, rule_id: str, proc_name: str) -> bool:
        key = f"{rule_id}:{norm(proc_name)}"
        ts  = utc_ts()
        with self._lock:
            last = self._seen.get(key)
            if last and (ts - last) < self._ttl:
                return True
            self._seen[key] = ts
            if len(self._seen) > self._max:
                # Evict oldest
                oldest = min(self._seen, key=lambda k: self._seen[k])
                del self._seen[oldest]
            return False


# ──────────────────────────── Detection Engine ────────────────────────────────

class DetectionEngine:
    def __init__(
        self,
        rules_path: Path,
        logger: TelemetryLogger,
        event_sink: EventSink | None = None,
        ti_cache: ThreatIntelCache | None = None,
        dedup_ttl: float = 60.0,
    ) -> None:
        self.rules_path   = rules_path
        self.logger       = logger
        self.event_sink   = event_sink
        self.ti_cache     = ti_cache or ThreatIntelCache()
        self.rules:        list[Rule] = []
        self.rules_loaded_at: float = 0.0
        self.scanner      = PatternScanner()
        self.behavioral   = BehavioralChain(ttl_seconds=300)
        self.dedup        = AlertDeduplicator(ttl_seconds=dedup_ttl)
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            raw = json.loads(self.rules_path.read_text(encoding="utf-8"))
            self.rules = [Rule(r) for r in raw]
            self.rules_loaded_at = time.time()
        except Exception as exc:
            self._emit({"event_type": "agent_error", "error": f"rules load failed: {exc}"})

    def reload_rules(self) -> int:
        self._load_rules()
        return len(self.rules)

    def evaluate(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        self.logger.write(event)
        self._emit(event)

        # TI enrichment
        self._enrich_with_ti(event)

        # Pattern scanner
        pattern_hits = self.scanner.scan(event)
        if pattern_hits:
            event["pattern_hits"] = pattern_hits

        # Rule matching
        alerts: list[dict[str, Any]] = []
        pid = event.get("pid")
        for rule in self.rules:
            if not rule.matches(event):
                continue

            proc_name = str(event.get("process_name") or "")
            if self.dedup.is_duplicate(rule.rule_id, proc_name):
                continue

            # Risk scoring
            score = RiskScore()
            score.add("rule_severity", SEV_WEIGHT.get(rule.severity, 10))
            if event.get("remote_is_public"):
                score.add("public_remote_ip", 10)
            for ph in pattern_hits:
                score.add(f"pattern:{ph['pattern_id']}", ph["weight"])
            if event.get("ti_hit"):
                score.add("threat_intel_hit", 50)
            if cmdline_entropy(str(event.get("command_line", ""))) > 5.0:
                score.add("high_entropy_cmdline", 15)

            # Behavioral chain
            if pid:
                self.behavioral.record(int(pid), event.get("event_type", ""), rule.rule_id)
            chain_hits = self.behavioral.detect_chains(
                int(pid) if pid else 0,
                [["OFFICE-MACRO", "PS-OBFUSCATED"],
                 ["CRED-LSASS",   "C2-TOOLS"],
                 ["RANSOMWARE",   "LATERAL"],
                 ["WEB-001",      "PS-OBFUSCATED"],
                 ["DEFENSE-EVASION", "CRED"],
                 ["EVENT-LOG-CLEAR", "DEFENSE-EVASION"],
                 ["CRED-COMSVCS", "EXFIL-RCLONE"],
                 ["LATERAL-WINRM", "C2-TUNNEL"],
                 ["ACCOUNT-CREATION", "PERSIST-WMI"],
                 ["DEFENSE-EVASION-AMSI", "C2-SHELL-OUTBOUND"],
                 ["CRED-BROWSER", "EXFIL-ARCHIVE"]
                ],
            ) if pid else []

            alert: dict[str, Any] = {
                "event_type":       "alert",
                "alert_id":         str(uuid.uuid4()),
                "rule_id":          rule.rule_id,
                "rule_name":        rule.raw.get("name"),
                "severity":         rule.severity,
                "description":      rule.raw.get("description"),
                "tags":             rule.tags,
                "mitre_attack_ids": rule.mitre_ids,
                "mitre_tactics":    rule.tactics,
                "risk_score":       score.to_dict(),
                "pattern_hits":     pattern_hits,
                "behavioral_chains": chain_hits,
                "matched_event":    event,
            }
            self.logger.write(alert)
            self._emit(alert)
            alerts.append(alert)

        return alerts

    def _enrich_with_ti(self, event: dict[str, Any]) -> None:
        # Check file hashes
        for field in ("sha256", "md5"):
            h = event.get(field) or event.get("snapshot", {}).get(field)
            hit = self.ti_cache.check_hash(h)
            if hit:
                event["ti_hit"] = hit
                return
        # Check remote IP
        hit = self.ti_cache.check_ip(event.get("remote_ip"))
        if hit:
            event["ti_hit"] = hit

    def _emit(self, event: dict[str, Any]) -> None:
        if self.event_sink is None:
            return
        try:
            self.event_sink(event)
        except Exception:
            pass


# ──────────────────────── Threat Hunter ───────────────────────────────────────

class ThreatHunter:
    """
    Proactive threat hunting: scans running processes for IOCs, anomalous
    loaded modules, hidden processes, and suspicious network connections
    that may have been missed by real-time monitoring.
    """

    def __init__(self, engine: "DetectionEngine") -> None:
        self.engine = engine

    def hunt(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        findings += self._hunt_processes()
        findings += self._hunt_network()
        return findings

    def _hunt_processes(self) -> list[dict[str, Any]]:
        findings = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username",
                                          "create_time", "ppid"]):
            try:
                pid  = proc.info["pid"]
                name = proc.info.get("name") or ""
                exe  = proc.info.get("exe") or ""
                cmd  = " ".join(proc.info.get("cmdline") or [])

                # Unusual executable locations
                if exe and name.lower() in {
                    "svchost.exe", "lsass.exe", "csrss.exe",
                    "winlogon.exe", "services.exe", "smss.exe",
                }:
                    if not is_path_in_system_dirs(exe):
                        findings.append({
                            "hunt_type": "masquerading",
                            "finding":   f"System process {name} running from non-standard path",
                            "pid":       pid,
                            "exe":       exe,
                            "severity":  "critical",
                        })

                # Hollowed process: process exists but has no exe on disk
                if exe and not Path(exe).exists() and sys.platform == "win32":
                    findings.append({
                        "hunt_type": "hollow_process",
                        "finding":   f"Process exe not on disk (possible process hollowing)",
                        "pid":       pid,
                        "name":      name,
                        "exe":       exe,
                        "severity":  "high",
                    })

                # High-entropy command lines (obfuscation)
                if cmd and cmdline_entropy(cmd) > 5.5:
                    findings.append({
                        "hunt_type": "high_entropy_cmdline",
                        "finding":   f"Very high entropy command line (possible obfuscation)",
                        "pid":       pid,
                        "name":      name,
                        "entropy":   round(cmdline_entropy(cmd), 3),
                        "severity":  "high",
                    })

                # Advanced PE Analysis using pefile (if available)
                if exe and Path(exe).exists() and "pefile" in sys.modules:
                    try:
                        pe = pefile.PE(exe, fast_load=True)
                        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
                        
                        # 1. Unsigned binary running from unusual path
                        is_signed = hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
                        if not is_signed and not is_path_in_system_dirs(exe) and name.lower() not in {"python.exe", "code.exe"}:
                            findings.append({
                                "hunt_type": "unsigned_binary",
                                "finding": f"Unsigned binary running from unusual location: {exe}",
                                "pid": pid,
                                "exe": exe,
                                "severity": "medium",
                            })

                        # 2. Suspicious Section characteristics (RWX - Executable & Writable)
                        for section in pe.sections:
                            chars = section.Characteristics
                            # IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
                            if (chars & 0x20000000) and (chars & 0x80000000):
                                findings.append({
                                    "hunt_type": "rwx_section",
                                    "finding": f"PE contains RWX section ({section.Name.decode('utf-8', 'ignore').strip()}) which is highly unusual",
                                    "pid": pid,
                                    "exe": exe,
                                    "severity": "critical",
                                })
                    except Exception:
                        pass
                        
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
                
        return findings

    def _hunt_network(self) -> list[dict[str, Any]]:
        findings = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr:
                    continue
                remote_port = conn.raddr.port
                remote_ip   = conn.raddr.ip

                # Listening on unusual high-numbered port (possible backdoor)
                if conn.status == "LISTEN" and remote_port > 49151:
                    findings.append({
                        "hunt_type": "suspicious_listener",
                        "finding":   f"Listening on ephemeral port {remote_port}",
                        "pid":       conn.pid,
                        "port":      remote_port,
                        "severity":  "medium",
                    })

                # TI hit on remote IP
                ti = self.engine.ti_cache.check_ip(remote_ip)
                if ti:
                    findings.append({
                        "hunt_type": "ti_network_hit",
                        "finding":   f"Active connection to known-malicious IP {remote_ip}",
                        "pid":       conn.pid,
                        "remote_ip": remote_ip,
                        "ti_entry":  ti,
                        "severity":  "critical",
                    })

        except (psutil.AccessDenied, AttributeError):
            pass
        return findings


# ──────────────────────── Event Log / ETW Monitor ────────────────────────────

class EventLogMonitor(threading.Thread):
    """
    Subscribes to WMI / ETW / Sysmon events for 100% reliable, real-time 
    telemetry generation without polling gaps.
    """
    def __init__(self, engine: "DetectionEngine") -> None:
        super().__init__(daemon=True)
        self.engine = engine
        self.running = True

    def run(self) -> None:
        if "wmi" not in sys.modules:
            return
        try:
            import wmi
            c = wmi.WMI()
            # WMI uses ETW under the hood for ProcessTrace events
            process_watcher = c.Win32_Process.watch_for("creation")
            
            while self.running:
                try:
                    new_process = process_watcher(timeout_ms=2000)
                    if new_process:
                        event = {
                            "event_type": "process_creation",
                            "process_name": new_process.Name,
                            "pid": getattr(new_process, "ProcessId", 0),
                            "command_line": getattr(new_process, "CommandLine", "") or "",
                            "path": getattr(new_process, "ExecutablePath", "") or "",
                            "ppid": getattr(new_process, "ParentProcessId", 0),
                            "source": "WMI_ETW"
                        }
                        # Feed the real-time event directly into the engine
                        self.engine.evaluate(event)
                except wmi.x_wmi_timed_out:
                    continue
                except Exception:
                    pass
        except Exception:
            pass

    def stop(self) -> None:
        self.running = False



# ──────────────────────────── EDR Agent ───────────────────────────────────────

class EdrAgent:
    def __init__(
        self,
        config: dict[str, Any],
        event_sink: EventSink | None = None,
    ) -> None:
        self.config       = config
        self.poll_interval = float(config.get("poll_interval_seconds", 2))
        self.event_sink   = event_sink

        self.logger = TelemetryLogger(
            Path(config.get("telemetry_path", "edr_telemetry.json")),
            sign_secret=config.get("telemetry_hmac_secret"),
            max_mb=float(config.get("telemetry_max_mb", 100)),
        )

        ioc_path = Path(config.get("ioc_path", "config/ioc_feed.json"))
        self.ti_cache = ThreatIntelCache(ioc_path if ioc_path.exists() else None, vt_api_key=config.get("virustotal_api_key"))

        self.engine = DetectionEngine(
            Path(config.get("rules_path", "rules/detection_rules.json")),
            self.logger,
            event_sink,
            self.ti_cache,
            dedup_ttl=float(config.get("alert_dedup_ttl_seconds", 60)),
        )

        self.net_baseline = NetworkBaseline(
            warmup_seconds=float(config.get("network_baseline_warmup_seconds", 120))
        )
        self.hunter = ThreatHunter(self.engine)
        self.etw_monitor = EventLogMonitor(self.engine)

        self.seen_pids:          set[int]                  = set()
        self.seen_connections:   set[tuple[int, str, int]] = set()
        self.file_state:         dict[str, dict[str, Any]] = {}
        self.registry_state:     dict[str, dict[str, Any]] = {}
        self.dns_cache:          dict[str, str]            = {}

        self.self_process = psutil.Process()
        self.self_process.cpu_percent(interval=None)
        self.running = True

        self._stats: dict[str, Any] = {
            "events_total":    0,
            "alerts_total":    0,
            "processes_seen":  0,
            "connections_seen":0,
            "files_monitored": 0,
            "rules_loaded":    len(self.engine.rules),
            "hunt_findings":   0,
            "ti_hits":         0,
            "start_time":      utc_now(),
            "os":              get_os_info(),
            "hostname":        hostname(),
            "agent_id":        AGENT_ID,
        }

        self._hunt_interval = float(config.get("hunt_interval_seconds", 120))
        self._last_hunt     = 0.0
        self._last_chain_purge = 0.0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    def run(self) -> None:
        enable_self_protection()
        self._write_event({
            "event_type":   "agent_start",
            "agent_name":   AGENT_NAME,
            "version":      VERSION,
            "config":       {k: v for k, v in self.config.items()
                             if k not in ("telemetry_hmac_secret",)},
            "rules_loaded": len(self.engine.rules),
            "os":           get_os_info(),
            "hostname":     hostname(),
        })
        self._prime_processes()
        self._prime_files()
        self._prime_registry()
        self._stats["files_monitored"] = len(self.file_state)
        self.etw_monitor.start()

        while self.running:
            scan_start = time.monotonic()
            self.scan_processes()
            self.scan_files()
            self.scan_network()
            self.scan_registry()
            self._maybe_hunt()
            self._maybe_purge_chains()
            self._sleep_with_cpu_budget(scan_start)

        self._write_event({"event_type": "agent_stop"})
        self.etw_monitor.stop()
        self.etw_monitor.join(timeout=2.0)

    def stop(self, *_: Any) -> None:
        self.running = False
        self.etw_monitor.stop()

    def reload_rules(self) -> int:
        count = self.engine.reload_rules()
        self._stats["rules_loaded"] = count
        self._write_event({"event_type": "rules_reloaded", "count": count})
        return count

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _write_event(self, event: dict[str, Any]) -> None:
        self.logger.write(event)
        self._stats["events_total"] += 1
        if self.event_sink is not None:
            try:
                self.event_sink(event)
            except Exception:
                pass

    def _handle_alerts(self, event: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        self._stats["alerts_total"]  += len(alerts)
        if event.get("ti_hit"):
            self._stats["ti_hits"] += 1
        self._handle_response_actions(event, alerts)

    def _maybe_hunt(self) -> None:
        now = time.monotonic()
        if now - self._last_hunt < self._hunt_interval:
            return
        self._last_hunt = now
        findings = self.hunter.hunt()
        self._stats["hunt_findings"] += len(findings)
        for f in findings:
            f["event_type"] = "threat_hunt_finding"
            self._write_event(f)
            # Generate alert for critical/high hunt findings
            if f.get("severity") in ("critical", "high"):
                alert = {
                    "event_type":    "alert",
                    "alert_id":      str(uuid.uuid4()),
                    "rule_id":       f"HUNT-{f.get('hunt_type','unknown').upper()}",
                    "rule_name":     f.get("finding"),
                    "severity":      f.get("severity", "high"),
                    "description":   "Threat hunter finding",
                    "tags":          ["threat-hunt"],
                    "mitre_attack_ids": [],
                    "risk_score":    {"total": SEV_WEIGHT.get(f.get("severity","high"), 50),
                                      "modifiers": [("hunt_finding", 50)]},
                    "matched_event": f,
                }
                self.logger.write(alert)
                if self.event_sink:
                    try:
                        self.event_sink(alert)
                    except Exception:
                        pass

    def _maybe_purge_chains(self) -> None:
        now = time.monotonic()
        if now - self._last_chain_purge > 60:
            self.engine.behavioral.purge_expired()
            self._last_chain_purge = now

    # ── Process monitoring ─────────────────────────────────────────────────────

    def _prime_processes(self) -> None:
        for proc in psutil.process_iter(["pid"]):
            self.seen_pids.add(proc.info["pid"])

    def scan_processes(self) -> None:
        attrs = ["pid", "name", "ppid", "create_time", "exe", "username",
                 "status", "nice", "num_threads"]
        for proc in psutil.process_iter(attrs):
            try:
                pid = int(proc.info["pid"])
            except (TypeError, KeyError):
                continue
            if pid in self.seen_pids:
                continue
            self.seen_pids.add(pid)
            self._stats["processes_seen"] += 1

            parent_name = parent_pid = None
            try:
                parent = proc.parent()
                if parent:
                    parent_name = parent.name()
                    parent_pid  = parent.pid
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass

            exe = proc.info.get("exe") or ""
            cmd = safe_cmdline(proc)
            sha = sha256_file(Path(exe)) if exe and Path(exe).exists() else None
            md5 = md5_file(Path(exe))    if exe and Path(exe).exists() else None

            event: dict[str, Any] = {
                "event_type":        "process_creation",
                "pid":               pid,
                "process_name":      proc.info.get("name"),
                "process_exe":       exe,
                "parent_pid":        parent_pid,
                "parent_process_name": parent_name,
                "process_tree":      self._process_tree(proc),
                "command_line":      cmd,
                "username":          proc.info.get("username"),
                "create_time":       proc.info.get("create_time"),
                "status":            proc.info.get("status"),
                "num_threads":       proc.info.get("num_threads"),
                "sha256":            sha,
                "md5":               md5,
                "is_system_path":    is_path_in_system_dirs(exe),
                "cmdline_entropy":   round(cmdline_entropy(cmd), 3) if cmd else 0,
            }
            alerts = self.engine.evaluate(event)
            self._handle_alerts(event, alerts)

    def _process_tree(self, proc: psutil.Process) -> list[dict[str, Any]]:
        tree: list[dict[str, Any]] = []
        current: psutil.Process | None = proc
        depth = 0
        max_depth = int(self.config.get("process_tree_max_depth", 12))
        while current is not None and depth < max_depth:
            try:
                tree.append({
                    "depth":        depth,
                    "pid":          current.pid,
                    "ppid":         current.ppid(),
                    "name":         current.name(),
                    "exe":          current.exe(),
                    "command_line": safe_cmdline(current),
                    "create_time":  current.create_time(),
                })
                current = current.parent()
                depth += 1
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                break
        return tree

    # ── File monitoring ────────────────────────────────────────────────────────

    def _prime_files(self) -> None:
        for path in self._iter_sensitive_files():
            snap = self._snapshot_file(path)
            if snap:
                self.file_state[str(path)] = snap

    def scan_files(self) -> None:
        for path in self._iter_sensitive_files():
            snap = self._snapshot_file(path)
            if not snap:
                continue
            prev = self.file_state.get(str(path))
            if prev is None:
                self.file_state[str(path)] = snap
                event = {
                    "event_type": "file_change", "action": "created",
                    "path": str(path), "snapshot": snap,
                }
                alerts = self.engine.evaluate(event)
                self._handle_alerts(event, alerts)
                continue
            if snap["mtime_ns"] != prev["mtime_ns"] or snap["sha256"] != prev["sha256"]:
                self.file_state[str(path)] = snap
                event = {
                    "event_type": "file_change", "action": "modified",
                    "path": str(path), "previous": prev, "snapshot": snap,
                    "size_delta": snap["size"] - prev["size"],
                }
                alerts = self.engine.evaluate(event)
                self._handle_alerts(event, alerts)

    def _iter_sensitive_files(self) -> Iterable[Path]:
        for item in self.config.get("sensitive_paths", []):
            p = Path(item)
            if p.exists() and p.is_file():
                yield p
        for root_text in self.config.get("fim_roots", []):
            root = Path(root_text)
            if not root.exists():
                continue
            for pattern in self.config.get("sensitive_globs", []):
                yield from (p for p in root.glob(pattern) if p.is_file())

    def _snapshot_file(self, path: Path) -> dict[str, Any] | None:
        try:
            stat = path.stat()
        except (OSError, PermissionError):
            return None
        sha = sha256_file(path)
        return {
            "size":     stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "atime_ns": stat.st_atime_ns,
            "ctime_ns": stat.st_ctime_ns,
            "sha256":   sha,
            "md5":      md5_file(path),
        }

    # ── Network monitoring ─────────────────────────────────────────────────────

    def scan_network(self) -> None:
        ignore_ips   = set(self.config.get("ignore_remote_ips", []))
        ignore_ports = set(self.config.get("ignore_remote_ports", []))

        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, AttributeError):
            return

        for conn in connections:
            if not conn.raddr or not conn.pid:
                continue
            remote_ip, remote_port = conn.raddr.ip, conn.raddr.port
            if remote_ip in ignore_ips or remote_port in ignore_ports:
                continue
            key = (conn.pid, remote_ip, remote_port)
            if key in self.seen_connections:
                continue
            self.seen_connections.add(key)
            self._stats["connections_seen"] += 1

            proc_name = cmd = None
            proc_obj: psutil.Process | None = None
            try:
                proc_obj  = psutil.Process(conn.pid)
                proc_name = proc_obj.name()
                cmd       = safe_cmdline(proc_obj)
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass

            # Reverse-DNS (best-effort, non-blocking via cache)
            rdns = self._reverse_dns(remote_ip)

            self.net_baseline.record(norm(proc_name or ""), remote_port)
            is_anomalous = self.net_baseline.is_anomalous(norm(proc_name or ""), remote_port)

            event: dict[str, Any] = {
                "event_type":    "network_connection",
                "pid":           conn.pid,
                "process_name":  proc_name,
                "command_line":  cmd,
                "process_tree":  self._process_tree(proc_obj) if proc_obj else [],
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_ip":     remote_ip,
                "remote_port":   remote_port,
                "remote_rdns":   rdns,
                "remote_is_public": is_public_ip(remote_ip),
                "status":        conn.status,
                "family":        "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
                "baseline_anomaly": is_anomalous,
                "is_high_risk_port": remote_port in HIGH_RISK_PORTS,
            }
            alerts = self.engine.evaluate(event)
            self._handle_alerts(event, alerts)

            # Auto-generate alert for baseline anomalies on sensitive processes
            sensitive_procs = {norm(p) for p in self.config.get("sensitive_processes", [])}
            if is_anomalous and norm(proc_name or "") in sensitive_procs:
                anomaly_event: dict[str, Any] = {
                    **event,
                    "event_type": "alert",
                    "alert_id":   str(uuid.uuid4()),
                    "rule_id":    "BASELINE-ANOMALY-NET",
                    "rule_name":  "Network Baseline Anomaly",
                    "severity":   "medium",
                    "description": f"Process {proc_name} connected to unexpected port {remote_port}",
                    "tags":       ["baseline-anomaly", "network"],
                }
                self.logger.write(anomaly_event)
                if self.event_sink:
                    try:
                        self.event_sink(anomaly_event)
                    except Exception:
                        pass

    def _reverse_dns(self, ip: str) -> str | None:
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        try:
            host = socket.gethostbyaddr(ip)[0]
            self.dns_cache[ip] = host
            return host
        except (socket.herror, socket.gaierror, OSError):
            self.dns_cache[ip] = None
            return None

    # ── Registry monitoring ────────────────────────────────────────────────────

    def _prime_registry(self) -> None:
        self.registry_state = self._snapshot_startup_registry()

    def scan_registry(self) -> None:
        current  = self._snapshot_startup_registry()
        prev_keys, cur_keys = set(self.registry_state), set(current)

        for key in sorted(cur_keys - prev_keys):
            event = {"event_type": "registry_change", "action": "created",
                     "registry_path": key, "snapshot": current[key]}
            alerts = self.engine.evaluate(event)
            self._handle_alerts(event, alerts)
        for key in sorted(prev_keys - cur_keys):
            event = {"event_type": "registry_change", "action": "deleted",
                     "registry_path": key, "previous": self.registry_state[key]}
            alerts = self.engine.evaluate(event)
            self._handle_alerts(event, alerts)
        for key in sorted(cur_keys & prev_keys):
            if current[key] != self.registry_state[key]:
                event = {
                    "event_type": "registry_change", "action": "modified",
                    "registry_path": key,
                    "previous": self.registry_state[key],
                    "snapshot": current[key],
                }
                alerts = self.engine.evaluate(event)
                self._handle_alerts(event, alerts)
        self.registry_state = current

    def _snapshot_startup_registry(self) -> dict[str, dict[str, Any]]:
        if sys.platform != "win32":
            return {}
        import winreg  # type: ignore
        snapshots: dict[str, dict[str, Any]] = {}
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        access_modes = [winreg.KEY_READ]
        if hasattr(winreg, "KEY_WOW64_64KEY"):
            access_modes.append(winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        if hasattr(winreg, "KEY_WOW64_32KEY"):
            access_modes.append(winreg.KEY_READ | winreg.KEY_WOW64_32KEY)

        for item in self.config.get("registry_startup_keys", []):
            hive_name, subkey = item.get("hive"), item.get("path")
            hive = hives.get(hive_name)
            if not hive or not subkey:
                continue
            for access in access_modes:
                view = self._registry_view_name(access)
                path_id = f"{hive_name}\\{subkey} [{view}]"
                try:
                    with winreg.OpenKey(hive, subkey, 0, access) as key:
                        values: dict[str, Any] = {}
                        idx = 0
                        while True:
                            try:
                                name, value, vtype = winreg.EnumValue(key, idx)
                            except OSError:
                                break
                            values[name or "(Default)"] = {"value": str(value), "type": vtype}
                            idx += 1
                        snapshots[path_id] = {"values": values}
                except OSError:
                    snapshots[path_id] = {"values": {}, "missing": True}
        return snapshots

    def _registry_view_name(self, access: int) -> str:
        if sys.platform != "win32":
            return "default"
        import winreg  # type: ignore
        if hasattr(winreg, "KEY_WOW64_64KEY") and access & winreg.KEY_WOW64_64KEY:
            return "64-bit"
        if hasattr(winreg, "KEY_WOW64_32KEY") and access & winreg.KEY_WOW64_32KEY:
            return "32-bit"
        return "default"

    # ── Response actions ───────────────────────────────────────────────────────

    def _handle_response_actions(
        self, event: dict[str, Any], alerts: list[dict[str, Any]]
    ) -> None:
        rc = self.config.get("response_actions", {})
        if not alerts:
            return

        max_sev = min(
            (SEVERITY_NUMERIC.get(norm(a.get("severity", "")), 99) for a in alerts),
            default=99,
        )
        has_critical = max_sev <= 1
        has_high     = max_sev <= 2

        et = event.get("event_type")

        if et == "process_creation":
            pid = event.get("pid")
            if not isinstance(pid, int) or pid == self.self_process.pid:
                return
            protected = {norm(i) for i in rc.get("protected_processes", [])}
            if norm(event.get("process_name", "")) in protected:
                self._write_event({
                    "event_type": "response_action", "action": "terminate",
                    "status": "skipped_protected", "pid": pid,
                })
                return
            if has_critical and rc.get("terminate_critical_processes", True):
                self.terminate_process(pid, event.get("process_name"), alerts)
            elif has_high and rc.get("suspend_high_processes", True):
                self.suspend_process(pid, event.get("process_name"), alerts)

        elif et == "file_change":
            path_str = event.get("path")
            if has_critical and path_str and rc.get("quarantine_critical_files", True):
                self.quarantine_file(Path(path_str), alerts)

        elif et == "network_connection":
            remote_ip = event.get("remote_ip")
            if has_critical and remote_ip and rc.get("block_critical_ips", False):
                self._block_ip(remote_ip, alerts)

    def terminate_process(
        self, pid: int, process_name: str | None = None,
        alerts: list[dict[str, Any]] | None = None
    ) -> None:
        alerts = alerts or []
        try:
            target = psutil.Process(pid)
            target.terminate()
            rc = self.config.get("response_actions", {})
            try:
                target.wait(timeout=float(rc.get("terminate_timeout_seconds", 3)))
                status = "terminated"
            except psutil.TimeoutExpired:
                if rc.get("kill_after_timeout", False):
                    target.kill()
                    status = "killed_after_timeout"
                else:
                    status = "terminate_sent"
            self._write_event({
                "event_type": "response_action", "action": "terminate",
                "status": status, "pid": pid, "process_name": process_name,
                "reason": "rule_match",
                "alerts": [{"rule_id": a.get("rule_id"), "severity": a.get("severity")}
                           for a in alerts],
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as exc:
            self._write_event({
                "event_type": "response_action", "action": "terminate",
                "status": "failed", "pid": pid, "error": exc.__class__.__name__,
            })

    def suspend_process(
        self, pid: int, process_name: str | None = None,
        alerts: list[dict[str, Any]] | None = None
    ) -> None:
        alerts = alerts or []
        try:
            psutil.Process(pid).suspend()
            self._write_event({
                "event_type": "response_action", "action": "suspend",
                "status": "suspended", "pid": pid, "process_name": process_name,
                "alerts": [{"rule_id": a.get("rule_id"), "severity": a.get("severity")}
                           for a in alerts],
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError) as exc:
            self._write_event({
                "event_type": "response_action", "action": "suspend",
                "status": "failed", "pid": pid, "error": exc.__class__.__name__,
            })

    def quarantine_file(
        self, path: Path, alerts: list[dict[str, Any]] | None = None
    ) -> None:
        import shutil
        alerts = alerts or []
        qdir   = Path(self.config.get("quarantine_dir", "EDR_Quarantine"))
        try:
            qdir.mkdir(parents=True, exist_ok=True)
            dest = qdir / f"{path.name}_{int(time.time())}.quarantine"
            shutil.move(str(path), str(dest))
            try:
                os.chmod(str(dest), 0o400)
            except Exception:
                pass
            self._write_event({
                "event_type": "response_action", "action": "quarantine",
                "status": "success", "path": str(path),
                "quarantine_path": str(dest),
                "alerts": [{"rule_id": a.get("rule_id")} for a in alerts],
            })
        except Exception as exc:
            self._write_event({
                "event_type": "response_action", "action": "quarantine",
                "status": "failed", "path": str(path), "error": repr(exc),
            })

    def _block_ip(self, ip: str, alerts: list[dict[str, Any]]) -> None:
        """Emit a block event (actual firewall rule would be OS-specific)."""
        self._write_event({
            "event_type": "response_action", "action": "block_ip",
            "status": "emitted", "ip": ip,
            "note": "Operator must apply firewall rule",
            "alerts": [{"rule_id": a.get("rule_id")} for a in alerts],
        })

    # ── CPU budget ─────────────────────────────────────────────────────────────

    def _sleep_with_cpu_budget(self, scan_started: float) -> None:
        max_cpu      = float(self.config.get("max_agent_cpu_percent", 5))
        min_interval = float(self.config.get("min_poll_interval_seconds", self.poll_interval))
        max_interval = float(self.config.get("max_poll_interval_seconds", 15))
        cpu_pct      = self.self_process.cpu_percent(interval=None)
        if cpu_pct > max_cpu:
            self.poll_interval = min(max_interval, max(self.poll_interval * 1.5, min_interval))
            self._write_event({
                "event_type": "resource_throttle",
                "agent_cpu_percent": cpu_pct,
                "new_poll_interval_seconds": self.poll_interval,
            })
        elif cpu_pct < max_cpu / 2 and self.poll_interval > min_interval:
            self.poll_interval = max(min_interval, self.poll_interval * 0.9)
        elapsed = time.monotonic() - scan_started
        time.sleep(max(self.poll_interval - elapsed, min_interval))


SEVERITY_NUMERIC = {"critical": 1, "high": 2, "medium": 3, "low": 4}


# ──────────────────────────── Config & Helpers ────────────────────────────────

def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)

def event_summary(event: dict[str, Any]) -> str:
    et = str(event.get("event_type", "unknown"))
    if et == "alert":
        m = event.get("matched_event", {})
        rs = event.get("risk_score", {}).get("total", "?")
        return (f"[score:{rs}] {event.get('rule_id')} — {event.get('rule_name')} "
                f"| {event_summary(m)}")
    if et == "process_creation":
        ent = event.get("cmdline_entropy", "")
        return (f"{event.get('process_name')} pid={event.get('pid')} "
                f"parent={event.get('parent_process_name')} ent={ent}")
    if et == "network_connection":
        anom = " ⚠ANOMALY" if event.get("baseline_anomaly") else ""
        return (f"{event.get('process_name')} pid={event.get('pid')} "
                f"→ {event.get('remote_ip')}:{event.get('remote_port')}{anom}")
    if et == "file_change":
        return f"{event.get('action')} {event.get('path')}"
    if et == "registry_change":
        return f"{event.get('action')} {event.get('registry_path')}"
    if et == "response_action":
        return (f"{event.get('action')} [{event.get('status')}] "
                f"pid={event.get('pid')} {event.get('process_name')}")
    if et == "threat_hunt_finding":
        return f"[{event.get('hunt_type')}] {event.get('finding')}"
    if et == "resource_throttle":
        return f"cpu={event.get('agent_cpu_percent')}% → {event.get('new_poll_interval_seconds')}s"
    if et == "rules_reloaded":
        return f"Loaded {event.get('count')} detection rules"
    return json.dumps(event, ensure_ascii=False, default=str)[:240]


# ────────────────────────────── Dashboard ─────────────────────────────────────

PALETTE = {
    "bg_deep":       "#070910",
    "bg_panel":      "#0b0d14",
    "bg_card":       "#111520",
    "bg_hover":      "#171d2e",
    "bg_selected":   "#1a2440",
    "border":        "#1c2235",
    "border_bright": "#243050",
    "fg_primary":    "#d4ddf0",
    "fg_secondary":  "#7a8aaa",
    "fg_muted":      "#3a4460",
    "accent_blue":   "#4d9fff",
    "accent_cyan":   "#22f0c8",
    "accent_green":  "#22c95a",
    "accent_yellow": "#f5b731",
    "accent_orange": "#ff7e3d",
    "accent_red":    "#ff4040",
    "accent_purple": "#a07aff",
    "accent_teal":   "#00e5b0",
    "sev_critical":  "#ff3030",
    "sev_critical_bg":"#2a0505",
    "sev_high":      "#ff7e3d",
    "sev_high_bg":   "#261100",
    "sev_medium":    "#f5b731",
    "sev_medium_bg": "#201800",
    "sev_low":       "#22c95a",
    "sev_low_bg":    "#021510",
    "info_bg":       "#040f20",
    "hunt_bg":       "#0d0d30",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class EdrDashboard:
    def __init__(self, config_path: Path) -> None:
        import tkinter as tk
        from tkinter import messagebox, ttk
        self.tk          = tk
        self.messagebox  = messagebox
        self.ttk         = ttk

        self.config_path  = config_path
        self.config       = load_config(config_path)
        self.telemetry_path = Path(self.config.get("telemetry_path", "edr_telemetry.json"))
        self.events:       queue.Queue[dict[str, Any]] = queue.Queue()
        self.agent:        EdrAgent | None = None
        self.agent_thread: threading.Thread | None = None
        self.all_events:   list[dict[str, Any]] = []
        self.row_payloads: dict[str, str] = {}
        self._alert_flash_job: str | None = None
        self._uptime_job:      str | None = None
        self._start_ts = time.time()

        self.root = tk.Tk()
        self.root.title(f"{AGENT_NAME}  v{VERSION}  —  Advanced EDR")
        self.root.geometry("1560x900")
        self.root.minsize(1200, 700)
        self.root.configure(bg=PALETTE["bg_deep"])
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self._configure_style()
        self._build_ui()
        self._load_existing_telemetry()
        self.apply_filters()
        self._set_status("ready", "Ready")
        self._drain_events()
        self._tick_uptime()

    # ── Style ──────────────────────────────────────────────────────────────────
    def _configure_style(self) -> None:
        style = self.ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except self.tk.TclError:
            pass
        P = PALETTE
        bg, card, fg, fg2 = P["bg_deep"], P["bg_card"], P["fg_primary"], P["fg_secondary"]

        style.configure(".", background=bg, foreground=fg, font=("Consolas", 9))
        style.configure("TFrame",        background=bg)
        style.configure("Card.TFrame",   background=card, relief="flat")
        style.configure("Panel.TFrame",  background=P["bg_panel"])

        style.configure("H1.TLabel",     background=P["bg_panel"], foreground=fg,
                        font=("Consolas", 16, "bold"))
        style.configure("H2.TLabel",     background=P["bg_panel"], foreground=P["accent_blue"],
                        font=("Consolas", 9, "bold"))
        style.configure("Sub.TLabel",    background=P["bg_panel"], foreground=fg2, font=("Consolas", 8))
        style.configure("TLabel",        background=bg, foreground=fg, font=("Consolas", 9))
        style.configure("Card.TLabel",   background=card, foreground=fg, font=("Consolas", 9))
        style.configure("Metric.TLabel", background=card, foreground=fg, font=("Consolas", 20, "bold"))
        style.configure("MetricName.TLabel", background=card, foreground=fg2, font=("Consolas", 8))

        # Treeview
        style.configure("Treeview",
                        rowheight=26, font=("Consolas", 8),
                        fieldbackground=P["bg_panel"], background=P["bg_panel"],
                        foreground=fg, borderwidth=0, relief="flat")
        style.configure("Treeview.Heading",
                        font=("Consolas", 8, "bold"), background=P["bg_card"],
                        foreground=P["accent_blue"], relief="flat", borderwidth=0)
        style.map("Treeview",
                  background=[("selected", P["bg_selected"])],
                  foreground=[("selected", fg)])
        style.map("Treeview.Heading", background=[("active", P["bg_hover"])])

        # Buttons
        for name, fg_c, bg_c, act_bg in [
            ("Primary", fg,               P["accent_blue"],   "#6ebaff"),
            ("Danger",  fg,               P["sev_critical"],  "#ff6060"),
            ("Ghost",   P["accent_blue"], P["bg_card"],       P["bg_hover"]),
            ("Warning", P["bg_deep"],     P["accent_yellow"], "#ffd060"),
            ("Hunt",    P["bg_deep"],     P["accent_teal"],   "#40ffcc"),
        ]:
            style.configure(f"{name}.TButton",
                            background=bg_c, foreground=fg_c,
                            font=("Consolas", 8, "bold"), relief="flat",
                            borderwidth=0, padding=(12, 6))
            style.map(f"{name}.TButton",
                      background=[("active", act_bg), ("disabled", P["fg_muted"])],
                      foreground=[("disabled", P["fg_secondary"])])

        style.configure("TCombobox",
                        fieldbackground=P["bg_card"], background=P["bg_card"],
                        foreground=fg, selectbackground=P["bg_selected"],
                        arrowcolor=P["accent_blue"])
        style.configure("TEntry",
                        fieldbackground=P["bg_card"], foreground=fg,
                        insertcolor=P["accent_blue"])
        style.configure("TScrollbar",
                        background=P["bg_card"], troughcolor=P["bg_deep"],
                        arrowcolor=P["fg_muted"], relief="flat", borderwidth=0)
        style.configure("TNotebook", background=P["bg_deep"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=P["bg_card"], foreground=fg2,
                        font=("Consolas", 8, "bold"), padding=(16, 8), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", P["bg_panel"]), ("active", P["bg_hover"])],
                  foreground=[("selected", P["accent_cyan"])])

    # ── Build UI ───────────────────────────────────────────────────────────────
    def _build_ui(self) -> None:
        tk, ttk, P = self.tk, self.ttk, PALETTE
        root = self.root

        # Sidebar
        sidebar = ttk.Frame(root, style="Panel.TFrame", width=230)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Logo
        logo = ttk.Frame(sidebar, style="Panel.TFrame", padding=(18, 22, 18, 18))
        logo.pack(fill="x")
        tk.Label(logo, text="⬡ SENTINEL", bg=P["bg_panel"], fg=P["accent_cyan"],
                 font=("Consolas", 13, "bold")).pack(anchor="w")
        tk.Label(logo, text=f"EDR v{VERSION}  ·  Advanced", bg=P["bg_panel"],
                 fg=P["fg_muted"], font=("Consolas", 7)).pack(anchor="w")
        tk.Frame(sidebar, bg=P["border"], height=1).pack(fill="x")

        # Agent controls
        ctrl = ttk.Frame(sidebar, style="Panel.TFrame", padding=(12, 16, 12, 8))
        ctrl.pack(fill="x")
        ttk.Label(ctrl, text="AGENT CONTROL", style="H2.TLabel").pack(anchor="w", pady=(0, 8))
        self.start_button = ttk.Button(ctrl, text="▶  Start Monitoring",
                                       style="Primary.TButton", command=self.start_agent)
        self.start_button.pack(fill="x", pady=(0, 5))
        self.stop_button  = ttk.Button(ctrl, text="■  Stop Agent",
                                       style="Danger.TButton", command=self.stop_agent,
                                       state="disabled")
        self.stop_button.pack(fill="x", pady=(0, 5))
        ttk.Button(ctrl, text="🔍  Run Threat Hunt",
                   style="Hunt.TButton", command=self.run_hunt_action).pack(fill="x", pady=(0, 5))
        ttk.Button(ctrl, text="↺  Reload Rules",
                   style="Ghost.TButton", command=self.reload_rules_action).pack(fill="x", pady=(0, 5))
        ttk.Button(ctrl, text="⟳  Reload Telemetry",
                   style="Ghost.TButton", command=self.reload_telemetry).pack(fill="x", pady=(0, 5))
        ttk.Button(ctrl, text="✕  Clear Logs",
                   style="Warning.TButton", command=self.clear_logs).pack(fill="x")

        tk.Frame(sidebar, bg=P["border"], height=1).pack(fill="x", pady=6)

        # Status
        status_f = ttk.Frame(sidebar, style="Panel.TFrame", padding=(12, 8, 12, 8))
        status_f.pack(fill="x")
        ttk.Label(status_f, text="STATUS", style="H2.TLabel").pack(anchor="w", pady=(0, 8))
        self._sidebar_rows: dict[str, self.tk.StringVar] = {}
        for label, key in [
            ("Agent", "agent"), ("Rules", "rules"),
            ("Uptime", "uptime"), ("CPU", "cpu"), ("TI Hits", "ti_hits"),
        ]:
            row = ttk.Frame(status_f, style="Panel.TFrame")
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=P["bg_panel"], fg=P["fg_muted"],
                     font=("Consolas", 8), width=8, anchor="w").pack(side="left")
            var = tk.StringVar(value="—")
            tk.Label(row, textvariable=var, bg=P["bg_panel"], fg=P["accent_cyan"],
                     font=("Consolas", 8, "bold"), anchor="w").pack(side="left")
            self._sidebar_rows[key] = var

        tk.Frame(sidebar, bg=P["border"], height=1).pack(fill="x", pady=6)

        # Filters
        filt = ttk.Frame(sidebar, style="Panel.TFrame", padding=(12, 8, 12, 8))
        filt.pack(fill="x")
        ttk.Label(filt, text="FILTERS", style="H2.TLabel").pack(anchor="w", pady=(0, 8))

        self.search_var = tk.StringVar()
        ttk.Label(filt, text="Search", style="Sub.TLabel").pack(anchor="w")
        se = ttk.Entry(filt, textvariable=self.search_var)
        se.pack(fill="x", pady=(2, 8))
        se.bind("<KeyRelease>", lambda _: self.apply_filters())

        self.type_filter_var = tk.StringVar(value="All")
        ttk.Label(filt, text="Event Type", style="Sub.TLabel").pack(anchor="w")
        tcb = ttk.Combobox(filt, textvariable=self.type_filter_var, state="readonly", width=22,
                           values=["All", "alert", "process_creation", "network_connection",
                                   "file_change", "registry_change", "response_action",
                                   "threat_hunt_finding", "resource_throttle",
                                   "agent_start", "agent_stop"])
        tcb.pack(fill="x", pady=(2, 8))
        tcb.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        self.severity_filter_var = tk.StringVar(value="All")
        ttk.Label(filt, text="Severity", style="Sub.TLabel").pack(anchor="w")
        scb = ttk.Combobox(filt, textvariable=self.severity_filter_var, state="readonly", width=22,
                           values=["All", "critical", "high", "medium", "low"])
        scb.pack(fill="x", pady=(2, 8))
        scb.bind("<<ComboboxSelected>>", lambda _: self.apply_filters())

        ttk.Button(filt, text="Reset Filters",
                   style="Ghost.TButton", command=self.reset_filters).pack(fill="x")

        # Main content
        main = ttk.Frame(root, style="Panel.TFrame")
        main.pack(side="left", fill="both", expand=True)

        # Header
        header = ttk.Frame(main, style="Panel.TFrame", padding=(24, 14, 24, 14))
        header.pack(fill="x")
        lh = ttk.Frame(header, style="Panel.TFrame")
        lh.pack(side="left", fill="y")
        ttk.Label(lh, text="Security Operations Center", style="H1.TLabel").pack(anchor="w")
        ttk.Label(lh,
                  text=f"Config: {self.config_path}  ·  Telemetry: {self.telemetry_path}  "
                       f"·  Agent: {AGENT_ID[:12]}…",
                  style="Sub.TLabel").pack(anchor="w")
        rh = ttk.Frame(header, style="Panel.TFrame")
        rh.pack(side="right", fill="y")
        self.status_indicator = tk.Label(rh, text="● OFFLINE",
                                          bg=P["bg_panel"], fg=P["fg_muted"],
                                          font=("Consolas", 9, "bold"))
        self.status_indicator.pack(anchor="e")
        self.status_text = tk.StringVar(value="")
        tk.Label(rh, textvariable=self.status_text, bg=P["bg_panel"],
                 fg=P["fg_secondary"], font=("Consolas", 8)).pack(anchor="e")

        tk.Frame(main, bg=P["border"], height=1).pack(fill="x")

        # Metric cards
        metrics = ttk.Frame(main, style="Panel.TFrame", padding=(20, 12, 20, 12))
        metrics.pack(fill="x")
        self._metric_vars: dict[str, tuple[self.tk.StringVar, self.tk.StringVar]] = {}
        for label, key, icon, color in [
            ("Total Events",    "events",      "◈", P["accent_blue"]),
            ("Active Alerts",   "alerts",      "⚠", P["sev_critical"]),
            ("Risk Score",      "risk",        "▲", P["accent_orange"]),
            ("Processes",       "processes",   "⬡", P["accent_cyan"]),
            ("Connections",     "connections", "⇌", P["accent_purple"]),
            ("Hunt Findings",   "hunt",        "🔍", P["accent_teal"]),
            ("Files Monitored", "files",       "◻", P["accent_yellow"]),
            ("Rules Loaded",    "rules_count", "⊛", P["accent_green"]),
        ]:
            card = ttk.Frame(metrics, style="Card.TFrame", padding=(14, 10))
            card.pack(side="left", fill="both", expand=True, padx=(0, 6))
            val_var = tk.StringVar(value="0")
            sub_var = tk.StringVar(value=label)
            tk.Label(card, text=icon, bg=P["bg_card"], fg=color,
                     font=("Consolas", 16)).pack(anchor="w")
            tk.Label(card, textvariable=val_var, bg=P["bg_card"], fg=P["fg_primary"],
                     font=("Consolas", 18, "bold")).pack(anchor="w")
            tk.Label(card, textvariable=sub_var, bg=P["bg_card"], fg=P["fg_secondary"],
                     font=("Consolas", 7)).pack(anchor="w")
            self._metric_vars[key] = (val_var, sub_var)

        tk.Frame(main, bg=P["border"], height=1).pack(fill="x")

        # Notebook
        nb_frame = ttk.Frame(main, style="Panel.TFrame", padding=(16, 10, 16, 10))
        nb_frame.pack(fill="both", expand=True)
        self.notebook = ttk.Notebook(nb_frame)
        self.notebook.pack(fill="both", expand=True)

        self.event_tree = self._make_tree(
            "  All Events  ",
            ("timestamp", "type", "process", "pid", "score", "summary"),
            {"timestamp": 158, "type": 135, "process": 130, "pid": 65,
             "score": 60, "summary": 700},
        )
        self.alert_tree = self._make_tree(
            "  ⚠ Alerts  ",
            ("timestamp", "severity", "score", "rule_id", "rule_name", "process", "summary"),
            {"timestamp": 158, "severity": 80, "score": 60, "rule_id": 130,
             "rule_name": 220, "process": 130, "summary": 400},
        )
        self.hunt_tree = self._make_tree(
            "  🔍 Hunt  ",
            ("timestamp", "severity", "hunt_type", "pid", "summary"),
            {"timestamp": 158, "severity": 80, "hunt_type": 160, "pid": 65, "summary": 700},
        )
        self._build_detail_tab()
        self._build_stats_tab()

        # Status bar
        statusbar = ttk.Frame(main, style="Panel.TFrame", padding=(16, 4, 16, 4))
        statusbar.pack(fill="x", side="bottom")
        tk.Frame(main, bg=P["border"], height=1).pack(fill="x", side="bottom")
        self.filter_count_var = tk.StringVar(value="")
        tk.Label(statusbar, textvariable=self.filter_count_var,
                 bg=P["bg_panel"], fg=P["fg_muted"], font=("Consolas", 7)).pack(side="left")
        tk.Label(statusbar,
                 text=f"{AGENT_NAME} {VERSION}  ·  Behavioral + Pattern + TI Engine  ·  {hostname()}",
                 bg=P["bg_panel"], fg=P["fg_muted"], font=("Consolas", 7)).pack(side="right")

    def _make_tree(self, title: str, columns: tuple, widths: dict) -> Any:
        P = PALETTE
        frame = self.ttk.Frame(self.notebook, style="Panel.TFrame", padding=(0, 6, 0, 0))
        self.notebook.add(frame, text=title)
        tree = self.ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        ys = self.ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xs = self.ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        for col in columns:
            tree.heading(col, text=col.upper())
            tree.column(col, width=widths.get(col, 100), minwidth=40,
                        stretch=(col == "summary"))
        tree.bind("<<TreeviewSelect>>", lambda _e, w=tree: self._show_selected(w))
        for tag, bg, fg in [
            ("critical", P["sev_critical_bg"], P["sev_critical"]),
            ("high",     P["sev_high_bg"],     P["sev_high"]),
            ("medium",   P["sev_medium_bg"],   P["sev_medium"]),
            ("low",      P["sev_low_bg"],      P["sev_low"]),
            ("system",   P["info_bg"],         P["accent_blue"]),
            ("response", "#0f1a2e",            P["accent_purple"]),
            ("hunt",     P["hunt_bg"],         P["accent_teal"]),
            ("normal",   P["bg_panel"],        P["fg_secondary"]),
        ]:
            tree.tag_configure(tag, background=bg, foreground=fg)
        return tree

    def _build_detail_tab(self) -> None:
        P = PALETTE
        frame = self.ttk.Frame(self.notebook, style="Panel.TFrame", padding=12)
        self.notebook.add(frame, text="  Event Details  ")
        top = self.ttk.Frame(frame, style="Panel.TFrame")
        top.pack(fill="x", pady=(0, 8))
        self.ttk.Label(top, text="EVENT INSPECTOR", style="H2.TLabel").pack(side="left", anchor="w")
        af = self.ttk.Frame(top, style="Panel.TFrame")
        af.pack(side="right")
        self.ttk.Button(af, text="⊘ Kill Process",
                        style="Danger.TButton", command=self._action_kill).pack(side="left", padx=(0, 5))
        self.ttk.Button(af, text="⏸ Suspend",
                        style="Warning.TButton", command=self._action_suspend).pack(side="left", padx=(0, 5))
        self.ttk.Button(af, text="⚑ Quarantine File",
                        style="Ghost.TButton", command=self._action_quarantine).pack(side="left")
        self.details = self.tk.Text(
            frame, wrap="word", font=("Consolas", 9),
            bg=P["bg_card"], fg=P["fg_primary"],
            insertbackground=P["accent_blue"],
            selectbackground=P["bg_selected"],
            relief="flat", borderwidth=0, padx=12, pady=10,
        )
        self.details.pack(fill="both", expand=True)

    def _build_stats_tab(self) -> None:
        P = PALETTE
        frame = self.ttk.Frame(self.notebook, style="Panel.TFrame", padding=20)
        self.notebook.add(frame, text="  Statistics  ")
        self.ttk.Label(frame, text="DETECTION STATISTICS & MITRE ATT&CK COVERAGE",
                       style="H2.TLabel").pack(anchor="w", pady=(0, 12))
        self.stats_text = self.tk.Text(
            frame, wrap="word", font=("Consolas", 9),
            bg=P["bg_card"], fg=P["fg_primary"],
            relief="flat", borderwidth=0, padx=12, pady=10, state="disabled",
        )
        self.stats_text.pack(fill="both", expand=True)

    # ── Agent control ──────────────────────────────────────────────────────────
    def start_agent(self) -> None:
        if self.agent_thread and self.agent_thread.is_alive():
            return
        self.config  = load_config(self.config_path)
        self.agent   = EdrAgent(self.config, self.events.put)
        self.agent_thread = threading.Thread(target=self._run_agent,
                                              name="edr-agent", daemon=True)
        self.agent_thread.start()
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self._start_ts = time.time()
        self._set_status("active", "Monitoring")

    def _run_agent(self) -> None:
        try:
            if self.agent:
                self.agent.run()
        except Exception as exc:
            self.events.put({"event_type": "gui_error",
                             "timestamp": utc_now(), "error": repr(exc)})

    def stop_agent(self) -> None:
        if self.agent:
            self.agent.stop()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self._set_status("ready", "Stopped")

    def run_hunt_action(self) -> None:
        if not self.agent:
            self.messagebox.showwarning("Hunt", "Start the agent first.")
            return
        self._set_status("active", "Threat hunting…")
        def _do():
            findings = self.agent.hunter.hunt()
            for f in findings:
                f["event_type"] = "threat_hunt_finding"
                self.events.put(f)
            self.events.put({"event_type": "agent_info",
                             "message": f"Hunt complete — {len(findings)} findings"})
        threading.Thread(target=_do, daemon=True).start()

    def reload_rules_action(self) -> None:
        if self.agent:
            count = self.agent.reload_rules()
            self._set_status("active", f"Rules reloaded ({count})")
        else:
            self._set_status("ready", "Agent not running")

    def reload_telemetry(self) -> None:
        self._clear_tables(clear_details=True)
        self.all_events.clear()
        self._load_existing_telemetry()
        self.apply_filters()
        self._set_status("ready", "Telemetry reloaded")

    def clear_logs(self) -> None:
        if not self.messagebox.askyesno("Clear Logs",
                f"Clear all data and empty:\n{self.telemetry_path}?"):
            return
        try:
            self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
            self.telemetry_path.write_text("", encoding="utf-8")
        except OSError as exc:
            self.messagebox.showerror("Error", f"Could not clear telemetry:\n{exc}")
            return
        self._clear_tables(clear_details=True)
        self.all_events.clear()
        self.apply_filters()
        self._set_status("ready", "Logs cleared")

    # ── Telemetry ──────────────────────────────────────────────────────────────
    def _load_existing_telemetry(self) -> None:
        if not self.telemetry_path.exists():
            return
        try:
            lines = self.telemetry_path.read_text(encoding="utf-8").splitlines()[-1000:]
        except OSError:
            return
        for line in lines:
            try:
                self._add_event(json.loads(line), from_file=True, render=False)
            except json.JSONDecodeError:
                continue

    def _drain_events(self) -> None:
        changed = False
        while True:
            try:
                evt = self.events.get_nowait()
            except queue.Empty:
                break
            self._add_event(evt)
            changed = True
        if changed:
            self._refresh_metrics()
        if (self.agent_thread and not self.agent_thread.is_alive()
                and self.stop_button["state"] == "normal"):
            self.start_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self._set_status("ready", "Stopped")
        self.root.after(300, self._drain_events)

    def _tick_uptime(self) -> None:
        if self.agent and self.agent.running:
            elapsed = int(time.time() - self._start_ts)
            h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
            self._sidebar_rows["uptime"].set(f"{h:02d}:{m:02d}:{s:02d}")
            try:
                cpu = self.agent.self_process.cpu_percent(interval=None)
                self._sidebar_rows["cpu"].set(f"{cpu:.1f}%")
            except Exception:
                pass
            ti = self.agent.stats.get("ti_hits", 0)
            self._sidebar_rows["ti_hits"].set(str(ti))
        self.root.after(1000, self._tick_uptime)

    def _add_event(self, event: dict[str, Any], from_file: bool = False,
                   render: bool = True) -> None:
        self.all_events.append(event)
        if len(self.all_events) > 3000:
            self.all_events = self.all_events[-3000:]
        if render:
            self.apply_filters()
        et = event.get("event_type")
        if et == "gui_error":
            self._set_status("error", f"Error: {event.get('error','')[:60]}")
        elif not from_file and et == "alert":
            sev = event.get("severity", "")
            self._flash_alert(sev)
            rs = event.get("risk_score", {}).get("total", "?")
            self._set_status("alert",
                             f"⚠ [{sev.upper()}] score={rs}  {event.get('rule_id')}")
        elif et == "agent_info":
            self._set_status("active", event.get("message", ""))

    def _flash_alert(self, severity: str) -> None:
        color = {
            "critical": PALETTE["sev_critical"],
            "high":     PALETTE["sev_high"],
            "medium":   PALETTE["sev_medium"],
            "low":      PALETTE["sev_low"],
        }.get(severity, PALETTE["accent_blue"])
        self.status_indicator.configure(fg=color)
        if self._alert_flash_job:
            self.root.after_cancel(self._alert_flash_job)
        self._alert_flash_job = self.root.after(
            3500, lambda: self.status_indicator.configure(fg=PALETTE["accent_cyan"])
        )

    # ── Filtering ──────────────────────────────────────────────────────────────
    def apply_filters(self) -> None:
        self._clear_tables()
        visible = 0
        for event in self.all_events:
            if self._event_matches_filters(event):
                self._insert_event(event)
                visible += 1
        total = len(self.all_events)
        self.filter_count_var.set(f"Showing {visible:,} of {total:,} events")
        self._refresh_metrics()
        self._refresh_stats()

    def reset_filters(self) -> None:
        self.search_var.set("")
        self.type_filter_var.set("All")
        self.severity_filter_var.set("All")
        self.apply_filters()

    def _event_matches_filters(self, event: dict[str, Any]) -> bool:
        et = str(event.get("event_type", ""))
        sel_type = self.type_filter_var.get()
        if sel_type not in ("All", "") and et != sel_type:
            return False
        sel_sev = self.severity_filter_var.get()
        if sel_sev not in ("All", ""):
            if et != "alert" or norm(event.get("severity", "")) != sel_sev:
                return False
        search = norm(self.search_var.get()).strip()
        if search:
            if search not in norm(json.dumps(event, ensure_ascii=False, default=str)):
                return False
        return True

    def _insert_event(self, event: dict[str, Any]) -> None:
        ts      = str(event.get("timestamp", ""))[:19].replace("T", " ")
        et      = str(event.get("event_type", ""))
        proc    = str(event.get("process_name") or
                      event.get("matched_event", {}).get("process_name") or "")
        pid_s   = str(event.get("pid") or
                      event.get("matched_event", {}).get("pid") or "")
        summary = event_summary(event)
        payload = json.dumps(event, ensure_ascii=False, indent=2, default=str)
        score   = str(event.get("risk_score", {}).get("total", ""))

        if et == "alert":
            sev  = norm(event.get("severity", ""))
            tag  = sev if sev in ("critical", "high", "medium", "low") else "normal"
            vals = (ts, sev.upper(), score, event.get("rule_id", ""),
                    event.get("rule_name", ""), proc, summary)
            iid  = self.alert_tree.insert("", 0, values=vals, tags=(tag,))
            self.row_payloads[self._row_key(self.alert_tree, iid)] = payload
            self._trim_tree(self.alert_tree)

        if et == "threat_hunt_finding":
            sev  = norm(event.get("severity", "medium"))
            vals = (ts, sev.upper(), str(event.get("hunt_type", "")),
                    str(event.get("pid", "")), summary)
            iid  = self.hunt_tree.insert("", 0, values=vals, tags=("hunt",))
            self.row_payloads[self._row_key(self.hunt_tree, iid)] = payload
            self._trim_tree(self.hunt_tree)

        # All events tree
        if et == "alert":
            sev    = norm(event.get("severity", ""))
            tag_ev = sev if sev in ("critical", "high", "medium", "low") else "normal"
        elif et in ("agent_start", "agent_stop", "resource_throttle",
                    "rules_reloaded", "agent_info"):
            tag_ev = "system"
        elif et == "response_action":
            tag_ev = "response"
        elif et == "threat_hunt_finding":
            tag_ev = "hunt"
        else:
            tag_ev = "normal"

        vals_ev = (ts, et, proc, pid_s, score, summary)
        iid_ev  = self.event_tree.insert("", 0, values=vals_ev, tags=(tag_ev,))
        self.row_payloads[self._row_key(self.event_tree, iid_ev)] = payload
        self._trim_tree(self.event_tree)

    def _clear_tables(self, clear_details: bool = False) -> None:
        self.event_tree.delete(*self.event_tree.get_children())
        self.alert_tree.delete(*self.alert_tree.get_children())
        self.hunt_tree.delete(*self.hunt_tree.get_children())
        if clear_details:
            self.details.delete("1.0", self.tk.END)
        self.row_payloads.clear()

    def _trim_tree(self, tree: Any, limit: int = 800) -> None:
        children = tree.get_children()
        if len(children) <= limit:
            return
        for iid in children[limit:]:
            self.row_payloads.pop(self._row_key(tree, iid), None)
            tree.delete(iid)

    def _show_selected(self, tree: Any) -> None:
        sel = tree.selection()
        if not sel:
            return
        payload = self.row_payloads.get(self._row_key(tree, sel[0]), "")
        self.details.delete("1.0", self.tk.END)
        self.details.insert("1.0", payload)
        self.notebook.select(3)

    def _row_key(self, tree: Any, iid: str) -> str:
        return f"{id(tree)}:{iid}"

    # ── Metrics & Stats ────────────────────────────────────────────────────────
    def _refresh_metrics(self) -> None:
        events_total = sum(1 for e in self.all_events if e.get("event_type") != "alert")
        alerts_total = sum(1 for e in self.all_events if e.get("event_type") == "alert")
        total_risk   = sum(
            e.get("risk_score", {}).get("total", 0)
            for e in self.all_events if e.get("event_type") == "alert"
        )
        hunt_total   = sum(1 for e in self.all_events
                           if e.get("event_type") == "threat_hunt_finding")
        self._metric_vars["events"][0].set(f"{events_total:,}")
        self._metric_vars["alerts"][0].set(f"{alerts_total:,}")
        self._metric_vars["risk"][0].set(f"{int(total_risk):,}")
        self._metric_vars["hunt"][0].set(f"{hunt_total:,}")
        if self.agent:
            s = self.agent.stats
            self._metric_vars["processes"][0].set(f"{s.get('processes_seen', 0):,}")
            self._metric_vars["connections"][0].set(f"{s.get('connections_seen', 0):,}")
            self._metric_vars["files"][0].set(f"{s.get('files_monitored', 0):,}")
            self._metric_vars["rules_count"][0].set(f"{s.get('rules_loaded', 0)}")
            self._sidebar_rows["rules"].set(f"{s.get('rules_loaded', 0)} rules")
            self._sidebar_rows["agent"].set("ACTIVE")

    def _refresh_stats(self) -> None:
        alerts = [e for e in self.all_events if e.get("event_type") == "alert"]
        sev_c: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        rule_c: dict[str, int] = {}
        tactic_c: dict[str, int] = {}
        total_risk = 0.0
        for a in alerts:
            sev = norm(a.get("severity", ""))
            if sev in sev_c:
                sev_c[sev] += 1
            rid = str(a.get("rule_id", ""))
            rule_c[rid] = rule_c.get(rid, 0) + 1
            for tactic in a.get("mitre_tactics", []):
                tactic_c[tactic] = tactic_c.get(tactic, 0) + 1
            total_risk += a.get("risk_score", {}).get("total", 0)

        lines = [f"  ALERT SEVERITY  {'─'*50}"]
        for sev in ("critical", "high", "medium", "low"):
            cnt = sev_c[sev]
            bar = "█" * min(cnt, 45)
            lines.append(f"  {sev.upper():<10}  {bar:<45}  {cnt}")
        lines.append(f"\n  TOTAL CUMULATIVE RISK SCORE: {int(total_risk):,}")
        lines.append(f"\n  MITRE ATT&CK TACTIC COVERAGE  {'─'*40}")
        for tactic in MITRE_TACTICS:
            cnt = tactic_c.get(tactic, 0)
            if cnt:
                bar = "▪" * min(cnt, 30)
                lines.append(f"  {tactic:<30}  {bar} ({cnt})")
        lines.append(f"\n  TOP TRIGGERED RULES  {'─'*40}")
        for rid, cnt in sorted(rule_c.items(), key=lambda x: x[1], reverse=True)[:15]:
            lines.append(f"  {rid:<35}  {cnt:>4} hits")
        lines.append(f"\n  EVENT TYPE BREAKDOWN  {'─'*40}")
        et_c: dict[str, int] = {}
        for e in self.all_events:
            et = str(e.get("event_type", ""))
            et_c[et] = et_c.get(et, 0) + 1
        for et, cnt in sorted(et_c.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"  {et:<35}  {cnt:>4}")

        text = "\n".join(lines)
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", self.tk.END)
        self.stats_text.insert("1.0", text)
        self.stats_text.configure(state="disabled")

    # ── Status ─────────────────────────────────────────────────────────────────
    def _set_status(self, kind: str, msg: str) -> None:
        colors = {
            "active": (PALETTE["accent_green"],  "● ACTIVE"),
            "alert":  (PALETTE["sev_critical"],  "● ALERT"),
            "error":  (PALETTE["sev_high"],       "● ERROR"),
            "ready":  (PALETTE["fg_muted"],       "● OFFLINE"),
        }
        color, label = colors.get(kind, (PALETTE["fg_muted"], "● OFFLINE"))
        self.status_indicator.configure(text=label, fg=color)
        self.status_text.set(msg)

    # ── Manual actions ─────────────────────────────────────────────────────────
    def _action_kill(self)        -> None: self._manual_action("terminate")
    def _action_suspend(self)     -> None: self._manual_action("suspend")
    def _action_quarantine(self)  -> None: self._manual_action("quarantine")

    def _manual_action(self, action_type: str) -> None:
        if not self.agent:
            self.messagebox.showerror("Error", "Agent is not running.")
            return
        tree = self.alert_tree if self.alert_tree.selection() else self.event_tree
        sel  = tree.selection()
        if not sel:
            self.messagebox.showwarning("No Selection", "Please select an event first.")
            return
        payload_str = self.row_payloads.get(self._row_key(tree, sel[0]), "")
        if not payload_str:
            return
        try:
            event = json.loads(payload_str)
        except Exception:
            return
        matched = event.get("matched_event", event)
        if action_type in ("terminate", "suspend"):
            pid = matched.get("pid")
            if not pid:
                self.messagebox.showwarning("No PID", "No process ID in selected event.")
                return
            try:
                if action_type == "terminate":
                    self.agent.terminate_process(int(pid), matched.get("process_name"), [])
                else:
                    self.agent.suspend_process(int(pid), matched.get("process_name"), [])
                self.messagebox.showinfo("Done", f"Command sent to PID {pid}.")
            except Exception as e:
                self.messagebox.showerror("Failed", str(e))
        elif action_type == "quarantine":
            path = matched.get("path")
            if not path:
                self.messagebox.showwarning("No Path", "No file path in selected event.")
                return
            try:
                self.agent.quarantine_file(Path(path), [])
                self.messagebox.showinfo("Done", f"File quarantined:\n{path}")
            except Exception as e:
                self.messagebox.showerror("Failed", str(e))

    def close(self) -> None:
        self.stop_agent()
        if self._uptime_job:
            self.root.after_cancel(self._uptime_job)
        self.root.after(250, self.root.destroy)

    def run(self) -> None:
        self.root.mainloop()


# ──────────────────────────── CLI Entry Point ─────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=f"{AGENT_NAME} v{VERSION} — Advanced Python EDR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--config", type=Path, default=DEFAULT_CONFIG,
                   help="Path to JSON config file")
    p.add_argument("--gui", action="store_true",
                   help="Launch desktop SOC dashboard")
    p.add_argument("--hunt", action="store_true",
                   help="Run one-shot threat hunt and exit")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.gui:
        EdrDashboard(args.config).run()
        return

    config = load_config(args.config)

    if args.hunt:
        logger = TelemetryLogger(Path(config.get("telemetry_path", "edr_telemetry.json")))
        engine = DetectionEngine(
            Path(config.get("rules_path", "rules/detection_rules.json")),
            logger,
        )
        hunter = ThreatHunter(engine)
        findings = hunter.hunt()
        for f in findings:
            print(json.dumps(f, indent=2, default=str))
        print(f"\n{len(findings)} findings.", file=sys.stderr)
        return

    agent = EdrAgent(config)
    signal.signal(signal.SIGINT,  agent.stop)
    signal.signal(signal.SIGTERM, agent.stop)
    agent.run()


if __name__ == "__main__":
    main()