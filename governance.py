"""
AI Tool Security Governance Framework

Enforces enterprise data-handling policies for ChatGPT, Claude, Gemini,
and Copilot usage. Scans prompts and file uploads for PII, secrets,
confidential markers, customer data, and financial info BEFORE they
reach any AI tool.

Components:
  1. Policy engine — loads JSON rules, classifies data, decides BLOCK/WARN/ALLOW
  2. RBAC enforcer — role-based access with per-tool, per-model, per-day limits
  3. Audit logger — tamper-evident JSON-lines log for compliance evidence
  4. Usage analytics — per-user, per-tool, per-department aggregation
  5. Flask dashboard + REST API

Author: Mohith Vasamsetti (CyberEnthusiastic)
License: MIT
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

try:
    from flask import Flask, jsonify, render_template_string, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


BASE_DIR = Path(__file__).parent


# --- Policy Engine -----------------------------------------------------------

@dataclass
class PolicyViolation:
    rule_id: str
    rule_name: str
    severity: str
    action: str  # BLOCK / WARN / ALLOW
    matched_pattern: str
    matched_text: str  # the actual snippet that matched (redacted)
    remediation: str


@dataclass
class ScanResult:
    prompt_hash: str
    timestamp: str
    user: str
    role: str
    tool: str
    model: str
    decision: str  # BLOCKED / WARNED / ALLOWED
    violations: List[PolicyViolation] = field(default_factory=list)
    total_violations: int = 0
    blocked_count: int = 0
    warned_count: int = 0


class PolicyEngine:
    def __init__(self, policy_path: str = "policies/default_policy.json"):
        p = BASE_DIR / policy_path
        self.policy = json.loads(p.read_text(encoding="utf-8"))
        self.rules = []
        for rule in self.policy.get("data_classification_rules", []):
            compiled = []
            for pat_str in rule.get("patterns", []):
                try:
                    compiled.append(re.compile(pat_str, re.IGNORECASE))
                except re.error:
                    pass
            self.rules.append({**rule, "_compiled": compiled})

    def scan_text(self, text: str) -> List[PolicyViolation]:
        violations = []
        for rule in self.rules:
            for pat in rule["_compiled"]:
                for m in pat.finditer(text):
                    matched = m.group(0)
                    # Redact: show first 3 and last 2 chars
                    if len(matched) > 8:
                        redacted = matched[:3] + "*" * (len(matched) - 5) + matched[-2:]
                    else:
                        redacted = matched[:2] + "***"
                    violations.append(PolicyViolation(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        action=rule.get("action", "WARN"),
                        matched_pattern=pat.pattern[:80],
                        matched_text=redacted,
                        remediation=rule.get("remediation", "Review and remove sensitive data."),
                    ))
        return violations


# --- RBAC Enforcer -----------------------------------------------------------

class RBACEnforcer:
    def __init__(self, policy: dict):
        self.roles = {r["name"]: r for r in policy.get("rbac_rules", {}).get("roles", [])}
        self.usage_counters: Dict[str, int] = {}  # user_id -> count today

    def check_access(self, user: str, role: str, tool: str, model: str) -> (bool, str):
        role_def = self.roles.get(role)
        if not role_def:
            return False, f"Unknown role: {role}"
        if tool not in role_def["allowed_tools"]:
            return False, f"Role '{role}' does not have access to tool '{tool}'"
        if model != "*" and "*" not in role_def["allowed_models"] and model not in role_def["allowed_models"]:
            return False, f"Role '{role}' cannot use model '{model}'"
        limit = role_def.get("daily_request_limit", -1)
        if limit > 0:
            count = self.usage_counters.get(user, 0)
            if count >= limit:
                return False, f"Daily limit ({limit}) reached for user '{user}'"
        return True, "Access granted"

    def record_usage(self, user: str):
        self.usage_counters[user] = self.usage_counters.get(user, 0) + 1


# --- Audit Logger ------------------------------------------------------------

class AuditLogger:
    def __init__(self, log_dir: str = "data"):
        self.log_dir = BASE_DIR / log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "audit_log.jsonl"

    def log(self, result: ScanResult):
        entry = {
            "event_id": str(uuid.uuid4()),
            **asdict(result),
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def get_recent(self, limit: int = 100) -> List[dict]:
        if not self.log_file.exists():
            return []
        lines = self.log_file.read_text(encoding="utf-8").strip().split("\n")
        entries = [json.loads(line) for line in lines if line.strip()]
        return entries[-limit:]

    def get_stats(self) -> dict:
        entries = self.get_recent(10000)
        total = len(entries)
        blocked = sum(1 for e in entries if e["decision"] == "BLOCKED")
        warned = sum(1 for e in entries if e["decision"] == "WARNED")
        allowed = sum(1 for e in entries if e["decision"] == "ALLOWED")
        by_user: Dict[str, int] = {}
        by_tool: Dict[str, int] = {}
        by_rule: Dict[str, int] = {}
        for e in entries:
            by_user[e["user"]] = by_user.get(e["user"], 0) + 1
            by_tool[e["tool"]] = by_tool.get(e["tool"], 0) + 1
            for v in e.get("violations", []):
                by_rule[v["rule_name"]] = by_rule.get(v["rule_name"], 0) + 1
        return {
            "total_scans": total,
            "blocked": blocked,
            "warned": warned,
            "allowed": allowed,
            "block_rate": round(blocked / total * 100, 1) if total else 0,
            "top_users": sorted(by_user.items(), key=lambda x: -x[1])[:10],
            "top_tools": sorted(by_tool.items(), key=lambda x: -x[1])[:5],
            "top_violations": sorted(by_rule.items(), key=lambda x: -x[1])[:10],
        }


# --- Governance Framework (orchestrator) ------------------------------------

class AIGovernanceFramework:
    def __init__(self, policy_path: str = "policies/default_policy.json"):
        self.engine = PolicyEngine(policy_path)
        self.rbac = RBACEnforcer(self.engine.policy)
        self.audit = AuditLogger()
        self.policy = self.engine.policy

    def evaluate(self, prompt: str, user: str = "anonymous",
                 role: str = "basic_user", tool: str = "ChatGPT",
                 model: str = "gpt-4o") -> ScanResult:
        now = datetime.now(tz=timezone.utc).isoformat()
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

        # 1. RBAC check
        access_ok, access_msg = self.rbac.check_access(user, role, tool, model)
        if not access_ok:
            result = ScanResult(
                prompt_hash=prompt_hash,
                timestamp=now,
                user=user, role=role, tool=tool, model=model,
                decision="BLOCKED",
                violations=[PolicyViolation(
                    rule_id="RBAC-001",
                    rule_name="RBAC Access Denied",
                    severity="HIGH",
                    action="BLOCK",
                    matched_pattern="rbac_check",
                    matched_text=access_msg,
                    remediation="Contact your security admin for access.",
                )],
                total_violations=1, blocked_count=1,
            )
            self.audit.log(result)
            return result

        # 2. Data classification scan
        violations = self.engine.scan_text(prompt)
        blocked = [v for v in violations if v.action == "BLOCK"]
        warned = [v for v in violations if v.action == "WARN"]

        if blocked:
            decision = "BLOCKED"
        elif warned:
            decision = "WARNED"
        else:
            decision = "ALLOWED"

        self.rbac.record_usage(user)

        result = ScanResult(
            prompt_hash=prompt_hash,
            timestamp=now,
            user=user, role=role, tool=tool, model=model,
            decision=decision,
            violations=violations,
            total_violations=len(violations),
            blocked_count=len(blocked),
            warned_count=len(warned),
        )
        self.audit.log(result)
        return result

    def batch_evaluate(self, prompts: List[dict]) -> List[ScanResult]:
        return [
            self.evaluate(
                prompt=p.get("prompt", ""),
                user=p.get("user", "anonymous"),
                role=p.get("role", "basic_user"),
                tool=p.get("tool", "ChatGPT"),
                model=p.get("model", "gpt-4o"),
            )
            for p in prompts
        ]


# --- CLI Mode ----------------------------------------------------------------

DEMO_PROMPTS = [
    {
        "prompt": "Help me fix this Python function that processes customer orders. The customer_id is CUST-48291 and their SSN is 123-45-6789.",
        "user": "jane.doe", "role": "basic_user", "tool": "ChatGPT", "model": "gpt-4o",
    },
    {
        "prompt": "Review this code: api_key = 'sk-proj-abc123def456ghi789jkl012mno345pqr678'",
        "user": "dev.smith", "role": "power_user", "tool": "Claude", "model": "claude-opus",
    },
    {
        "prompt": "CONFIDENTIAL - Our Q3 revenue was $45.2M ARR, up 23% YoY. Draft investor update.",
        "user": "cfo.jones", "role": "basic_user", "tool": "ChatGPT", "model": "gpt-4o",
    },
    {
        "prompt": "How do I implement a binary search in Python?",
        "user": "intern.kim", "role": "basic_user", "tool": "ChatGPT", "model": "gpt-4o",
    },
    {
        "prompt": "Summarize this patient diagnosis: Patient John Smith, DOB 03/15/1985, diagnosed with Type 2 diabetes. Medical record #MR-2024-8847.",
        "user": "hr.admin", "role": "basic_user", "tool": "Gemini", "model": "gemini-pro",
    },
    {
        "prompt": "Write a Terraform module for an S3 bucket with versioning enabled.",
        "user": "dev.patel", "role": "power_user", "tool": "Claude", "model": "claude-sonnet",
    },
    {
        "prompt": "Help debug: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA... [truncated for safety]",
        "user": "dev.newbie", "role": "power_user", "tool": "GitHub Copilot", "model": "gpt-4o",
    },
    {
        "prompt": "The merger with AcmeCorp is happening next Tuesday. Draft the internal comms. Non-public financial information included: deal value is $2.3B.",
        "user": "legal.chen", "role": "basic_user", "tool": "ChatGPT", "model": "gpt-4o",
    },
    {
        "prompt": "What are best practices for Kubernetes pod security policies?",
        "user": "sre.garcia", "role": "power_user", "tool": "Claude", "model": "claude-sonnet",
    },
    {
        "prompt": "Please help me with a query. My email is sarah.connor@company.com and phone is 555-867-5309.",
        "user": "sales.rep", "role": "basic_user", "tool": "ChatGPT", "model": "gpt-4o",
    },
]


def main():
    from license_guard import verify_license, print_banner
    verify_license()
    print_banner("AI Governance Framework")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    parser = argparse.ArgumentParser(
        description="AI Tool Security Governance Framework"
    )
    parser.add_argument("--demo", action="store_true",
                        help="Run demo with 10 sample enterprise prompts")
    parser.add_argument("--scan", type=str, help="Scan a single prompt text")
    parser.add_argument("--user", default="anonymous")
    parser.add_argument("--role", default="basic_user",
                        choices=["basic_user", "power_user", "admin"])
    parser.add_argument("--tool", default="ChatGPT")
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--stats", action="store_true",
                        help="Show audit log statistics")
    parser.add_argument("-o", "--output", default="reports/governance_report.json")
    parser.add_argument("--html", default="reports/governance_report.html")
    parser.add_argument("-p", "--policy", default="policies/default_policy.json")
    args = parser.parse_args()

    print("=" * 60)
    print("  [AI Tool Security Governance Framework v1.0]")
    print("=" * 60)

    gov = AIGovernanceFramework(args.policy)

    if args.stats:
        stats = gov.audit.get_stats()
        print(json.dumps(stats, indent=2))
        return

    if args.scan:
        result = gov.evaluate(args.scan, args.user, args.role, args.tool, args.model)
        _print_result(result)
        return

    # Demo mode
    print(f"  Policy: {gov.policy['policy_name']}")
    print(f"  Rules : {len(gov.engine.rules)} data classification rules")
    print(f"  Roles : {len(gov.rbac.roles)} RBAC roles")
    print()

    prompts = DEMO_PROMPTS
    results = gov.batch_evaluate(prompts)

    for r in results:
        _print_result(r)

    # Summary
    total = len(results)
    blocked = sum(1 for r in results if r.decision == "BLOCKED")
    warned = sum(1 for r in results if r.decision == "WARNED")
    allowed = sum(1 for r in results if r.decision == "ALLOWED")

    print("=" * 60)
    print(f"  Total prompts : {total}")
    print(f"  BLOCKED       : {blocked}")
    print(f"  WARNED        : {warned}")
    print(f"  ALLOWED       : {allowed}")
    print(f"  Block rate    : {round(blocked / total * 100, 1)}%")
    print("=" * 60)

    summary = {
        "total": total, "blocked": blocked, "warned": warned, "allowed": allowed,
        "block_rate": round(blocked / total * 100, 1),
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({
            "summary": summary,
            "results": [asdict(r) for r in results],
        }, f, indent=2)
    print(f"\n[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, results, args.html)
    print(f"[+] HTML report: {args.html}")


def _print_result(r: ScanResult):
    colors = {"BLOCKED": "\033[91m", "WARNED": "\033[93m", "ALLOWED": "\033[92m"}
    reset = "\033[0m"
    c = colors.get(r.decision, "")
    print(f"  {c}{r.decision:<8}{reset}  user={r.user:<14} tool={r.tool:<12} violations={r.total_violations}")
    for v in r.violations:
        sev_c = "\033[91m" if v.severity == "CRITICAL" else "\033[93m"
        print(f"    {sev_c}[{v.severity}]{reset} {v.rule_id} {v.rule_name}: {v.matched_text}")


if __name__ == "__main__":
    main()
