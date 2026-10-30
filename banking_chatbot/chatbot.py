"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from llm_client import get_llm_client, resolve_model

load_dotenv()

FINANCIAL_KEYWORDS = frozenset({
    "balance", "transfer", "account", "statement", "loan",
    "credit", "debit", "transaction", "payment",
})

# Patterns that suggest injection attempts (PCI DSS Req 6)
_INJECTION_PATTERN = re.compile(
    r"(--|;|\bDROP\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b"
    r"|\bEXEC\b|\bSCRIPT\b|<[a-z]|\$\{|\beval\b|\bexec\b)",
    re.IGNORECASE,
)

# Absolute audit log path — resolved relative to this file so it is stable
# regardless of the working directory.  Override with AUDIT_LOG_PATH env var.
_DEFAULT_AUDIT_DIR = Path(__file__).resolve().parent.parent / "audit_log"
AUDIT_PATH = Path(os.environ.get("AUDIT_LOG_PATH",
                                  str(_DEFAULT_AUDIT_DIR / "chatbot_tool_calls.jsonl")))

# Rate-limit state backed by a file so counts survive process restarts
# (PCI DSS Req 6).  File path follows the same env-var override pattern.
_RATE_LIMIT_PATH = Path(os.environ.get("RATE_LIMIT_STATE_PATH",
                                        str(_DEFAULT_AUDIT_DIR / ".rate_limit_state.json")))


def _load_rate_counts() -> dict[str, int]:
    """Load per-session financial query counts from the persistent state file."""
    if not _RATE_LIMIT_PATH.exists():
        return {}
    try:
        return json.loads(_RATE_LIMIT_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_rate_counts(counts: dict[str, int]) -> None:
    """Atomically persist rate-limit counts with exclusive locking."""
    _RATE_LIMIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_RATE_LIMIT_PATH, "w", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(counts))
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    # Restrict state file to owner only — contains session identifiers (PCI DSS Req 10.7)
    os.chmod(_RATE_LIMIT_PATH, 0o600)


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def pre_response_pii_filter(response: str) -> str:
    """Redact card/account numbers (PCI DSS Req 3) — handles plain, spaced, and dashed formats."""
    # Redact 13–19 consecutive digits with optional spaces/dashes (card numbers)
    response = re.sub(r"\b\d[\d \-]{11,17}\d\b", "[REDACTED-CARD]", response)
    response = re.sub(r"\b\d{13,19}\b", "[REDACTED-CARD]", response)
    # Redact 8–12 consecutive digits (account numbers)
    response = re.sub(r"\b\d{8,12}\b", "[REDACTED-ACCT]", response)
    return response


def rate_limit_check(session_id: str, user_message: str = "balance") -> None:
    """Raise after 20 financial queries per session (PCI DSS Req 6).

    Counts are persisted to a file so they survive process restarts.
    """
    if not is_financial_query(user_message):
        return
    counts = _load_rate_counts()
    count = counts.get(session_id, 0) + 1
    counts[session_id] = count
    _save_rate_counts(counts)
    if count > 20:
        # Do not expose session_id or count to callers — log internally only
        write_audit_log_entry({"session_id": session_id, "event": "rate_limit_exceeded", "count": count})
        raise RuntimeError("Rate limit exceeded. Please contact support.")


def write_audit_log_entry(event: dict) -> None:
    """Append a JSONL audit record with file locking to prevent race conditions (PCI DSS Req 10)."""
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "CHATBOT_TOOL_CALL",
        **event,
    }
    # Exclusive lock prevents concurrent write corruption
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            f.write(json.dumps(entry) + "\n")
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    # Restrict audit log to owner only (PCI DSS Req 10.7)
    os.chmod(AUDIT_PATH, 0o600)


def sanitize_input(user_message: str) -> str:
    """Validate and sanitize input: strip control chars, enforce length, reject injection (PCI DSS Req 6)."""
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", user_message)
    sanitized = sanitized[:4096]
    if _INJECTION_PATTERN.search(sanitized):
        raise ValueError("Input contains disallowed patterns. Please rephrase your request.")
    return sanitized


def run_with_guardrails(user_message: str, session_id: str) -> str:
    """Chain input validation, rate limit, call Claude, PII filter, then write audit log."""
    clean_message = sanitize_input(user_message)
    rate_limit_check(session_id, clean_message)
    raw = call_claude(clean_message)
    filtered = pre_response_pii_filter(raw)
    write_audit_log_entry({
        "session_id": session_id,
        "financial_query": is_financial_query(clean_message),
        "response_length": len(filtered),
        "input_length": len(clean_message),
    })
    return filtered


def call_claude(user_message: str, tools: list[dict[str, Any]] | None = None) -> str:
    """Send a user message to Claude and return the text response."""
    client = get_llm_client()
    response = client.messages.create(
        model=resolve_model("claude-sonnet-4-5"),
        max_tokens=1024,
        tools=tools or [],
        messages=[{"role": "user", "content": user_message}],
    )
    for block in response.content:
        if block.type == "text":
            return block.text
    return ""


def handle_message(user_message: str) -> str:
    """Basic chatbot handler — guardrails added in Module 6 Project 3."""
    return call_claude(user_message)


if __name__ == "__main__":
    print(handle_message("What services does Heritage National Bank offer?"))
