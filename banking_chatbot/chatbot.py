"""
Module 3 — Banking Chatbot (lab stub)
Extended in Module 6 Project 3 with PCI DSS compliance guardrails.
"""

from __future__ import annotations

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

_session_counts: dict[str, int] = {}
AUDIT_PATH = Path("audit_log/chatbot_tool_calls.jsonl")


def is_financial_query(user_message: str) -> bool:
    """Return True if the message looks like a financial query."""
    tokens = set(user_message.lower().split())
    return bool(tokens & FINANCIAL_KEYWORDS)


def pre_response_pii_filter(response: str) -> str:
    """Redact card numbers (PCI DSS Req 3) and account numbers from responses."""
    response = re.sub(r"\b\d{13,19}\b", "[REDACTED-CARD]", response)
    response = re.sub(r"\b\d{8,12}\b", "[REDACTED-ACCT]", response)
    return response


def rate_limit_check(session_id: str, user_message: str = "balance") -> None:
    """Raise after 20 financial queries per session (PCI DSS Req 6)."""
    if not is_financial_query(user_message):
        return
    count = _session_counts.get(session_id, 0) + 1
    _session_counts[session_id] = count
    if count > 20:
        # Do not expose session_id or count to callers — log internally only
        write_audit_log_entry({"session_id": session_id, "event": "rate_limit_exceeded", "count": count})
        raise RuntimeError("Rate limit exceeded. Please contact support.")


def write_audit_log_entry(event: dict) -> None:
    """Append a JSONL audit record (PCI DSS Req 10)."""
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "CHATBOT_TOOL_CALL",
        **event,
    }
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def sanitize_input(user_message: str) -> str:
    """Strip control characters and enforce max length (PCI DSS Req 6 — input validation)."""
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", user_message)
    return sanitized[:4096]


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
