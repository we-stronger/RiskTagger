"""Redact credentials from diagnostic messages without printing their values."""
import os
import re


def redact_sensitive_text(message: str) -> str:
    text = str(message)
    for name, value in os.environ.items():
        if re.search(r"(?i)(key|secret|password|token|rpc_urls)", name) and len(value) >= 8:
            for part in value.split(","):
                if len(part.strip()) >= 8:
                    text = text.replace(part.strip(), "[REDACTED]")
    text = re.sub(r"(?i)([?&](?:apikey|api_key|token|key)=)[^&\s]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)(https?://[^\s/]+/(?:v3|v2)/)[A-Za-z0-9_-]{16,}", r"\1[REDACTED]", text)
    return text
