"""Contract queries using local RPC credentials and a configurable public fallback."""
import os
import re
import requests
from project_config import get_module_settings


def _build_providers():
    settings = get_module_settings("tracer")["rpc"]
    private_urls = [url.strip() for url in os.getenv(settings["urls_env"], "").split(",") if url.strip()]
    urls = list(dict.fromkeys(private_urls + settings["public_urls"]))
    return [{"url": url, "failures": 0} for url in urls]


providers = _build_providers()


def is_contract(address):
    """Return 0 for EOAs, 1 for contracts, or a diagnostic when all RPCs fail."""
    if not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
        return "Invalid Ethereum address"
    timeout = get_module_settings("tracer")["rpc"]["timeout_seconds"]
    for provider in sorted(providers, key=lambda item: item["failures"]):
        try:
            response = requests.post(
                provider["url"], timeout=timeout,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]},
            )
            response.raise_for_status()
            payload = response.json()
            code = payload.get("result")
            if "error" in payload or not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", code):
                raise ValueError("Invalid RPC response")
            provider["failures"] = 0
            return 0 if code == "0x" else 1
        except Exception:
            # Provider URLs and exception text can contain credentials.
            provider["failures"] += 1
    return "All Ethereum RPC providers failed; check local credentials or connectivity"
