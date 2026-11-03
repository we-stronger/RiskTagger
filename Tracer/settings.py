"""Tracer runtime settings.

Non-secret values live in project_settings.yaml; credentials come from the
environment or the Git-ignored root .env file.
"""

import os
from project_config import (
    CASE_INPUT_ROOT,
    PROJECT_ROOT,
    TRACER_OUTPUT_ROOT,
    TRACER_REFERENCE_ROOT,
    get_case_profile_path,
    get_event_name,
    get_module_settings,
    resolve_project_path,
)


SETTINGS = get_module_settings("tracer")

EVENT_NAME = get_event_name()
SPIDER_SETTINGS = SETTINGS["spider"]
LLM_SETTINGS = SETTINGS["llm"]
FILTER_SETTINGS = SETTINGS["filter"]


class Config:
    """Runtime view of the values in project_settings.yaml."""

    BASE_DIR = PROJECT_ROOT
    EVENT_NAME = EVENT_NAME
    DATA_DIR = TRACER_OUTPUT_ROOT / EVENT_NAME / "data"
    DATA_LLM_DIR = TRACER_OUTPUT_ROOT / EVENT_NAME
    SPIDER_DIR = resolve_project_path(os.getenv("BLOCKCHAIN_SPIDER_DIR", SETTINGS["spider"]["directory"]))
    CASE_PROFILE = get_case_profile_path(EVENT_NAME)
    CONTRACT_CACHE_FILE = TRACER_OUTPUT_ROOT / "contract_check_cache.json"
    PATHS = {
        "source_addr": DATA_DIR / "src_addr_token",
        "base_source_addr": CASE_INPUT_ROOT / EVENT_NAME / "source_addr_token",
        "raw_tx_data": DATA_DIR / "blockscan_data",
        "normal_addr_info": DATA_DIR / "all_data_normal",
        "risktagger_hack": DATA_DIR / "RiskTagger_hack",
        "reference": TRACER_REFERENCE_ROOT,
        "llm_result": DATA_LLM_DIR / "LLM_result/llmResult",
        "llm_input": DATA_LLM_DIR / "LLM_result/llmInput",
        "mappings": DATA_DIR / "mappings",
        "memory_db": DATA_LLM_DIR / "llm_memory_db",
        "crosschain_data": DATA_DIR / "crosschain_data",
        "logs": DATA_LLM_DIR / "logs",
        "result": DATA_DIR / "result",
    }

    class Spider:
        _keys_str = os.getenv(SPIDER_SETTINGS["api_keys_env"], "")
        API_KEYS = [key.strip() for key in _keys_str.split(",") if key.strip()]
        ENDPOINT = SPIDER_SETTINGS["endpoint"]
        STRATEGY = SPIDER_SETTINGS["strategy"]
        TYPE = ",".join(SPIDER_SETTINGS["middlewares"])
        MAX_WORKERS = SPIDER_SETTINGS["max_workers"]
        TIMEOUT = SPIDER_SETTINGS["timeout_seconds"]

    class LLM:
        API_KEY = os.getenv(LLM_SETTINGS["api_key_env"])
        MODEL_NAME = LLM_SETTINGS["model"]
        BASE_URL = LLM_SETTINGS["base_url"]
        API_KEY_EMB = os.getenv(LLM_SETTINGS["embedding_api_key_env"])
        MODEL_NAME_EMB = LLM_SETTINGS["embedding_model"]
        BASE_URL_EMB = LLM_SETTINGS["embedding_base_url"]
        TEMPERATURE = LLM_SETTINGS["temperature"]
        MAX_TOKENS = LLM_SETTINGS["max_tokens"]

    class Filter:
        MIN_AMOUNT = FILTER_SETTINGS["min_amount"]
        MAX_ADDRESSES_PER_HOP = FILTER_SETTINGS["max_addresses_per_hop"]
        MAX_HOP = FILTER_SETTINGS["max_hop"]
        TOP_AMOUNT_RATIO = FILTER_SETTINGS["top_amount_ratio"]
        COVERAGE_THRESHOLD = FILTER_SETTINGS["coverage_threshold"]
        Trace_others = FILTER_SETTINGS["trace_others"]
        CONTRACT_TRACE = FILTER_SETTINGS["contract_trace"]
        MAX_TIME_WINDOW = FILTER_SETTINGS["max_time_window_seconds"]
        _START_TIMESTAMP_BY_EVENT = FILTER_SETTINGS["start_timestamp_by_event"]
        _DEFAULT_START_TIMESTAMP = FILTER_SETTINGS["default_start_timestamp"]
        START_TIMESTAMP = _START_TIMESTAMP_BY_EVENT.get(EVENT_NAME, _DEFAULT_START_TIMESTAMP)
        CONTRACT_WHITELIST = set(FILTER_SETTINGS["contract_whitelist"])

    class Concurrency:
        PROCESS_WORKERS = SETTINGS["concurrency"]["process_workers"]

    @staticmethod
    def ensure_dirs():
        """Create the directories required by the active tracing run."""
        for path in Config.PATHS.values():
            if path not in (Config.PATHS["base_source_addr"], Config.PATHS["reference"]):
                path.mkdir(parents=True, exist_ok=True)
