from functools import lru_cache
import os
from pathlib import Path
from typing import Union

import yaml
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
PROJECT_SETTINGS_FILE = PROJECT_ROOT / "project_settings.yaml"
load_dotenv(PROJECT_ROOT / ".env", override=False)


@lru_cache(maxsize=1)
def load_project_settings() -> dict:
    """Load the single user-editable runtime configuration file."""
    with PROJECT_SETTINGS_FILE.open("r", encoding="utf-8") as file:
        settings = yaml.safe_load(file) or {}
    if not isinstance(settings, dict) or "modules" not in settings:
        raise ValueError(f"Invalid project settings: {PROJECT_SETTINGS_FILE}")
    return settings


def get_module_settings(module_name: str) -> dict:
    """Return one module's settings and fail early on a misspelled module name."""
    try:
        return load_project_settings()["modules"][module_name]
    except KeyError as exc:
        raise KeyError(f"Missing settings for module '{module_name}'") from exc


def resolve_project_path(value: Union[str, Path]) -> Path:
    """Resolve a project-relative configuration path."""
    path = Path(value)
    return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()

DATA_ROOT = PROJECT_ROOT / "data"
CASE_INPUT_ROOT = DATA_ROOT / "cases"
OUTPUT_ROOT = PROJECT_ROOT / "outputs"
TRACER_OUTPUT_ROOT = OUTPUT_ROOT / "tracer"
TRACER_REFERENCE_ROOT = DATA_ROOT / "reference_list"
EXPLAINER_OUTPUT_ROOT = OUTPUT_ROOT / "explainer"


def get_event_name() -> str:
    """Use one event for both paper components; prohibit path traversal."""
    name = os.getenv("RISKTAGGER_EVENT_NAME", get_module_settings("tracer")["runtime"]["event_name"])
    if not name or name in {".", ".."} or any(char in name for char in '/\\:'):
        raise ValueError("Event name must be a single directory name")
    return name


def get_case_profile_path(event_name: str) -> Path:
    return CASE_INPUT_ROOT / event_name / "case_profile.json"


def require_environment(name: str) -> str:
    """Fail without including credential values in error messages."""
    value = os.getenv(name, "").strip()
    if not value or value.lower().startswith(("your_", "replace_")):
        raise ValueError(f"Set {name} in the environment or the local .env file")
    return value
