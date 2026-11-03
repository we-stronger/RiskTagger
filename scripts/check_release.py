"""Scan publishable files without printing secrets; optionally audit Git history.

python scripts/check_release.py
python scripts/check_release.py --staged
python scripts/check_release.py --history
"""
import argparse
import ast
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {".gitignore", ".env.example", "project_config.py", "project_settings.yaml",
              "runtime_security.py", "requirements.txt", "README.md"}
PUBLIC_DIRS = {"Tracer", "Explainer", "scripts", "tests", "examples", ".githooks", ".github"}
PUBLIC_SUFFIXES = {".py", ".json", ".yaml", ".yml", ".toml", ".sh"}
SECRET_NAME = re.compile(r"(?i)(api[_-]?keys?\d*|secret|password|private[_-]?key|access[_-]?token|auth[_-]?token)")
TOKEN_PATTERN = re.compile(r"(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AIza[A-Za-z0-9_-]{25,}|AKIA[A-Z0-9]{16})")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
CREDENTIAL_URL = re.compile(r"(?i)(?:https?://[^\s/]+/(?:v2|v3)/[A-Za-z0-9_-]{20,}|[?&](?:apikey|api_key|token|key)=[A-Za-z0-9_-]{16,})")


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def forbidden_path(name):
    path = Path(name)
    for part in path.parts:
        lower = part.lower()
        if lower in {".git", ".aws", ".ssh", "__pycache__", "data", "outputs", "external", "dist", "backend", "frontend", "extractor"}:
            return True
        if lower.startswith(".env") and lower != ".env.example":
            return True
    return path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".pkl", ".log", ".pdf", ".zip", ".pyc"} or bool(
        re.search(r"(?i)(credentials.*\.json|service-account.*\.json)$", path.name))


def public_path(name):
    path = Path(name)
    return not forbidden_path(name) and (name in ROOT_FILES or (
        path.parts[0] in PUBLIC_DIRS and (path.suffix in PUBLIC_SUFFIXES or path.parts[0] == ".githooks")))


def local_secret_values():
    """Known local .env values are compared in memory, never emitted."""
    path = ROOT / ".env"
    if not path.exists():
        return []
    values = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        name, separator, value = line.partition("=")
        if separator and not name.lstrip().startswith("#") and (SECRET_NAME.search(name) or "RPC_URL" in name):
            for item in value.strip().strip("\"'").split(","):
                if len(item.strip()) >= 12:
                    values.append(item.strip())
    return values


def suspicious_literal(value):
    return (isinstance(value, str) and len(value) >= 12
            and not value.lower().startswith(("your_", "replace_", "placeholder", "etherscan_key_", "http", "set "))
            and bool(re.fullmatch(r"[A-Za-z0-9_+/=.-]+", value))
            and not re.fullmatch(r"[A-Z][A-Z0-9_]+", value))


def scan_text(name, text, known_values=()):
    findings = set()
    for number, line in enumerate(text.splitlines(), 1):
        if TOKEN_PATTERN.search(line) or PRIVATE_KEY.search(line) or CREDENTIAL_URL.search(line):
            findings.add((name, number, "credential pattern"))
        if any(value in line for value in known_values):
            findings.add((name, number, "matches local credential"))
        value_pattern = r"\s*[\"']?([\w-]+)[\"']?\s*[:=]\s*[\"']([^\s\"',}]+)[\"']"
        if not str(name).endswith(".py"):
            value_pattern = r"\s*[\"']?([\w-]+)[\"']?\s*[:=]\s*[\"']?([^\s\"',}]+)"
        match = re.match(value_pattern, line)
        if match and SECRET_NAME.search(match[1]) and not match[1].lower().endswith("_env") and suspicious_literal(match[2]):
            findings.add((name, number, "literal credential"))
    if str(name).endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            findings.add((name, 0, "Python syntax error"))
            return sorted(findings)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not any(SECRET_NAME.search(ast.unparse(target)) for target in targets):
                    continue
                # Inspect direct constants, not environment-variable names passed to calls.
                if isinstance(node.value, ast.Constant) and suspicious_literal(node.value.value):
                    findings.add((name, node.lineno, "literal credential assignment"))
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and SECRET_NAME.search(key.value):
                        if isinstance(value, ast.Constant) and suspicious_literal(value.value):
                            findings.add((name, value.lineno, "literal credential in mapping"))
            if isinstance(node, ast.keyword) and node.arg and SECRET_NAME.search(node.arg):
                if isinstance(node.value, ast.Constant) and suspicious_literal(node.value.value):
                    findings.add((name, node.value.lineno, "literal credential argument"))
    return sorted(findings)


def candidate_names(staged=False):
    if not (ROOT / ".git").exists():
        if staged:
            raise ValueError("No Git metadata; initialize the repository before scanning staged files")
        paths = [ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()]
        for directory in PUBLIC_DIRS:
            folder = ROOT / directory
            if folder.exists():
                paths.extend(path for path in folder.rglob("*") if path.is_file()
                             and public_path(path.relative_to(ROOT).as_posix()))
        return sorted({path.relative_to(ROOT).as_posix() for path in paths})
    if staged:
        data = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    else:
        data = git("ls-files", "--cached", "--others", "--exclude-standard", "-z")
    return sorted(set(item.decode("utf-8") for item in data.split(b"\0") if item))


def scan_worktree(staged=False):
    findings = []
    known = local_secret_values()
    for name in candidate_names(staged):
        path = ROOT / name
        if not staged and not path.exists():
            continue  # Locally deleted files are not part of the release archive.
        if forbidden_path(name):
            findings.append((name, 0, "private or generated file selected for Git"))
            continue
        if not staged and (path.is_symlink() or not path.resolve().is_relative_to(ROOT)):
            findings.append((name, 0, "link outside release boundary"))
            continue
        data = git("show", f":{name}") if staged else path.read_bytes()
        findings.extend(scan_text(name, data.decode("utf-8-sig", errors="replace"), known))
    return sorted(set(findings))


def scan_history():
    if not (ROOT / ".git").exists():
        return []
    findings = []
    seen = set()
    known = local_secret_values()
    for commit in git("rev-list", "--all").decode().splitlines():
        for entry in git("ls-tree", "-r", "-z", commit).split(b"\0"):
            if not entry:
                continue
            metadata, name_bytes = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if kind != b"blob" or oid in seen:
                continue
            seen.add(oid)
            name = name_bytes.decode("utf-8")
            label = f"{commit[:8]}:{name}"
            history_parts = Path(name).parts
            if any(part.lower().startswith('.env') and part.lower() != '.env.example' for part in history_parts) or Path(name).suffix in {'.pem', '.key', '.p12', '.pfx'}:
                findings.append((label, 0, "private file in Git history"))
            if Path(name).suffix in {".py", ".yaml", ".yml", ".json", ".toml", ".txt", ".md"} or name == ".env.example":
                data = git("cat-file", "blob", oid.decode())
                findings.extend(scan_text(label, data.decode("utf-8-sig", errors="replace"), known))
    return sorted(set(findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--staged", action="store_true", help="Scan staged blobs rather than working copies")
    parser.add_argument("--history", action="store_true", help="Also scan every commit reachable from local refs")
    args = parser.parse_args()
    if not (ROOT / ".git").exists():
        if args.staged:
            parser.error("No Git metadata; initialize the repository before scanning staged files")
        print("Git metadata absent: scanning publishable source files; no local history to inspect.")
    findings = scan_worktree(args.staged)
    if args.history:
        findings.extend(scan_history())
    for name, number, reason in findings:
        print(f"{name}:{number}: {reason} [value hidden]")
    print(f"Release scan: {'FAIL' if findings else 'PASS'} ({len(findings)} findings)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
