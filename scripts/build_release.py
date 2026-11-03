"""Export an audited source ZIP without .git, credentials, local data, or outputs.

Run: python scripts/build_release.py
Publish by extracting the ZIP into a NEW repository. Do not push the old Git history.
"""
import argparse
from pathlib import Path
import sys
from zipfile import ZipFile, ZIP_DEFLATED

if __package__:
    from .check_release import ROOT, PUBLIC_DIRS, ROOT_FILES, public_path, scan_text, scan_worktree, local_secret_values
else:
    from check_release import ROOT, PUBLIC_DIRS, ROOT_FILES, public_path, scan_text, scan_worktree, local_secret_values


def build_release(output):
    findings = scan_worktree()
    if findings:
        raise ValueError("Release scan failed; run scripts/check_release.py for locations (values hidden)")
    paths = {ROOT / name for name in ROOT_FILES if (ROOT / name).is_file()}
    for directory in PUBLIC_DIRS:
        folder = ROOT / directory
        if folder.exists():
            paths.update(path for path in folder.rglob("*") if path.is_file() and public_path(path.relative_to(ROOT).as_posix()))
    payload = []
    known = local_secret_values()
    for path in sorted(paths):
        name = path.relative_to(ROOT).as_posix()
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError("Release files must not be symlinks")
        data = path.read_bytes()
        if scan_text(name, data.decode("utf-8-sig", errors="replace"), known):
            raise ValueError(f"Release scan failed for {name}; credential values hidden")
        payload.append((name, data))
    output = Path(output).resolve()
    allowed = (ROOT / "dist").resolve()
    if output.parent != allowed or output.suffix != ".zip":
        raise ValueError("Release ZIP must be placed directly under dist/")
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, data in payload:
            archive.writestr("RiskTagger_WWW2027/" + name, data)
    print(f"Audited source archive: {output} ({len(payload)} files; no Git history)")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "RiskTagger_WWW2027_source.zip")
    args = parser.parse_args()
    build_release(args.output)


if __name__ == "__main__":
    main()
