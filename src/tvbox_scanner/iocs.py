"""Load IOC definitions from data/iocs/*.json.

Each file describes one malware family. See data/iocs/README.md for the schema.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Shipped inside the package so `pip install git+https://...` (non-editable) still finds them.
DEFAULT_IOC_DIR = Path(__file__).resolve().parent / "data" / "iocs"

HASH_LENGTHS = {"sha1": 40, "sha256": 64}
FILE_KINDS = {"any", "file", "dir"}


@dataclass
class FileIoc:
    path: str
    severity: str = "HIGH"
    note: str = ""
    # "dir" / "file" / "any". Lets a vaccinated box (payload dir replaced by a locked empty
    # file, as the T95 cleanup does) stop matching.
    kind: str = "any"
    # If set, the file only counts as malicious when its content contains one of these
    # strings (for legit files that malware modifies, like install-recovery.sh).
    content_markers: list[str] = field(default_factory=list)


@dataclass
class PackageIoc:
    name: str
    severity: str = "HIGH"
    note: str = ""


@dataclass
class IocSet:
    family: str
    sources: list[str] = field(default_factory=list)
    packages: list[PackageIoc] = field(default_factory=list)
    files: list[FileIoc] = field(default_factory=list)
    # {"sha1": {...}, "sha256": {...}}, lowercase hex
    hashes: dict[str, set[str]] = field(default_factory=lambda: {k: set() for k in HASH_LENGTHS})
    process_names: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    device_models: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> set[str]:
        return self.hashes["sha256"]

    @classmethod
    def from_dict(cls, data: dict) -> IocSet:
        family = data["family"]
        hashes = {}
        for algo, length in HASH_LENGTHS.items():
            values = {h.strip().lower() for h in data.get(algo, [])}
            bad = [h for h in values if len(h) != length or any(c not in "0123456789abcdef" for c in h)]
            if bad:
                raise ValueError(f"{family}: invalid {algo} values: {bad[:3]}")
            hashes[algo] = values
        files = [FileIoc(**f) for f in data.get("files", [])]
        for f in files:
            if f.kind not in FILE_KINDS:
                raise ValueError(f"{family}: file {f.path} has unknown kind {f.kind!r}")
        return cls(
            family=family,
            sources=data.get("sources", []),
            packages=[PackageIoc(name=p) if isinstance(p, str) else PackageIoc(**p)
                      for p in data.get("packages", [])],
            files=files,
            hashes=hashes,
            process_names=data.get("process_names", []),
            domains=[d.strip().lower() for d in data.get("domains", [])],
            ips=[ip.strip() for ip in data.get("ips", [])],
            device_models=data.get("device_models", []),
        )


def load_iocs(directory: Path = DEFAULT_IOC_DIR) -> list[IocSet]:
    sets = []
    for path in sorted(directory.glob("*.json")):
        with path.open(encoding="utf-8") as fh:
            sets.append(IocSet.from_dict(json.load(fh)))
    if not sets:
        raise FileNotFoundError(f"No IOC files found in {directory}")
    return sets
