from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class TargetType(str, Enum):
    PACKAGE = "package"
    FILE = "file"
    PROCESS = "process"
    NETWORK = "network"
    DEVICE = "device"


class Verdict(str, Enum):
    NO_IOC_MATCH = "no_ioc_match"            # not proof of clean: only known IOCs were checked
    SUSPICIOUS = "suspicious"
    INFECTED_REMOVABLE = "infected_removable"  # everything found lives in /data
    INFECTED_FIRMWARE = "infected_firmware"    # something lives in /system or /vendor


@dataclass
class Finding:
    scanner: str
    severity: Severity
    title: str
    target_type: TargetType
    target: str
    family: str | None = None
    detail: str = ""
    evidence: dict = field(default_factory=dict)

    @property
    def in_firmware(self) -> bool:
        path = self.evidence.get("path", self.target if self.target_type == TargetType.FILE else "")
        return path.startswith(("/system", "/vendor", "/product", "/odm"))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["target_type"] = self.target_type.value
        return d


@dataclass
class ScanResult:
    device: dict
    findings: list[Finding]
    root: bool
    ioc_families: list[str]
    errors: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> Verdict:
        real = [f for f in self.findings if f.severity >= Severity.HIGH]
        if real:
            if any(f.in_firmware for f in real):
                return Verdict.INFECTED_FIRMWARE
            return Verdict.INFECTED_REMOVABLE
        if any(f.severity >= Severity.MEDIUM for f in self.findings):
            return Verdict.SUSPICIOUS
        return Verdict.NO_IOC_MATCH

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "device": self.device,
            "root": self.root,
            "ioc_families": self.ioc_families,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: -f.severity)],
            "errors": self.errors,
        }
