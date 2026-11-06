from __future__ import annotations

import json
from pathlib import Path

from tvbox_scanner.models import ScanResult


def write_json(result: ScanResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
