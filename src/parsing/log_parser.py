from __future__ import annotations

import re
from typing import List, Tuple

try:
    from drain3 import TemplateMiner
except Exception:  # pragma: no cover - fallback when drain3 is unavailable
    TemplateMiner = None  # type: ignore[assignment]


class LogParser:
    def __init__(self) -> None:
        self._miner = TemplateMiner() if TemplateMiner else None

    def parse(self, log_line: str) -> Tuple[str, List[str]]:
        if self._miner is not None:
            result = self._miner.add_log_message(log_line)
            template = result.get("template_mined") or log_line
            extracted = self._extract_parameters(log_line)
            return template, extracted

        template = self._to_template(log_line)
        return template, self._extract_parameters(log_line)

    @staticmethod
    def _to_template(log_line: str) -> str:
        template = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<*>", log_line)
        template = re.sub(r"\b\d+\b", "<*>", template)
        template = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<*>", template)
        return template

    @staticmethod
    def _extract_parameters(log_line: str) -> List[str]:
        return re.findall(r"\b(?:\d+\.\d+\.\d+\.\d+|\d+|[0-9a-fA-F]{8,})\b", log_line)
