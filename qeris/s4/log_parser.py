"""QERIS S4: Task T22a - Log Parser and Ingestion Engine.

Parses immutable JSON lines log streams into structured formats, supporting
both standard Python dictionaries/dataclasses and pandas DataFrames.
Provides filtering, grouping, and statistical aggregation routines.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Union

from qeris.s4.log_schema import LogRecord


class LogTable:
    """Lightweight in-memory table of LogRecords with querying capabilities."""

    def __init__(self, records: Optional[Sequence[LogRecord]] = None):
        self.records: List[LogRecord] = list(records or [])

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[LogRecord]:
        return iter(self.records)

    def __getitem__(self, idx: int) -> LogRecord:
        return self.records[idx]

    def append(self, record: LogRecord) -> None:
        self.records.append(record)

    def filter(self, predicate: Callable[[LogRecord], bool]) -> LogTable:
        """Return a new LogTable matching the predicate function."""
        return LogTable([r for r in self.records if predicate(r)])

    def where(self, **kwargs: Any) -> LogTable:
        """Filter records by exact field equality matches."""
        def match(r: LogRecord) -> bool:
            return all(getattr(r, k, None) == v for k, v in kwargs.items())
        return self.filter(match)

    def column(self, col_name: str) -> List[Any]:
        """Extract a column values list."""
        return [getattr(r, col_name) for r in self.records]

    def group_by(self, key_fn: Callable[[LogRecord], Any]) -> Dict[Any, LogTable]:
        """Group records into buckets by key function."""
        groups: Dict[Any, List[LogRecord]] = defaultdict(list)
        for r in self.records:
            groups[key_fn(r)].append(r)
        return {k: LogTable(v) for k, v in groups.items()}

    def to_dicts(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self.records]

    def to_pandas(self) -> Any:
        """Convert to pandas DataFrame if pandas is installed."""
        try:
            import pandas as pd
            return pd.DataFrame(self.to_dicts())
        except ImportError:
            raise RuntimeError("pandas is not installed; use to_dicts() or native LogTable methods.")


class LogParser:
    """Parser for reading and validating raw QERIS .jsonl log files."""

    @staticmethod
    def parse_file(file_path: Union[str, Path], skip_errors: bool = True) -> LogTable:
        """Parse a single JSON lines file into a LogTable."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        records: List[LogRecord] = []
        with open(path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(LogRecord.from_json(line))
                except Exception as err:
                    if not skip_errors:
                        raise ValueError(f"Error parsing line {line_no} in {path}: {err}") from err

        return LogTable(records)

    @staticmethod
    def parse_directory(dir_path: Union[str, Path], pattern: str = "*.jsonl", skip_errors: bool = True) -> LogTable:
        """Recursively scan a directory and parse all matching JSONL log files."""
        root = Path(dir_path)
        table = LogTable()
        if not root.exists():
            return table

        for log_file in sorted(root.rglob(pattern)):
            sub_table = LogParser.parse_file(log_file, skip_errors=skip_errors)
            table.records.extend(sub_table.records)

        return table
