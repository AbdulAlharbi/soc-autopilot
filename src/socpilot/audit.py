"""Append-only, hash-chained audit log.

Every tool call, decision, approval and state transition is recorded as a JSON
line whose hash includes the previous line's hash. Anyone can verify the chain
later; a tampered or deleted entry breaks it. This is what lets a human trust
what the agents say they did.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._read_last_hash()

    # ------------------------------------------------------------------ #
    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["hash"]
        return last

    @staticmethod
    def _digest(prev: str, body: dict[str, Any]) -> str:
        payload = prev + json.dumps(body, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------ #
    def record(self, incident_id: str, actor: str, event: str, **payload: Any) -> dict[str, Any]:
        body = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "incident": incident_id,
            "actor": actor,
            "event": event,
            "payload": payload,
            "prev": self._last_hash,
        }
        body["hash"] = self._digest(self._last_hash, {k: v for k, v in body.items() if k != "hash"})
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, default=str) + "\n")
        self._last_hash = body["hash"]
        return body

    def entries(self, incident_id: str | None = None) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if incident_id is None or entry["incident"] == incident_id:
                    yield entry

    def verify(self) -> tuple[bool, int]:
        """Return (chain_is_valid, number_of_entries)."""
        prev = GENESIS
        count = 0
        for entry in self.entries():
            expected = self._digest(prev, {k: v for k, v in entry.items() if k != "hash"})
            if entry["hash"] != expected or entry["prev"] != prev:
                return False, count
            prev = entry["hash"]
            count += 1
        return True, count
