"""Runtime settings, resolved from environment variables with sane defaults."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass
class Settings:
    root: Path = ROOT
    data_dir: Path = field(default_factory=lambda: ROOT / "data")
    out_dir: Path = field(default_factory=lambda: Path(_env("SOCPILOT_OUT_DIR", str(ROOT / "out"))))
    policy_path: Path = field(default_factory=lambda: Path(_env("SOCPILOT_POLICY", str(ROOT / "config" / "policy.yaml"))))
    brain: str = field(default_factory=lambda: _env("SOCPILOT_BRAIN", "auto"))  # auto | claude | heuristic
    model: str = field(default_factory=lambda: _env("SOCPILOT_MODEL", "claude-sonnet-4-5"))
    business_tz_offset_hours: int = field(default_factory=lambda: int(_env("SOCPILOT_TZ_OFFSET", "3")))  # Riyadh
    business_hours: tuple[int, int] = (7, 19)
    ir_lead: str = field(default_factory=lambda: _env("SOCPILOT_IR_LEAD", "ir-lead@corp.example"))
    soc_channel: str = "#soc-incidents"
    approvals_channel: str = "#soc-approvals"

    @property
    def fixtures_dir(self) -> Path:
        return self.data_dir / "fixtures"

    @property
    def scenarios_dir(self) -> Path:
        return self.data_dir / "scenarios"

    @property
    def playbooks_dir(self) -> Path:
        return self.data_dir / "playbooks"

    @property
    def incidents_dir(self) -> Path:
        return self.out_dir / "incidents"

    @property
    def reports_dir(self) -> Path:
        return self.out_dir / "reports"

    @property
    def world_path(self) -> Path:
        return self.out_dir / "world.json"

    @property
    def audit_path(self) -> Path:
        return self.out_dir / "audit.jsonl"

    def resolve_brain(self) -> str:
        if self.brain == "auto":
            return "claude" if os.environ.get("ANTHROPIC_API_KEY") else "heuristic"
        return self.brain
