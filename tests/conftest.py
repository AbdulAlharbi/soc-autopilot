from pathlib import Path

import pytest

from socpilot.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings()
    s.out_dir = tmp_path / "out"
    s.brain = "heuristic"
    return s
