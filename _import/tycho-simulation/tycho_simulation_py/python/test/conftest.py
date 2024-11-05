from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def asset_dir():
    return Path(__file__).parent / "assets"
