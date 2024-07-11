from pathlib import Path
from typing import Final

TYCHO_CLIENT_FOLDER = Path(__file__) / "bins"
TYCHO_CLIENT_LOG_FOLDER = TYCHO_CLIENT_FOLDER / "logs"

EXTERNAL_ACCOUNT: Final[str] = "0xf847a638E44186F3287ee9F8cAF73FF4d4B80784"
"""This is a dummy address used as a transaction sender"""
UINT256_MAX: Final[int] = 2 ** 256 - 1
MAX_BALANCE: Final[int] = UINT256_MAX // 2
"""0.5 of the maximal possible balance to avoid overflow errors"""
