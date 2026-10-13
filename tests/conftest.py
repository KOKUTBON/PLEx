import sys
from pathlib import Path

# Ensure repository src takes precedence over any site-packages editable install
SRC_PATH = str(Path(__file__).resolve().parent.parent / "src")
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)
elif sys.path[0] != SRC_PATH:
    sys.path.remove(SRC_PATH)
    sys.path.insert(0, SRC_PATH)
