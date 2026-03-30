"""
Add python_client to sys.path so all test modules can import project code directly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "python_client"))
