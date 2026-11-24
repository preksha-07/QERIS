"""Top-level conftest.py: add workspace root and submodules to sys.path."""
import sys
import os

root = os.path.dirname(os.path.abspath(__file__))
if root not in sys.path:
    sys.path.insert(0, root)

import qeris
s1_pkg = os.path.join(root, "qeris", "s1", "qeris")
if os.path.isdir(s1_pkg) and s1_pkg not in getattr(qeris, "__path__", []):
    qeris.__path__.append(s1_pkg)

s3_dir = os.path.join(root, "qeris", "s3")
if s3_dir not in sys.path:
    sys.path.insert(0, s3_dir)

s2_dir = os.path.join(root, "qeris", "s2")
if s2_dir not in sys.path:
    sys.path.insert(0, s2_dir)
