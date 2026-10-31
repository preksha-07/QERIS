"""QERIS top-level package."""
import os
import sys

# Extend package search path to include S1 implementation subpackage
_s1_pkg = os.path.join(os.path.dirname(__file__), "s1", "qeris")
if os.path.exists(_s1_pkg) and _s1_pkg not in __path__:
    __path__.append(_s1_pkg)
