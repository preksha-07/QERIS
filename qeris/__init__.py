"""QERIS top-level package."""
import os
import sys

# Extend package search path to include S1 implementation subpackage
_s1_pkg = os.path.join(os.path.dirname(__file__), "s1", "qeris")
if os.path.exists(_s1_pkg) and _s1_pkg not in __path__:
    __path__.append(_s1_pkg)

# Alias qeris.classical to top-level qeris_classical if available
try:
    import qeris_classical
    sys.modules["qeris.classical"] = qeris_classical
except ImportError:
    pass
