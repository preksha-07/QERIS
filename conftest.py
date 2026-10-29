"""Top-level conftest.py: add workspace root to sys.path so qeris.s4.* resolves."""
import sys
import os

# Parent of qeris/ package directory
sys.path.insert(0, os.path.dirname(__file__))
