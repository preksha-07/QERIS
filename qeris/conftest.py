"""conftest.py: Add s4 and s3 directories to sys.path for pytest discovery."""
import sys
import os

# s4 directory: flat imports (log_schema, fault_injection, etc.)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "s4"))
# s3 directory: flat imports (audit_logger, failure_taxonomy, etc.)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "s3"))
