#!/usr/bin/env python3
"""Health check script for Docker healthcheck."""

import sys

# Import the health_check function from the main module
try:
    from privaseeai_security.__main__ import health_check
    
    if health_check():
        print("OK")
        sys.exit(0)
    else:
        print("FAIL")
        sys.exit(1)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
