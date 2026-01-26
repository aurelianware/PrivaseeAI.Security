#!/usr/bin/env python3
"""Health check script for Docker healthcheck.

Note: This script is designed specifically for the Docker environment
and uses /app as the base path, matching the WORKDIR in the Dockerfile.
"""

import sys

# Add the app directory to Python path to find the module
# This path is specific to the Docker container environment
sys.path.insert(0, '/app')

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
