#!/usr/bin/env python
"""Setup script for privaseeai-security package."""
from setuptools import setup

# Read requirements
with open("requirements.txt") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

# Configuration is in pyproject.toml
setup(
    install_requires=requirements,
)
