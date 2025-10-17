"""Test execution module for FLOSS."""

from .config import TestConfig
from .runner import TestRunner

__all__ = ["TestRunner", "TestConfig"]
