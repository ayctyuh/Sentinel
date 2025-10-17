"""
Unit tests for safety helper functions in formulas.base.
"""

from floss.core.formulas.base import safe_divide, safe_sqrt


def test_safe_divide_basic_and_zero_division() -> None:
    assert safe_divide(10, 2) == 5
    assert safe_divide(1, 0) == 0.0  # default when denom is zero
    assert safe_divide(1, 0, default=42.0) == 42.0


def test_safe_sqrt_negative_and_positive() -> None:
    assert safe_sqrt(9) == 3
    assert safe_sqrt(0) == 0
    assert safe_sqrt(-1) == 0.0  # guarded
