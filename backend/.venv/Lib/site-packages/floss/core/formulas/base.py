"""
Abstract base class for SBFL formulas.

This module defines the interface that all SBFL formula implementations must follow.
"""

import math
from abc import ABC, abstractmethod
from typing import Optional


class SBFLFormula(ABC):
    """
    Abstract base class for Spectrum-Based Fault Localization formulas.

    All SBFL formulas take the same four parameters:
    - n_cf: number of failed tests that cover the element
    - n_nf: number of failed tests that do NOT cover the element
    - n_cp: number of passed tests that cover the element
    - n_np: number of passed tests that do NOT cover the element
    """

    def __init__(self, name: Optional[str] = None):
        """Initialize the formula with an optional custom name."""
        self._name = name or self.__class__.__name__.replace("Formula", "").lower()

    @property
    def name(self) -> str:
        """Get the formula name."""
        return self._name

    @abstractmethod
    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        """
        Calculate the suspiciousness score for a code element.

        Args:
            n_cf: Number of failed tests covering the element
            n_nf: Number of failed tests NOT covering the element
            n_cp: Number of passed tests covering the element
            n_np: Number of passed tests NOT covering the element

        Returns:
            Suspiciousness score (typically between 0 and 1)
        """
        pass

    def __str__(self) -> str:
        """String representation of the formula."""
        return f"{self.__class__.__name__}(name='{self.name}')"

    def __repr__(self) -> str:
        """Detailed string representation."""
        return self.__str__()


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning default value if denominator is zero.

    Args:
        numerator: The numerator
        denominator: The denominator
        default: Value to return if denominator is zero

    Returns:
        Result of division or default value
    """
    if denominator == 0:
        return default
    return numerator / denominator


def safe_sqrt(value: float) -> float:
    """
    Safely compute square root, handling negative values.

    Args:
        value: Value to compute square root of

    Returns:
        Square root of value, or 0 if value is negative
    """
    if value < 0:
        return 0.0
    return math.sqrt(value)
