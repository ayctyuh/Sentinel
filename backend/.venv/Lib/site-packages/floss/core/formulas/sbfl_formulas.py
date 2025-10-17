"""
Implementation of popular SBFL formulas.

This module provides implementations of the most commonly used and effective
SBFL formulas, including those supported by GZoltar.
"""

from typing import Optional

from .base import SBFLFormula, safe_divide, safe_sqrt


class OchiaiFormula(SBFLFormula):
    """
    Ochiai similarity coefficient formula.

    One of the most effective SBFL formulas in practice.

    Formula: n_cf / sqrt((n_cf + n_nf) * (n_cf + n_cp))

    Reference: Ochiai, A. (1957). Zoogeographic studies on the soleoid
    fishes found in Japan and its neighboring regions.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        if n_cf == 0:
            return 0.0

        denominator = safe_sqrt((n_cf + n_nf) * (n_cf + n_cp))
        return safe_divide(n_cf, denominator)


class TarantulaFormula(SBFLFormula):
    """
    Tarantula formula for fault localization.

    One of the first and most well-known SBFL formulas.

    Formula: (n_cf / (n_cf + n_nf)) / ((n_cf / (n_cf + n_nf)) + (n_cp / (n_cp + n_np)))

    Reference: Jones, J.A., Harrold, M.J.: Empirical evaluation of the
    tarantula automatic fault-localization technique. ASE 2005.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        failed_total = n_cf + n_nf
        passed_total = n_cp + n_np

        if failed_total == 0:
            return 0.0

        failed_ratio = safe_divide(n_cf, failed_total)
        passed_ratio = safe_divide(n_cp, passed_total)

        return safe_divide(failed_ratio, failed_ratio + passed_ratio)


class JaccardFormula(SBFLFormula):
    """
    Jaccard similarity coefficient formula.

    Measures similarity between sets, adapted for fault localization.

    Formula: n_cf / (n_cf + n_nf + n_cp)

    Reference: Jaccard, P. (1912). The distribution of the flora in the alpine zone.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        denominator = n_cf + n_nf + n_cp
        return safe_divide(n_cf, denominator)


class DStarFormula(SBFLFormula):
    """
    D* formula for fault localization.

    An optimized binary formula that performs well in practice.

    Formula: n_cf^star / (n_cp + n_nf)
    where star is typically 2 or 3

    Reference: Wong, W.E., Debroy, V., Gao, R., Li, Y.: The DStar method
    for effective software fault localization. TSE 2014.
    """

    def __init__(self, star: int = 2, name: Optional[str] = None):
        """
        Initialize D* formula.

        Args:
            star: Exponent value (typically 2 or 3)
            name: Optional custom name
        """
        self.star = star
        super().__init__(name or f"dstar{star}")

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        if n_cf == 0:
            return 0.0

        numerator = n_cf**self.star
        denominator = n_cp + n_nf

        return safe_divide(numerator, denominator)


class Kulczynski2Formula(SBFLFormula):
    """
    Kulczynski2 formula for fault localization.

    Formula: 0.5 * (n_cf / (n_cf + n_nf) + n_cf / (n_cf + n_cp))

    Reference: Kulczynski, S. (1927). Die Pflanzenassoziationen der Pieninen.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        if n_cf == 0:
            return 0.0

        term1 = safe_divide(n_cf, n_cf + n_nf)
        term2 = safe_divide(n_cf, n_cf + n_cp)

        return 0.5 * (term1 + term2)


class Naish1Formula(SBFLFormula):
    """
    Naish1 formula for fault localization.

    Formula: -1 if n_cf > 0 and n_cp > 0, else n_nf

    Reference: Naish, L., Lee, H.J., Ramamohanarao, K.: A model for
    spectra-based software diagnosis. TOSEM 2011.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        if n_cf > 0 and n_cp > 0:
            return -1.0
        return float(n_nf)


class RussellRaoFormula(SBFLFormula):
    """
    Russell-Rao similarity coefficient formula.

    Formula: n_cf / (n_cf + n_nf + n_cp + n_np)

    Reference: Russell, P.F., Rao, T.R. (1940). On habitat and association
    of species of anopheline larvae in south-eastern Madras.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        total = n_cf + n_nf + n_cp + n_np
        return safe_divide(n_cf, total)


class SorensenDiceFormula(SBFLFormula):
    """
    Sorensen-Dice similarity coefficient formula.

    Formula: 2 * n_cf / (2 * n_cf + n_nf + n_cp)

    Reference: Sørensen, T. (1948). A method of establishing groups of
    equal amplitude in plant sociology.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        denominator = 2 * n_cf + n_nf + n_cp
        return safe_divide(2 * n_cf, denominator)


class SBIFormula(SBFLFormula):
    """
    Similarity-Based Index (SBI) formula.

    Formula: 1 - (n_cp / (n_cf + n_cp))

    Reference: Yu, Y., Jones, J.A., Harrold, M.J.: An empirical study of
    the effects of test-suite reduction on fault localization. ICSE 2008.
    """

    def calculate(self, n_cf: int, n_nf: int, n_cp: int, n_np: int) -> float:
        if n_cf == 0 and n_cp == 0:
            return 0.0

        ratio = safe_divide(n_cp, n_cf + n_cp)
        return 1.0 - ratio
