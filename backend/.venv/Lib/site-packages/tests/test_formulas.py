"""
Test suite for FLOSS SBFL formulas.
"""

import math

import pytest

from floss.core.formulas import (
    DStarFormula,
    JaccardFormula,
    Kulczynski2Formula,
    OchiaiFormula,
    TarantulaFormula,
)


class TestSBFLFormulas:
    """Test cases for SBFL formula implementations."""

    def test_ochiai_formula(self) -> None:
        """Test Ochiai formula calculation."""
        formula = OchiaiFormula()

        # Test case: element covered by 2 failed tests, 1 passed test
        # n_cf=2, n_nf=1, n_cp=1, n_np=2
        score = formula.calculate(n_cf=2, n_nf=1, n_cp=1, n_np=2)

        expected = 2 / math.sqrt((2 + 1) * (2 + 1))  # 2 / sqrt(9) = 2/3
        assert abs(score - expected) < 1e-6

        # Test edge case: no failed tests covering
        score = formula.calculate(n_cf=0, n_nf=3, n_cp=2, n_np=1)
        assert score == 0.0

        # Test edge case: division by zero
        score = formula.calculate(n_cf=0, n_nf=0, n_cp=0, n_np=0)
        assert score == 0.0

    def test_tarantula_formula(self) -> None:
        """Test Tarantula formula calculation."""
        formula = TarantulaFormula()

        # Test standard case
        score = formula.calculate(n_cf=2, n_nf=1, n_cp=1, n_np=2)

        failed_ratio = 2 / (2 + 1)  # 2/3
        passed_ratio = 1 / (1 + 2)  # 1/3
        expected = failed_ratio / (
            failed_ratio + passed_ratio
        )  # (2/3) / (2/3 + 1/3) = (2/3) / 1 = 2/3

        assert abs(score - expected) < 1e-6

        # Test no failed tests
        score = formula.calculate(n_cf=0, n_nf=0, n_cp=2, n_np=1)
        assert score == 0.0

    def test_jaccard_formula(self) -> None:
        """Test Jaccard formula calculation."""
        formula = JaccardFormula()

        score = formula.calculate(n_cf=2, n_nf=1, n_cp=1, n_np=2)
        expected = 2 / (2 + 1 + 1)  # 2/4 = 0.5

        assert abs(score - expected) < 1e-6

        # Test edge case
        score = formula.calculate(n_cf=0, n_nf=1, n_cp=0, n_np=2)
        assert score == 0.0

    def test_dstar_formula(self) -> None:
        """Test D* formula calculation."""
        formula = DStarFormula(star=2)

        score = formula.calculate(n_cf=3, n_nf=1, n_cp=2, n_np=1)
        expected = (3**2) / (2 + 1)  # 9/3 = 3.0

        assert abs(score - expected) < 1e-6

        # Test with different star value
        formula3 = DStarFormula(star=3)
        score3 = formula3.calculate(n_cf=2, n_nf=1, n_cp=1, n_np=1)
        expected3 = (2**3) / (1 + 1)  # 8/2 = 4.0

        assert abs(score3 - expected3) < 1e-6

        # Test no coverage
        score = formula.calculate(n_cf=0, n_nf=2, n_cp=1, n_np=1)
        assert score == 0.0

    def test_kulczynski2_formula(self) -> None:
        """Test Kulczynski2 formula calculation."""
        formula = Kulczynski2Formula()

        score = formula.calculate(n_cf=2, n_nf=1, n_cp=1, n_np=2)
        term1 = 2 / (2 + 1)  # 2/3
        term2 = 2 / (2 + 1)  # 2/3
        expected = 0.5 * (term1 + term2)  # 0.5 * (2/3 + 2/3) = 2/3

        assert abs(score - expected) < 1e-6

        # Test no failed coverage
        score = formula.calculate(n_cf=0, n_nf=2, n_cp=1, n_np=1)
        assert score == 0.0

    def test_formula_names(self) -> None:
        """Test that formulas have correct names."""
        assert OchiaiFormula().name == "ochiai"
        assert TarantulaFormula().name == "tarantula"
        assert JaccardFormula().name == "jaccard"
        assert DStarFormula().name == "dstar2"
        assert DStarFormula(star=3).name == "dstar3"
        assert Kulczynski2Formula().name == "kulczynski2"

    def test_formula_string_representation(self) -> None:
        """Test string representation of formulas."""
        formula = OchiaiFormula()
        assert "OchiaiFormula" in str(formula)
        assert "ochiai" in str(formula)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
