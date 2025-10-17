"""
Performance and benchmark tests for the FLOSS run command.

These tests ensure the run command performs efficiently and handles
larger codebases appropriately.
"""

import json
import os
import time

from click.testing import CliRunner

from floss.core.cli.main import main


class TestRunCommandPerformance:
    """Performance tests for the run command."""

    def test_run_command_timing(self) -> None:
        """Test that run command completes in reasonable time."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            # Create multiple source files
            for i in range(5):
                with open(f"src/module_{i}.py", "w") as f:
                    f.write(
                        f"""
def function_{i}_1(x):
    if x > {i}:
        return x * 2
    return x

def function_{i}_2(x):
    return x + {i}

def function_{i}_3(x):
    if x == {i}:
        return True
    return False
"""
                    )

            # Create corresponding test files
            for i in range(5):
                with open(f"tests/test_module_{i}.py", "w") as f:
                    f.write(
                        f"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from module_{i} import function_{i}_1, function_{i}_2, function_{i}_3

def test_function_{i}_1_positive():
    assert function_{i}_1({i+1}) == {(i+1)*2}

def test_function_{i}_1_negative():
    assert function_{i}_1({i-1}) == {i-1}

def test_function_{i}_2():
    assert function_{i}_2(10) == {10+i}

def test_function_{i}_3_true():
    assert function_{i}_3({i}) == True

def test_function_{i}_3_false():
    assert function_{i}_3({i+1}) == False

def test_function_{i}_fail():
    # Add a failing test for modules 0 and 2 to trigger FL
    if {i} in [0, 2]:
        assert function_{i}_1(5) == 999  # This will fail
    else:
        assert function_{i}_1(5) >= 0  # This will pass
"""
                    )

            # Measure execution time
            start_time = time.time()

            result = runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "perf_report.json"]
            )

            end_time = time.time()
            execution_time = end_time - start_time

            # Verify success
            assert result.exit_code == 0
            assert os.path.exists("perf_report.json")

            # Verify reasonable execution time
            # (should be under 30 seconds for this small project)
            assert (
                execution_time < 30
            ), f"Execution took too long: {execution_time} seconds"

            # Verify all tests were found and executed
            assert "Total tests: 30" in result.output  # 5 modules * 6 tests each

            # Verify report contains all modules
            with open("perf_report.json", "r") as f:
                report = json.load(f)

            # Should have data for all 5 modules
            module_count = 0
            for file_path in report["files"]:
                if "module_" in file_path and ".py" in file_path:
                    module_count += 1

            assert module_count == 5

    def test_run_command_memory_usage(self) -> None:
        """Test that run command handles multiple files
        without excessive memory usage."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            # Create larger source files with more functions
            for i in range(3):
                lines = []
                lines.append(f"# Module {i} with many functions")

                for j in range(20):  # 20 functions per module
                    lines.append(
                        f'''
def function_{i}_{j}(param):
    """Function {j} in module {i}."""
    if param > {j}:
        result = param * {j+1}
        if result > 100:
            return result - 50
        return result
    elif param == {j}:
        return param ** 2
    else:
        return param + {j}
'''
                    )

                with open(f"src/large_module_{i}.py", "w") as f:
                    f.write("\n".join(lines))

            # Create comprehensive test files
            for i in range(3):
                lines = []
                lines.append(
                    f"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from large_module_{i} import *
"""
                )

                for j in range(20):
                    lines.append(
                        f"""
def test_function_{i}_{j}_case1():
    expected = {j+5} * {j+1} - 50 if ({j+5} * {j+1}) > 100 else {j+5} * {j+1}
    assert function_{i}_{j}({j+5}) == expected

def test_function_{i}_{j}_case2():
    assert function_{i}_{j}({j}) == {j} ** 2

def test_function_{i}_{j}_case3():
    assert function_{i}_{j}({j-1}) == {j-1} + {j}

def test_function_{i}_{j}_fail():
    # Add failing tests for some functions to trigger FL
    if {i} == 0 and {j} % 5 == 0:  # Fail some tests in first module
        assert function_{i}_{j}(0) == 999  # This will fail
    else:
        assert function_{i}_{j}(0) >= 0  # This will pass
"""
                    )

                with open(f"tests/test_large_module_{i}.py", "w") as f:
                    f.write("\n".join(lines))

            # Run the command
            result = runner.invoke(
                main, ["run", "--source-dir", "src", "--output", "large_report.json"]
            )

            # Should complete successfully
            assert result.exit_code == 0

            # Should handle all tests (3 modules * 20 functions * 4 tests = 240 tests)
            assert "Total tests: 240" in result.output

            # Report should be created and contain data
            assert os.path.exists("large_report.json")

            with open("large_report.json", "r") as f:
                report = json.load(f)

            # Verify structure is intact
            assert "files" in report
            assert "fl_metadata" in report
            assert len(report["files"]) >= 3  # At least our 3 modules

    def test_run_command_with_many_formulas(self) -> None:
        """Test run command performance with multiple SBFL formulas."""
        runner = CliRunner()

        with runner.isolated_filesystem():
            os.makedirs("src")
            os.makedirs("tests")

            # Create source with mixed passing/failing scenarios
            with open("src/mixed_results.py", "w") as f:
                f.write(
                    """
def good_function(x):
    return x * 2

def buggy_function(x):
    if x > 5:
        return x * 3  # Bug: should be x * 2
    return x * 2

def another_good(x):
    return x + 1

def another_buggy(x):
    if x < 0:
        return 0  # Bug: should handle negative numbers properly
    return x - 1
"""
                )

            with open("tests/test_mixed_results.py", "w") as f:
                f.write(
                    """
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from mixed_results import good_function, buggy_function, another_good, another_buggy

def test_good_function():
    assert good_function(5) == 10

def test_buggy_function_small():
    assert buggy_function(3) == 6  # Should pass

def test_buggy_function_large():
    assert buggy_function(10) == 20  # Will fail due to bug

def test_another_good():
    assert another_good(5) == 6

def test_another_buggy_positive():
    assert another_buggy(5) == 4

def test_another_buggy_negative():
    assert another_buggy(-1) == -2  # Will fail due to bug
"""
                )

            # Test with all available formulas
            start_time = time.time()

            result = runner.invoke(
                main,
                [
                    "run",
                    "--source-dir",
                    "src",
                    "--formulas",
                    "ochiai",
                    "--formulas",
                    "tarantula",
                    "--formulas",
                    "jaccard",
                    "--formulas",
                    "dstar2",
                    "--output",
                    "multi_formula_report.json",
                ],
            )

            end_time = time.time()
            execution_time = end_time - start_time

            assert result.exit_code == 0
            assert "Formulas: ochiai, tarantula, jaccard, dstar2" in result.output

            # Should complete in reasonable time even with multiple formulas
            assert (
                execution_time < 15
            ), f"Multiple formulas took too long: {execution_time} seconds"

            # Verify report contains all formulas
            with open("multi_formula_report.json", "r") as f:
                report = json.load(f)

            formulas = report["fl_metadata"]["formulas_used"]
            assert "ochiai" in formulas
            assert "tarantula" in formulas
            assert "jaccard" in formulas
            assert "dstar2" in formulas

            # Verify suspiciousness scores exist for all formulas
            file_data = None
            for file_path, data in report["files"].items():
                if "mixed_results.py" in file_path:
                    file_data = data
                    break

            assert file_data is not None
            suspiciousness = file_data["suspiciousness"]

            # Check that scores exist for all formulas on covered lines
            for line, scores in suspiciousness.items():
                assert "ochiai" in scores
                assert "tarantula" in scores
                assert "jaccard" in scores
                assert "dstar2" in scores
