"""
Command-line interface for FLOSS.

This module provides a CLI for fault localization tasks.
"""

import json
import logging
import os
import sys
from typing import Callable, List, Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from ..fl.config import FLConfig
from ..fl.engine import FLEngine
from ..test.config import TestConfig
from ..test.runner import TestResult, TestRunner

console = Console()


# --- Shared Click Options ---


def shared_options(f: Callable) -> Callable:
    """Decorator for shared options across commands."""
    f = click.option(
        "--config",
        "-c",
        default="floss.conf",
        help="Configuration file (default: floss.conf)",
    )(f)
    return f


def test_options(f: Callable) -> Callable:
    """Decorator for test-related options."""
    f = click.option(
        "--source-dir",
        "-s",
        default=".",
        help="Source code directory to analyze (default: .)",
    )(f)
    f = click.option(
        "--test-dir", "-t", help="Test directory (default: auto-detected by pytest)"
    )(f)
    f = click.option(
        "--test-filter", "-k", help="Filter tests using pytest -k pattern"
    )(f)
    f = click.option(
        "--ignore",
        multiple=True,
        help=(
            "Additional file patterns to ignore for test discovery "
            "(besides */__init__.py)"
        ),
    )(f)
    f = click.option(
        "--omit",
        multiple=True,
        help=("Additional file patterns to omit from coverage (besides */__init__.py)"),
    )(f)
    return f


def fl_options(f: Callable) -> Callable:
    """Decorator for fault localization options."""
    f = click.option(
        "--formulas",
        "-f",
        multiple=True,
        help="SBFL formulas to use (default: all available)",
    )(f)
    return f


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """
    FLOSS: Fault Localization with Spectrum-based Scoring

    A tool for automated fault localization using SBFL techniques.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    setup_logging(verbose)


@main.command()
@click.option(
    "--output",
    "-o",
    default="coverage.json",
    help="Output file for coverage data (default: coverage.json)",
)
@test_options
@shared_options
@click.pass_context
def test(
    ctx: click.Context,
    source_dir: str,
    test_dir: Optional[str],
    output: str,
    test_filter: Optional[str],
    ignore: List[str],
    omit: List[str],
    config: str,
) -> TestResult:
    """
    Run tests with coverage collection.

    Executes tests using pytest with coverage context collection and produces
    an enhanced coverage JSON file with test outcome information.
    """
    try:
        # Load configuration
        test_config = TestConfig.from_file(config)

        # Override with command line arguments
        if source_dir != ".":  # Only override if different from default
            test_config.source_dir = source_dir
        if test_dir:
            test_config.test_dir = test_dir
        if output != "coverage.json":
            test_config.output_file = output

        # Merge ignore patterns
        if ignore:
            test_config.ignore_patterns = (test_config.ignore_patterns or []) + list(
                ignore
            )

        # Merge omit patterns
        if omit:
            test_config.omit_patterns = (test_config.omit_patterns or []) + list(omit)

        console.print(
            "[bold green]Running tests with coverage collection...[/bold green]"
        )
        console.print(f"Source dir: [cyan]{test_config.source_dir}[/cyan]")
        if test_config.test_dir:
            console.print(f"Test dir: [cyan]{test_config.test_dir}[/cyan]")
        console.print(f"Output file: [cyan]{test_config.output_file}[/cyan]")

        # Execute tests with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[yellow]Executing tests and collecting coverage...", total=None
            )
            runner = TestRunner(test_config)
            result = runner.run_tests(test_filter)
            progress.update(task, completed=100, total=100)

        # Write coverage matrix code_lines-tests
        with open(test_config.output_file, "w") as f:
            json.dump(result.coverage_data, f, indent=2)

        # Display results
        total_tests = (
            len(result.passed_tests)
            + len(result.failed_tests)
            + len(result.skipped_tests)
        )
        console.print("\n[bold green]✓[/bold green] Test execution completed!")
        console.print(f"Total tests: {total_tests}")
        console.print(f"Passed: [green]{len(result.passed_tests)}[/green]")
        console.print(f"Failed: [red]{len(result.failed_tests)}[/red]")
        console.print(f"Skipped: [yellow]{len(result.skipped_tests)}[/yellow]")

        if result.failed_tests:
            console.print("\n[bold red]Failed tests:[/bold red]")
            for test in result.failed_tests:
                console.print(f"  - {test}")

        console.print(
            f"\n[bold green]Coverage data saved to:[/bold green] "
            f"{test_config.output_file}"
        )
        return result

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option(
    "--input",
    "-i",
    default="coverage.json",
    help="Input coverage file (default: coverage.json)",
)
@click.option(
    "--output",
    "-o",
    default="report.json",
    help="Output report file (default: report.json)",
)
@fl_options
@shared_options
@click.pass_context
def fl(
    ctx: click.Context, input: str, output: str, formulas: List[str], config: str
) -> None:
    """
    Calculate fault localization suspiciousness scores.

    Takes a coverage.json file as input and produces a report.json file
    with suspiciousness scores calculated using SBFL formulas.
    """
    try:
        # Load configuration
        fl_config = FLConfig.from_file(config)

        # Override with command line arguments
        if input != "coverage.json":
            fl_config.input_file = input
        if output != "report.json":
            fl_config.output_file = output
        if formulas:
            fl_config.formulas = list(formulas)

        console.print(
            "[bold green]Calculating fault localization scores...[/bold green]"
        )
        console.print(f"Input file: [cyan]{fl_config.input_file}[/cyan]")
        console.print(f"Output file: [cyan]{fl_config.output_file}[/cyan]")
        console.print(f"Formulas: [cyan]{', '.join(fl_config.formulas or [])}[/cyan]")

        # Create FL engine and calculate with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[yellow]Calculating suspiciousness scores...", total=None
            )
            engine = FLEngine(fl_config)
            engine.calculate_suspiciousness(fl_config.input_file, fl_config.output_file)
            progress.update(task, completed=100, total=100)

        console.print("\n[bold green]✓[/bold green] Fault localization completed!")
        console.print(f"Report saved to: [cyan]{fl_config.output_file}[/cyan]")

    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] No such file or directory: "
            f"{fl_config.input_file}"
        )
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(
            f"[bold red]Error:[/bold red] Malformed JSON in input file: "
            f"{fl_config.input_file} \n"
            f"Line {e.lineno}, Column {e.colno}: {e.msg}"
        )
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option(
    "--output",
    "-o",
    default="report.json",
    help="Output file for fault localization report (default: report.json)",
)
@test_options
@fl_options
@shared_options
@click.pass_context
def run(
    ctx: click.Context,
    source_dir: str,
    test_dir: Optional[str],
    output: str,
    test_filter: Optional[str],
    ignore: List[str],
    omit: List[str],
    formulas: List[str],
    config: str,
) -> None:
    """
    Run complete fault localization pipeline.

    Executes tests with coverage collection and calculates fault localization
    suspiciousness scores in a single command.
    """
    try:
        # Load configurations
        test_config = TestConfig.from_file(config)
        fl_config = FLConfig.from_file(config)

        # Override test config with command line arguments
        if source_dir != ".":
            test_config.source_dir = source_dir
        if test_dir:
            test_config.test_dir = test_dir
        if ignore:
            test_config.ignore_patterns = (test_config.ignore_patterns or []) + list(
                ignore
            )
        if omit:
            test_config.omit_patterns = (test_config.omit_patterns or []) + list(omit)

        # Use same file for both phases
        intermediate_file = (
            output.replace(".json", "_coverage.json")
            if output != "report.json"
            else "coverage.json"
        )
        test_config.output_file = intermediate_file

        # Override fl config with command line arguments
        fl_config.input_file = intermediate_file
        if output != "report.json":
            fl_config.output_file = output
        if formulas:
            fl_config.formulas = list(formulas)

        console.print(
            "[bold green]Running complete fault localization pipeline...[/bold green]"
        )
        console.print(f"Source dir: [cyan]{test_config.source_dir}[/cyan]")
        if test_config.test_dir:
            console.print(f"Test dir: [cyan]{test_config.test_dir}[/cyan]")
        console.print(f"Final output: [cyan]{fl_config.output_file}[/cyan]")
        console.print(f"Formulas: [cyan]{', '.join(fl_config.formulas or [])}[/cyan]")

        # Phase 1: Run tests with coverage
        console.print(
            "\n[bold blue]Phase 1: Running tests with coverage...[/bold blue]"
        )
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "[yellow]Executing tests and collecting coverage...", total=None
                )
                runner = TestRunner(test_config)
                result = runner.run_tests(test_filter)
                progress.update(task, completed=100, total=100)
        except Exception as e:
            console.print("\n[bold red]✗[/bold red] Test execution failed!")
            console.print(f"[bold red]Error:[/bold red] {e}")
            if ctx.obj.get("verbose"):
                console.print_exception()
            # Cleanup intermediate file
            if os.path.exists(intermediate_file):
                os.remove(intermediate_file)
            sys.exit(1)

        with open(test_config.output_file, "w") as f:
            json.dump(result.coverage_data, f, indent=2)

        total_tests = (
            len(result.passed_tests)
            + len(result.failed_tests)
            + len(result.skipped_tests)
        )
        console.print("\n[bold green]✓[/bold green] Test execution completed!")
        console.print(f"Total tests: {total_tests}")
        console.print(f"Passed: [green]{len(result.passed_tests)}[/green]")
        console.print(f"Failed: [red]{len(result.failed_tests)}[/red]")
        console.print(f"Skipped: [yellow]{len(result.skipped_tests)}[/yellow]")

        if result.failed_tests:
            console.print("\n[bold red]Failed tests:[/bold red]")
            for test in result.failed_tests:
                console.print(f"  - {test}")
        # Check if fault localization is needed
        if not result.failed_tests:
            console.print(
                "\n[bold yellow]ℹ[/bold yellow] All tests passed - "
                "fault localization not needed."
            )
            console.print("✓ Pipeline completed successfully!")

            # Cleanup intermediate file since we're not proceeding to FL
            if intermediate_file != fl_config.output_file and os.path.exists(
                intermediate_file
            ):
                os.remove(intermediate_file)
            return

        # Phase 2: Calculate fault localization
        console.print(
            "\n[bold blue]Phase 2: Calculating fault localization scores...[/bold blue]"
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[yellow]Calculating suspiciousness scores...", total=None
            )
            engine = FLEngine(fl_config)
            engine.calculate_suspiciousness(fl_config.input_file, fl_config.output_file)
            progress.update(task, completed=100, total=100)

        # Cleanup intermediate file if different from final output
        if intermediate_file != fl_config.output_file and os.path.exists(
            intermediate_file
        ):
            os.remove(intermediate_file)

        console.print(
            "\n[bold green]✓[/bold green] Fault localization pipeline completed!"
        )
        console.print(f"Report saved to: [cyan]{fl_config.output_file}[/cyan]")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)


@main.command()
@click.option(
    "--report",
    "-r",
    default="report.json",
    help="Report file to visualize (default: report.json)",
)
@click.option(
    "--port", "-p", default=8501, help="Port for the dashboard (default: 8501)"
)
@click.option("--no-open", is_flag=True, help="Do not auto-open browser")
@click.pass_context
def ui(ctx: click.Context, report: str, port: int, no_open: bool) -> None:
    """
    Launch FLOSS dashboard for result visualization.

    Opens an interactive web dashboard to visualize fault localization
    results with treemaps, source code highlighting, coverage matrices,
    and sunburst charts.
    """
    try:
        from floss.ui.dashboard import launch_dashboard

        console.print("[bold green]Starting FLOSS Dashboard...[/bold green]")
        console.print(f"Report file: [cyan]{report}[/cyan]")
        console.print(f"Port: [cyan]{port}[/cyan]")

        launch_dashboard(report_file=report, port=port, auto_open=not no_open)

    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] Dashboard dependencies not available."
        )
        console.print(
            escape("Install UI extras: pip install .[ui]  (or: pip install floss[ui])")
        )
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
