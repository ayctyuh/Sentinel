"""
Tests for the 'FLOSS ui' CLI command.

Covers help, successful launch with mocked dashboard, and ImportError path.
"""

import builtins
import sys
import types
from typing import Any, Optional

from click.testing import CliRunner

from floss.core.cli.main import main


class TestUICLI:
    def test_ui_command_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["ui", "--help"])
        assert result.exit_code == 0
        assert "Launch FLOSS dashboard" in result.output
        assert "--report" in result.output
        assert "--port" in result.output
        assert "--no-open" in result.output

    def test_ui_command_success_with_mock_dashboard(self, monkeypatch: Any) -> None:
        runner = CliRunner()

        # Create a fake module FLOSS.ui.dashboard with a mock launch_dashboard
        fake_module = types.SimpleNamespace()
        calls: dict[str, Any] = {}

        def fake_launch_dashboard(report_file: str, port: int, auto_open: bool) -> None:
            calls["report_file"] = report_file
            calls["port"] = port
            calls["auto_open"] = auto_open

        fake_module.launch_dashboard = fake_launch_dashboard

        # Inject the fake module so the
        # from ..ui.dashboard import launch_dashboard works
        monkeypatch.setitem(
            sys.modules,
            "floss.ui.dashboard",
            fake_module,
        )

        result = runner.invoke(
            main,
            [
                "ui",
                "--report",
                "my_report.json",
                "--port",
                "9000",
                "--no-open",
            ],
        )

        assert result.exit_code == 0
        # Verify our fake dashboard was called with the right args
        assert calls["report_file"] == "my_report.json"
        assert calls["port"] == 9000
        assert calls["auto_open"] is False

    def test_ui_command_import_error(self, monkeypatch: Any) -> None:
        runner = CliRunner()

        real_import = builtins.__import__

        def raising_import(
            name: str,
            globals: Optional[dict[str, Any]] = None,
            locals: Optional[dict[str, Any]] = None,
            fromlist: tuple = (),
            level: int = 0,
        ) -> Any:
            # Raise only for the dashboard import used by the ui command
            target = "floss.ui.dashboard"
            if name == target or (fromlist and target.endswith("." + name)):
                raise ImportError("Dashboard not installed")
            return real_import(name, globals, locals, fromlist, level)

        monkeypatch.setattr(builtins, "__import__", raising_import)

        result = runner.invoke(main, ["ui"])  # uses defaults

        assert result.exit_code == 1
        assert "Dashboard dependencies not available" in result.output
