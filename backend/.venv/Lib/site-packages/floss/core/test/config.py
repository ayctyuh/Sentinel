"""Configuration management for FLOSS tests."""

import configparser
import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class TestConfig:
    """Configuration for test execution."""

    __test__ = False
    source_dir: str = "."
    test_dir: Optional[str] = None
    output_file: str = "coverage.json"
    ignore_patterns: Optional[List[str]] = None
    omit_patterns: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.ignore_patterns is None:
            self.ignore_patterns = ["*/__init__.py"]
        if self.omit_patterns is None:
            self.omit_patterns = ["*/__init__.py"]

    @classmethod
    def from_file(cls, config_file: str = "floss.conf") -> "TestConfig":
        """Load configuration from floss.conf file."""
        config = cls()

        if not os.path.exists(config_file):
            return config

        parser = configparser.ConfigParser()
        parser.read(config_file)

        if "test" in parser:
            test_section = parser["test"]

            if "source_dir" in test_section:
                config.source_dir = test_section["source_dir"]

            if "test_dir" in test_section:
                config.test_dir = test_section["test_dir"]

            if "output_file" in test_section:
                config.output_file = test_section["output_file"]

            if "ignore" in test_section:
                patterns = test_section["ignore"].split(",")
                config.ignore_patterns = [p.strip() for p in patterns if p.strip()]

            if "omit" in test_section:
                patterns = test_section["omit"].split(",")
                config.omit_patterns = [p.strip() for p in patterns if p.strip()]

        return config

    def get_coveragerc_content(self) -> str:
        """Generate .coveragerc content with required settings."""
        omit_list = ", ".join(self.omit_patterns or ["*/__init__.py"])

        return f"""[run]
omit = {omit_list}

[json]
show_contexts = True
"""

    def write_coveragerc(self, path: str = ".coveragerc") -> None:
        """Write .coveragerc file with configuration."""
        content = self.get_coveragerc_content()
        with open(path, "w") as f:
            f.write(content)
