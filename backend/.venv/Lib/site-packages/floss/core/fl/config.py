"""
Configuration for Fault Localization.
"""

import configparser
import os
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FLConfig:
    """Configuration for fault localization."""

    input_file: str = "coverage.json"
    output_file: str = "report.json"
    formulas: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.formulas is None:
            self.formulas = ["ochiai", "tarantula", "jaccard", "dstar2"]

    @classmethod
    def from_file(cls, config_file: str) -> "FLConfig":
        """Load configuration from file."""
        config = cls()

        if not os.path.exists(config_file):
            return config

        parser = configparser.ConfigParser()
        parser.read(config_file)

        if "fl" in parser:
            fl_section = parser["fl"]
            config.input_file = fl_section.get("input_file", config.input_file)
            config.output_file = fl_section.get("output_file", config.output_file)

            formulas_str = fl_section.get("formulas", "")
            if formulas_str:
                config.formulas = [f.strip() for f in formulas_str.split(",")]

        return config
