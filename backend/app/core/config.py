from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "MalScan Backend"
    storage_dir: Path = Path(__file__).resolve().parents[2] / "storage"
    results_dir: Path = storage_dir / "results"
    database_url: str = f"sqlite:///{(storage_dir / 'malscan.db').as_posix()}"

    class Config:
        env_prefix = "MALSCAN_"
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    settings = Settings()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    return settings


settings = get_settings()
