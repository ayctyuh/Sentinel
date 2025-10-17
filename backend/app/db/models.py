from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.sqlite import JSON

from app.db.session import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, index=True, nullable=False)
    filename = Column(String, nullable=False)
    original_name = Column(String, nullable=False)
    sha256 = Column(String, nullable=False, index=True)
    sha1 = Column(String, nullable=False)
    md5 = Column(String, nullable=False)
    file_type = Column(String, nullable=False)
    architecture = Column(String, nullable=True)
    verdict = Column(String, nullable=False)
    score = Column(Float, nullable=False)
    options = Column(JSON, nullable=False, default=dict)
    yara_matches = Column(JSON, nullable=False, default=list)
    result_path = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    def to_summary(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "filename": self.original_name,
            "sha256": self.sha256,
            "verdict": self.verdict,
            "score": self.score,
            "created_at": self.created_at.isoformat(),
            "download_url": f"/jobs/{self.job_id}/download",
        }

    def to_result(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        base = {
            "job_id": self.job_id,
            "filename": self.original_name,
            "hashes": {
                "md5": self.md5,
                "sha1": self.sha1,
                "sha256": self.sha256,
            },
            "file_type": self.file_type,
            "architecture": self.architecture,
            "verdict": self.verdict,
            "score": self.score,
            "options": self.options or {},
            "yara_matches": self.yara_matches or [],
            "created_at": self.created_at.isoformat(),
        }
        base.update(payload)
        return base
