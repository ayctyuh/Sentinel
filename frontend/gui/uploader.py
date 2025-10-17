"""
Utility helpers for talking to the backend upload/scan API.

The real implementation should perform HTTP requests against the FastAPI
endpoints. For now we keep the interface minimal so the GUI can interact
with a placeholder implementation without raising errors.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ScanJob:
    """Lightweight representation of a queued scan job."""

    job_id: str
    target: str
    mode: str
    options: Dict[str, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    status: str = "queued"
    result: str = ""


class Uploader:
    """
    Placeholder upload client.

    Replace these methods with real HTTP calls once the backend is ready.
    """

    _id_counter = itertools.count(1)

    def __init__(self) -> None:
        self._jobs: List[ScanJob] = []

    def upload_file(self, file_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(file_path, "file", options or {})
        job.status = "completed"
        job.result = self._format_result(job, verdict="Không phát hiện mối đe dọa đáng kể.")
        return job

    def scan_by_hash(self, hash_value: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(hash_value, "hash", options or {})
        job.status = "completed"
        job.result = self._format_result(job, verdict="Không trùng khớp với các mẫu độc hại đã biết.")
        return job

    def schedule_system_scan(self, root_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(root_path, "system", options or {})
        job.status = "running"
        job.result = ""
        return job

    def schedule_directory_scan(self, root_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(root_path, "folder", options or {})
        job.status = "completed"
        job.result = self._format_result(job, verdict="Hoàn tất quét thư mục, không phát hiện nguy cơ.")
        return job

    def finalize_job(self, job: ScanJob, verdict: str) -> ScanJob:
        job.status = "completed"
        job.result = self._format_result(job, verdict=verdict)
        return job

    def list_jobs(self) -> List[ScanJob]:
        return list(self._jobs)

    def _create_job(self, target: str, mode: str, options: Dict[str, str]) -> ScanJob:
        job_id = f"job-{next(self._id_counter):05d}"
        job = ScanJob(job_id=job_id, target=target, mode=mode, options=options)
        self._jobs.append(job)
        return job

    def _format_result(self, job: ScanJob, verdict: Optional[str] = None) -> str:
        timestamp = time.strftime("%H:%M:%S", time.localtime(job.created_at))
        lines = [
            f"[{timestamp}] Báo cáo cho {job.job_id}",
            f"- Chế độ: {job.mode}",
            f"- Mục tiêu: {job.target}",
        ]
        if job.options:
            lines.append(f"- Tùy chọn: {self._stringify_options(job.options)}")
        if verdict:
            lines.append(f"- Kết luận: {verdict}")
        else:
            lines.append("- Kết luận: Đang xử lý…")
        return "\n".join(lines)

    @staticmethod
    def _stringify_options(options: Dict[str, str]) -> str:
        return ", ".join(f"{key}={value}" for key, value in options.items())
