"""
Utility helpers for talking to the backend upload/scan API.

The real implementation should perform HTTP requests against the FastAPI
endpoints. For now we keep the interface minimal so the GUI can interact
with a placeholder implementation without raising errors.
"""

from __future__ import annotations

import itertools
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests


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
    result_file: str = ""
    payload: Optional[Dict[str, Any]] = None


class Uploader:
    """
    Placeholder upload client.

    Replace these methods with real HTTP calls once the backend is ready.
    """

    _id_counter = itertools.count(1)

    def __init__(self, base_url: Optional[str] = None) -> None:
        self._jobs: List[ScanJob] = []
        raw_base = base_url or os.environ.get("MALSCAN_BACKEND_URL", "http://127.0.0.1:8000")
        self.base_url = raw_base.rstrip("/") + "/"
        self.session = requests.Session()

    def upload_file(self, file_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        opts = options or {}
        data = {
            "enable_yara": _bool_param(opts.get("yara", True)),
            "enable_capa": _bool_param(opts.get("capa") or False),
            "enable_floss": _bool_param(opts.get("floss") or False),
            "enable_pestudio": _bool_param(opts.get("pestudio") or False),
        }

        try:
            with open(file_path, "rb") as fh:
                resp = self.session.post(
                    urljoin(self.base_url, "scan/file"),
                    data=data,
                    files={"file": (os.path.basename(file_path), fh)},
                    timeout=120,
                )
        except OSError as exc:
            raise RuntimeError(f"Không thể đọc tệp: {exc}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Không thể kết nối backend: {exc}") from exc

        if resp.status_code >= 400:
            raise RuntimeError(_response_error(resp))

        payload = resp.json()
        job = self._create_job(file_path, "file", opts)
        job.status = "completed"
        job.payload = payload
        job.result = json.dumps(payload, ensure_ascii=False, indent=2)
        job.result_file = self._result_download_url(payload)
        return job

    def scan_by_hash(self, hash_value: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        opts = options or {}
        data = {
            "hash_value": hash_value,
            "enable_yara": _bool_param(opts.get("yara", True)),
            "enable_capa": _bool_param(opts.get("capa") or False),
            "enable_floss": _bool_param(opts.get("floss") or False),
            "enable_pestudio": _bool_param(opts.get("pestudio") or False),
        }

        try:
            resp = self.session.post(urljoin(self.base_url, "scan/hash"), data=data, timeout=30)
        except requests.RequestException as exc:
            raise RuntimeError(f"Không thể kết nối backend: {exc}") from exc

        if resp.status_code == 404:
            raise RuntimeError("Không tìm thấy kết quả trùng khớp với hash đã nhập.")
        if resp.status_code >= 400:
            raise RuntimeError(_response_error(resp))

        payload = resp.json()
        job = self._create_job(hash_value, "hash", opts)
        job.status = "completed"
        job.payload = payload
        job.result = json.dumps(payload, ensure_ascii=False, indent=2)
        job.result_file = self._result_download_url(payload)
        return job

    def schedule_system_scan(self, root_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(root_path, "system", options or {})
        job.status = "running"
        job.result = ""
        return job

    def schedule_directory_scan(self, root_path: str, options: Optional[Dict[str, str]] = None) -> ScanJob:
        job = self._create_job(root_path, "folder", options or {})
        job.status = "completed"
        job.result = _format_result(job, verdict="Hoàn tất quét thư mục, không phát hiện nguy cơ.")
        job.result_file = self._result_file_path(job)
        return job

    def finalize_job(self, job: ScanJob, verdict: str) -> ScanJob:
        job.status = "completed"
        job.result = _format_result(job, verdict=verdict)
        job.result_file = self._result_file_path(job)
        return job

    def list_jobs(self) -> List[ScanJob]:
        return list(self._jobs)

    def _create_job(self, target: str, mode: str, options: Dict[str, str]) -> ScanJob:
        job_id = f"job-{next(self._id_counter):05d}"
        job = ScanJob(job_id=job_id, target=target, mode=mode, options=options)
        self._jobs.append(job)
        return job

    @staticmethod
    def _result_file_path(job: ScanJob) -> str:
        return f"results/{job.job_id}.json"

    def _result_download_url(self, payload: Dict[str, Any]) -> str:
        download = payload.get("download_url")
        if not download:
            return ""
        return urljoin(self.base_url, download.lstrip("/"))


def _bool_param(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return "true" if value.lower() in {"true", "1", "yes", "on"} else "false"
    return "true" if value else "false"


def _response_error(resp: requests.Response) -> str:
    try:
        payload = resp.json()
        detail = payload.get("detail") or payload
    except ValueError:
        detail = resp.text
    return f"Backend trả về lỗi {resp.status_code}: {detail}"


def _format_result(job: ScanJob, verdict: Optional[str] = None) -> str:
    timestamp = time.strftime("%H:%M:%S", time.localtime(job.created_at))
    lines = [
        f"[{timestamp}] Báo cáo cho {job.job_id}",
        f"- Chế độ: {job.mode}",
        f"- Mục tiêu: {job.target}",
    ]
    if job.options:
        lines.append(f"- Tùy chọn: {_stringify_options(job.options)}")
    if verdict:
        lines.append(f"- Kết luận: {verdict}")
    else:
        lines.append("- Kết luận: Đang xử lý…")
    return "\n".join(lines)


def _stringify_options(options: Dict[str, str]) -> str:
    return ", ".join(f"{key}={value}" for key, value in options.items())
