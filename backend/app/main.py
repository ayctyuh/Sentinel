from __future__ import annotations

import hashlib
import json
import os
import struct
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import ScanRecord
from app.db.session import Base, engine, get_db
from app.scanner.capa_wrapper import run_capa
from app.scanner.floss_wrapper import run_floss
from app.scanner.pestudio_wrapper import run_pestudio_like_analysis
from app.scanner.yara_runner import scan_bytes

app = FastAPI(title=settings.app_name, version="1.0")

Base.metadata.create_all(bind=engine)

STORAGE_DIR = settings.storage_dir
RESULTS_DIR = settings.results_dir


def _detect_file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    return "UNKNOWN"


def _detect_architecture(data: bytes) -> Optional[str]:
    if not data.startswith(b"MZ"):
        return None
    if len(data) < 0x40:
        return None
    pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
    if len(data) < pe_offset + 6:
        return None
    machine = struct.unpack("<H", data[pe_offset + 4 : pe_offset + 6])[0]
    return {
        0x014C: "x86",
        0x8664: "x64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }.get(machine, f"UNKNOWN(0x{machine:04x})")


def _calculate_score(
    yara_matches: List[Dict[str, str]],
    capa_result: Dict,
    pestudio_result: Dict,
    default_weight: float = 20.0,
) -> float:
    score = 0.0
    score += min(60.0, len(yara_matches) * default_weight)
    capa_rules = capa_result.get("rules", []) if capa_result else []
    score += min(30.0, len(capa_rules) * 7.5)
    if pestudio_result.get("imports"):
        flagged = [dll for dll in pestudio_result["imports"] if dll.lower().startswith("advapi32")]
        score += min(10.0, len(flagged) * 2.5)
    return round(min(score, 100.0), 2)


def _make_verdict(score: float) -> str:
    if score >= 80:
        return "Highly suspicious"
    if score >= 55:
        return "Suspicious"
    if score >= 30:
        return "Needs review"
    return "Likely benign"


def _compute_hashes(data: bytes) -> Dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _prepare_result_payload(
    job_id: str,
    filename: str,
    hashes: Dict[str, str],
    file_type: str,
    architecture: Optional[str],
    yara_matches: List[Dict],
    capa_result: Optional[Dict],
    floss_result: Optional[Dict],
    pestudio_result: Optional[Dict],
    score: float,
    verdict: str,
) -> Dict[str, object]:
    payload: Dict[str, object] = {
        "job_id": job_id,
        "filename": filename,
        "hashes": hashes,
        "file_type": file_type,
        "architecture": architecture,
        "verdict": verdict,
        "score": score,
        "yara_matches": yara_matches,
    }

    if capa_result:
        payload["capa"] = capa_result
    if floss_result:
        payload["floss"] = floss_result
    if pestudio_result:
        payload["pestudio"] = pestudio_result

    if not any((capa_result, floss_result, pestudio_result)):
        payload["summary"] = {
            "message": "Không có công cụ bổ sung nào được chọn. Hiển thị thông tin cơ bản của tệp.",
        }

    return payload


def _save_result_file(job_id: str, payload: Dict[str, object]) -> Path:
    path = RESULTS_DIR / f"{job_id}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def _assign_job_id(record: ScanRecord) -> str:
    return f"job-{record.id:05d}"


@app.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    enable_yara: bool = Form(True),
    enable_capa: bool = Form(False),
    enable_floss: bool = Form(False),
    enable_pestudio: bool = Form(False),
    db: Session = Depends(get_db),
):
    data = await file.read()
    hashes = _compute_hashes(data)

    safe_filename = f"{hashes['sha256'][:12]}_{file.filename}"
    save_path = STORAGE_DIR / safe_filename
    with save_path.open("wb") as fh:
        fh.write(data)

    yara_matches = scan_bytes(data) if enable_yara else []
    capa_result = run_capa(str(save_path)) if enable_capa else None
    floss_result = run_floss(str(save_path)) if enable_floss else None
    pestudio_result = run_pestudio_like_analysis(str(save_path)) if enable_pestudio else None

    file_type = _detect_file_type(data)
    architecture = _detect_architecture(data)

    score = _calculate_score(yara_matches, capa_result or {}, pestudio_result or {})
    verdict = _make_verdict(score)

    payload = _prepare_result_payload(
        job_id="pending",
        filename=file.filename,
        hashes=hashes,
        file_type=file_type,
        architecture=architecture,
        yara_matches=yara_matches,
        capa_result=capa_result,
        floss_result=floss_result,
        pestudio_result=pestudio_result,
        score=score,
        verdict=verdict,
    )

    record = ScanRecord(
        job_id="pending",
        filename=str(save_path),
        original_name=file.filename,
        sha256=hashes["sha256"],
        sha1=hashes["sha1"],
        md5=hashes["md5"],
        file_type=file_type,
        architecture=architecture,
        verdict=verdict,
        score=score,
        options={
            "yara": enable_yara,
            "capa": enable_capa,
            "floss": enable_floss,
            "pestudio": enable_pestudio,
        },
        yara_matches=yara_matches,
    )

    db.add(record)
    db.flush()
    job_id = _assign_job_id(record)
    payload["job_id"] = job_id

    result_path = _save_result_file(job_id, payload)
    record.job_id = job_id
    record.result_path = str(result_path)
    record.summary = payload.get("summary") and json.dumps(payload["summary"], ensure_ascii=False)
    db.commit()

    response_payload = payload.copy()
    response_payload["download_url"] = f"/jobs/{job_id}/download"
    response_payload["result_path"] = str(result_path)

    return JSONResponse(response_payload)


@app.post("/scan/hash")
def scan_by_hash(
    hash_value: str = Form(...),
    enable_yara: bool = Form(True),
    enable_capa: bool = Form(False),
    enable_floss: bool = Form(False),
    enable_pestudio: bool = Form(False),
    db: Session = Depends(get_db),
):
    value = hash_value.strip().lower()
    if not value:
        raise HTTPException(status_code=400, detail="Hash value is required")

    record = (
        db.query(ScanRecord)
        .filter(
            or_(
                ScanRecord.sha256 == value,
                ScanRecord.sha1 == value,
                ScanRecord.md5 == value,
            )
        )
        .first()
    )

    if not record:
        raise HTTPException(status_code=404, detail="Hash not found in database")

    result_path = Path(record.result_path)
    if not result_path.exists():
        raise HTTPException(status_code=404, detail="Result file missing")

    with result_path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)

    payload.setdefault("download_url", f"/jobs/{record.job_id}/download")
    response = record.to_result(payload)
    response["download_url"] = payload["download_url"]
    response["result_path"] = record.result_path

    requested_tools = {
        "yara": enable_yara,
        "capa": enable_capa,
        "floss": enable_floss,
        "pestudio": enable_pestudio,
    }
    response["tools_requested"] = requested_tools
    response["from_cache"] = True

    return JSONResponse(response)


@app.get("/jobs")
def list_jobs(limit: int = 25, db: Session = Depends(get_db)):
    records = (
        db.query(ScanRecord)
        .order_by(ScanRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "items": [record.to_summary() for record in records],
    }


@app.get("/jobs/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.job_id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Job not found")
    result_file = Path(record.result_path)
    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Result file missing")
    with result_file.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return record.to_result(payload)


@app.get("/jobs/{job_id}/download")
def download_job(job_id: str, db: Session = Depends(get_db)):
    record = db.query(ScanRecord).filter(ScanRecord.job_id == job_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Job not found")
    result_path = Path(record.result_path)
    if not result_path.exists():
        raise HTTPException(status_code=404, detail="Result file missing")
    return FileResponse(result_path, media_type="application/json", filename=f"{job_id}.json")
