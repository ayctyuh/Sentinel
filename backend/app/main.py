# backend/app/main.py
from fastapi import FastAPI, File, UploadFile, WebSocket
from fastapi.responses import JSONResponse
import hashlib
import os
from scanner.yara_runner import scan_bytes

app = FastAPI(title="MalScan Backend", version="1.0")

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "../../storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """Nhận file từ người dùng, lưu và quét bằng YARA"""
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    save_path = os.path.join(STORAGE_DIR, f"{sha256}_{file.filename}")

    with open(save_path, "wb") as f:
        f.write(content)

    # Quét file bằng YARA
    results = scan_bytes(content)

    return JSONResponse({
        "filename": file.filename,
        "sha256": sha256,
        "result": results
    })

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket test - sẽ dùng để cập nhật tiến trình realtime"""
    await websocket.accept()
    await websocket.send_text("Connected to MalScan WebSocket")
    await websocket.close()
