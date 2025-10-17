# backend/app/scanner/yara_runner.py
import yara
import os

RULES_DIR = os.path.join(os.path.dirname(__file__), "../../rules")
_rules = None

def compile_rules():
    """Biên dịch tất cả file YARA trong thư mục rules/"""
    global _rules
    rule_files = {}
    for fname in os.listdir(RULES_DIR):
        if fname.endswith(".yar") or fname.endswith(".yara"):
            rule_files[fname] = os.path.join(RULES_DIR, fname)
    if not rule_files:
        raise FileNotFoundError("Không tìm thấy file .yar trong thư mục rules/")
    _rules = yara.compile(filepaths=rule_files)

def scan_bytes(data: bytes):
    """Chạy quét YARA trên dữ liệu bytes"""
    global _rules
    if _rules is None:
        compile_rules()
    matches = _rules.match(data=data)
    result = []
    for m in matches:
        result.append({
            "rule": m.rule,
            "tags": m.tags,
            "meta": m.meta,
            "strings": [s[2].decode(errors="ignore") if isinstance(s[2], bytes) else s[2] for s in m.strings]
        })
    return result
