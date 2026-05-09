"""
sysmon_collector.py
───────────────────
PowerShell Get-WinEvent 방식으로 Sysmon 이벤트 수집.
수집 대상 Event ID: 1(프로세스 생성), 3(네트워크 연결), 5(프로세스 종료), 22(DNS 쿼리)
"""

from __future__ import annotations
import subprocess
import json
import platform
from datetime import datetime

SYSMON_CHANNEL   = "Microsoft-Windows-Sysmon/Operational"
TARGET_EVENT_IDS = {1, 3, 5, 22}

_MITRE_MAP = {
    1:  {"Tactic ID": "TA0002", "Tactic Name": "Execution",
         "Technique ID": "T1059",
         "Technique Name": "Command and Scripting Interpreter",
         "탐지 유형": "의심"},
    3:  {"Tactic ID": "TA0011", "Tactic Name": "Command and Control",
         "Technique ID": "T1071",
         "Technique Name": "Application Layer Protocol",
         "탐지 유형": "의심"},
    5:  {"Tactic ID": "TA0005", "Tactic Name": "Defense Evasion",
         "Technique ID": "T1070",
         "Technique Name": "Indicator Removal",
         "탐지 유형": "정상"},
    22: {"Tactic ID": "TA0011", "Tactic Name": "Command and Control",
         "Technique ID": "T1071.004",
         "Technique Name": "DNS",
         "탐지 유형": "의심"},
}

_RISK_MAP = {1: "M", 3: "M", 5: "L", 22: "L"}


def is_available() -> bool:
    return platform.system() == "Windows"


def _get_field(message: str, field: str) -> str:
    """Message 텍스트에서 특정 필드 값 추출."""
    for line in message.splitlines():
        if line.strip().startswith(field + ":"):
            return line.split(":", 1)[-1].strip()
    return ""


def _build_행위내용(event_id: int, msg: str) -> str:
    if event_id == 1:
        proc   = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        parent = _get_field(msg, "ParentImage").replace("\\", "/").split("/")[-1]
        cmd    = _get_field(msg, "CommandLine")[:80]
        return f"[ID:1] {proc} 프로세스 생성 (부모: {parent}) | CMD: {cmd}"
    if event_id == 3:
        proc  = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        dst   = _get_field(msg, "DestinationIp")
        port  = _get_field(msg, "DestinationPort")
        proto = _get_field(msg, "Protocol")
        return f"[ID:3] {proc} 네트워크 연결 → {dst}:{port} ({proto})"
    if event_id == 5:
        proc = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        pid  = _get_field(msg, "ProcessId")
        return f"[ID:5] {proc} 프로세스 종료 (PID: {pid})"
    if event_id == 22:
        proc  = _get_field(msg, "Image").replace("\\", "/").split("/")[-1]
        query = _get_field(msg, "QueryName")
        return f"[ID:22] {proc} DNS 쿼리: {query}"
    return "알 수 없는 이벤트"


def collect(max_records: int = 500) -> list[dict]:
    if not is_available():
        raise RuntimeError("Windows 환경에서만 수집 가능합니다.")

    ids_filter = ",".join(str(i) for i in TARGET_EVENT_IDS)

    ps_script = f"""
$events = Get-WinEvent -LogName '{SYSMON_CHANNEL}' -MaxEvents {max_records} |
    Where-Object {{ {" -or ".join(f"$_.Id -eq {i}" for i in TARGET_EVENT_IDS)} }}

$result = @()
foreach ($e in $events) {{
    $result += [PSCustomObject]@{{
        Id          = $e.Id
        TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Message     = $e.Message
    }}
}}
$result | ConvertTo-Json -Depth 3
"""

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        if proc.returncode != 0 or not proc.stdout.strip():
            return []

        raw = proc.stdout.strip()

        # 단일 객체면 리스트로 감싸기
        if raw.startswith("{"):
            raw = f"[{raw}]"

        events_json = json.loads(raw)

    except Exception:
        return []

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows    = []

    for ev in events_json:
        event_id = int(ev.get("Id", 0))
        if event_id not in TARGET_EVENT_IDS:
            continue

        msg      = ev.get("Message", "")
        gen_time = ev.get("TimeCreated", now_str)
        mitre    = _MITRE_MAP[event_id]
        risk     = _RISK_MAP[event_id]

        proc_image = _get_field(msg, "Image")
        proc_name  = proc_image.replace("\\", "/").split("/")[-1] or "unknown.exe"

        rows.append({
            "로그 수신 날짜": now_str,
            "로그 생성 날짜": gen_time,
            "호스트 IP 주소": "localhost",
            "운영체제":       platform.platform(),
            "룰 레벨":        "중요" if risk in ("H", "High") else "일반",
            "위험도":         risk,
            "탐지 유형":      mitre["탐지 유형"],
            "Tactic ID":      mitre["Tactic ID"],
            "Tactic Name":    mitre["Tactic Name"],
            "Technique ID":   mitre["Technique ID"],
            "Technique Name": mitre["Technique Name"],
            "행위 내용":      _build_행위내용(event_id, msg),
            "프로세스":       proc_name,
            "상태":           "신규",
            "EventID":        event_id,
            "CommandLine":    _get_field(msg, "CommandLine"),
            "DestinationIp":  _get_field(msg, "DestinationIp"),
            "DestinationPort":_get_field(msg, "DestinationPort"),
            "QueryName":      _get_field(msg, "QueryName"),
        })

    return rows
# ==================================================================
# (이 위쪽은 기존 sysmon_collector.py 원본 코드입니다. 절대 건드리지 마세요!)
# ==================================================================

# ==================================================================
# ⚖️  EDR 위협 판별 및 분류 로직 (순수 Rule-based)
# ==================================================================
def evaluate_threat_level(log_data: dict) -> dict:
    """
   
    """
    event_id = log_data.get("EventID", 0)
    
    # 1. 네트워크 통신 (Event ID 3) - C&C 서버 통신 및 외부 유출 위험
    if event_id == 3:
        log_data["상태"] = "의심(주의)"
        log_data["위험도"] = "High"
        log_data["탐지 유형"] = "네트워크 이상 통신"
        log_data["조치내용"] = "⚠️ 외부 통신 시도 (정밀분석 대상)"
        
    # 2. 프로세스 생성 (Event ID 1) - 악성코드 및 스크립트 실행 가능성
    elif event_id == 1:
        log_data["상태"] = "의심"
        log_data["위험도"] = "Medium"
        log_data["탐지 유형"] = "의심스러운 프로세스 실행"
        log_data["조치내용"] = "⏸️ 신규 프로세스 실행 모니터링"
        
    # 3. DNS 쿼리 (Event ID 22) - 악성 도메인 탐색
    elif event_id == 22:
        log_data["상태"] = "의심"
        log_data["위험도"] = "Low"
        log_data["탐지 유형"] = "비정상 DNS 요청"
        log_data["조치내용"] = "👀 DNS 접속 기록 유지"
        
    # 4. 프로세스 종료 (Event ID 5) - 일반적인 정상 행위
    elif event_id == 5:
        log_data["상태"] = "정상"
        log_data["위험도"] = "Low"
        log_data["탐지 유형"] = "정상 행위"
        log_data["조치내용"] = "✅ 정상 종료 (기록 유지)"
        
    # 5. 그 외의 알 수 없는 이벤트
    else:
        log_data["상태"] = "신규"
        log_data["위험도"] = "Low"
        log_data["탐지 유형"] = "알 수 없음"
        log_data["조치내용"] = "기본 수집"

    return log_data

def apply_jonghan_policy(collected_logs: list[dict]) -> list[dict]:
    """
  
    """
    processed_logs = []
    for log in collected_logs:
       
        judged_log = evaluate_threat_level(log)
        processed_logs.append(judged_log)
        
    return processed_logs