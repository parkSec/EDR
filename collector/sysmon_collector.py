import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests


# ============================================================
# 기본 설정
# ============================================================

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
TARGET_EVENT_IDS = [1, 3, 5, 22]

API_URL = "http://127.0.0.1:8000/logs"
POLL_INTERVAL = 3
BATCH_SIZE = 500

AGENT_PID = os.getpid()
_API_TARGET = urlparse(API_URL)
API_HOST = _API_TARGET.hostname or "127.0.0.1"
API_PORT = _API_TARGET.port or (443 if _API_TARGET.scheme == "https" else 80)

BASE_DIR = Path(__file__).resolve().parent.parent
COLLECTOR_DIR = Path(__file__).resolve().parent

STATE_FILE = COLLECTOR_DIR / "collector_state.json"
FILELESS_STATE_FILE = COLLECTOR_DIR / "fileless_state.json"
ALERT_LOG_FILE = COLLECTOR_DIR / "alert_logs.jsonl"

XGBOOST_DIR = BASE_DIR / "xgboost"
sys.path.insert(0, str(XGBOOST_DIR))

if str(COLLECTOR_DIR) not in sys.path:
    sys.path.insert(0, str(COLLECTOR_DIR))


# ============================================================
# Fileless 탐지 모듈 로드
# ============================================================

try:
    from fileless_detector import (
        detect_fileless_threats as _detect_fileless,
        get_latest_powershell_record_id as _get_latest_fileless_record_id,
    )

    FILELESS_READY = True
except Exception as e:
    FILELESS_READY = False
    _detect_fileless = None
    _get_latest_fileless_record_id = None
    print("[Fileless] 모듈 로드 실패:", e)


# ============================================================
# XGBoost 모델 로드
# ============================================================

try:
    from threat_predictor import ThreatPredictor

    THREAT_PREDICTOR = ThreatPredictor()
    PREDICTOR_READY = THREAT_PREDICTOR.is_ready()

    if PREDICTOR_READY:
        print("[XGBoost] 모델 로드 성공")
    else:
        print("[XGBoost] 모델 준비 안 됨")

except Exception as e:
    THREAT_PREDICTOR = None
    PREDICTOR_READY = False
    print("[XGBoost] 로드 실패:", e)


# ============================================================
# MITRE 기본 매핑
# ============================================================

MITRE_MAP = {
    1: {
        "risk": "Medium",
        "detect_type": "프로세스 실행",
        "tactic_id": "TA0002",
        "tactic_name": "Execution",
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
    3: {
        "risk": "Medium",
        "detect_type": "네트워크 연결",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
    },
    5: {
        "risk": "Low",
        "detect_type": "프로세스 종료",
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
    },
    22: {
        "risk": "Low",
        "detect_type": "DNS 요청",
        "tactic_id": "TA0011",
        "tactic_name": "Command and Control",
        "technique_id": "T1071.004",
        "technique_name": "DNS",
    },
}

ATTACK_STAGE_MAP = {
    "Execution": "실행",
    "Persistence": "지속성 확보",
    "Privilege Escalation": "권한 상승",
    "Defense Evasion": "방어 우회",
    "Credential Access": "자격 증명 탈취",
    "Discovery": "시스템 탐색",
    "Lateral Movement": "내부 이동",
    "Collection": "정보 수집",
    "Command and Control": "명령 및 제어",
    "Exfiltration": "데이터 유출",
    "Impact": "시스템 영향",
}


def get_attack_stage(tactic):
    return ATTACK_STAGE_MAP.get(tactic, "Unknown")


def build_ai_reason(log):
    reasons = []
    event_id = int(log.get("event_id") or 0)

    if event_id == 1:
        reasons.append("Process Create")
    elif event_id == 3:
        reasons.append("Network Connection")
    elif event_id == 5:
        reasons.append("Process Terminated")
    elif event_id == 22:
        reasons.append("DNS Query")

    if log.get("risk") == "High":
        reasons.append("Rule Based Detection")

    if log.get("ai_score") is not None:
        reasons.append(f"AI Score {log['ai_score']}")

    return ", ".join(reasons)


# ============================================================
# 상태 파일 관리
# ============================================================


def load_last_record_id():
    if not STATE_FILE.exists():
        return 0

    try:
        with open(STATE_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
            return int(data.get("last_record_id", 0))
    except Exception as e:
        print("[Sysmon state 읽기 오류]", e)
        return 0


def save_last_record_id(record_id):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {"last_record_id": int(record_id)},
            f,
            ensure_ascii=False,
            indent=2,
        )


def load_last_fileless_record_id():
    if not FILELESS_STATE_FILE.exists():
        return None

    try:
        with open(FILELESS_STATE_FILE, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
            return int(data.get("last_fileless_record_id", 0))
    except Exception as e:
        print("[Fileless state 읽기 오류]", e)
        return None


def save_last_fileless_record_id(record_id):
    with open(FILELESS_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {"last_fileless_record_id": int(record_id)},
            f,
            ensure_ascii=False,
            indent=2,
        )


def initialize_fileless_record_id():
    """
    fileless_state.json이 없으면 현재 최신 4104를 시작점으로 자동 생성한다.
    따라서 과거 로그 전체를 재처리하지 않고 EDR 실행 이후 새 4104부터 본다.
    """

    saved = load_last_fileless_record_id()
    if saved is not None:
        return saved

    latest = 0

    if FILELESS_READY and _get_latest_fileless_record_id is not None:
        try:
            latest = int(_get_latest_fileless_record_id() or 0)
        except Exception:
            latest = 0

    save_last_fileless_record_id(latest)
    print(
        "[Fileless 상태 초기화] "
        f"현재 최신 4104 RecordId {latest}부터 이후 로그를 감시합니다."
    )
    return latest


# ============================================================
# 공통 유틸
# ============================================================


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_field(message, field_name):
    if not message:
        return ""

    target = field_name + ":"

    for line in str(message).splitlines():
        line = line.strip()
        if line.startswith(target):
            return line.split(":", 1)[1].strip()

    return ""


def get_process_name(image_path):
    if not image_path:
        return "unknown.exe"

    image_path = str(image_path).replace("\\", "/")
    return image_path.split("/")[-1] or "unknown.exe"


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def safe_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(str(value))
    except Exception:
        return default


def is_agent_backend_log(log):
    """현재 EDR 수집기가 FastAPI :8000으로 보내는 자체 Event ID 3 로그를 제외한다."""

    event_id = safe_int(log.get("event_id"))
    process_id = safe_int(log.get("process_id"))
    destination_ip = str(log.get("destination_ip") or "").strip()
    destination_port = safe_int(log.get("destination_port"))

    backend_addresses = {
        API_HOST,
        "127.0.0.1",
        "::1",
        "localhost",
    }

    return (
        event_id == 3
        and process_id == AGENT_PID
        and destination_port == API_PORT
        and destination_ip in backend_addresses
    )


def get_network_peer(message, host_ip=""):
    initiated = get_field(message, "Initiated").strip().lower()
    source_ip = get_field(message, "SourceIp").strip()
    source_port = get_field(message, "SourcePort").strip()
    destination_ip = get_field(message, "DestinationIp").strip()
    destination_port = get_field(message, "DestinationPort").strip()

    if initiated == "false":
        remote_ip = source_ip
        direction = "inbound"
    elif initiated == "true":
        remote_ip = destination_ip
        direction = "outbound"
    elif host_ip and destination_ip == host_ip:
        remote_ip = source_ip
        direction = "inbound"
    elif host_ip and source_ip == host_ip:
        remote_ip = destination_ip
        direction = "outbound"
    else:
        remote_ip = destination_ip or source_ip
        direction = "unknown"

    return {
        "direction": direction,
        "remote_ip": remote_ip,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
    }


# ============================================================
# 행위 설명 생성
# ============================================================


def make_action_desc(event_id, message):
    image = get_field(message, "Image")
    process_name = get_process_name(image)

    if event_id == 1:
        command_line = get_field(message, "CommandLine")
        parent_image = get_field(message, "ParentImage")
        parent_name = get_process_name(parent_image)
        return (
            f"[ID:1] {process_name} 프로세스 실행"
            f" | 부모: {parent_name}"
            f" | CMD: {command_line[:120]}"
        )

    if event_id == 3:
        network = get_network_peer(message)
        protocol = get_field(message, "Protocol")

        if network["direction"] == "inbound":
            return (
                f"[ID:3] {process_name} 인바운드 연결"
                f" | 원격: {network['source_ip']}:{network['source_port']}"
                f" -> 로컬: {network['destination_ip']}:{network['destination_port']}"
                f" | {protocol}"
            )

        if network["direction"] == "outbound":
            return (
                f"[ID:3] {process_name} 아웃바운드 연결"
                f" | 로컬: {network['source_ip']}:{network['source_port']}"
                f" -> 원격: {network['destination_ip']}:{network['destination_port']}"
                f" | {protocol}"
            )

        return (
            f"[ID:3] {process_name} 네트워크 연결"
            f" | {network['source_ip']}:{network['source_port']}"
            f" -> {network['destination_ip']}:{network['destination_port']}"
            f" | {protocol}"
        )

    if event_id == 5:
        process_id = get_field(message, "ProcessId")
        return f"[ID:5] {process_name} 프로세스 종료 | PID: {process_id}"

    if event_id == 22:
        query_name = get_field(message, "QueryName")
        return f"[ID:22] {process_name} DNS 요청 | {query_name}"

    return "Sysmon 이벤트"


# ============================================================
# Fileless + Sysmon 상관관계 가중치
# ============================================================

CORRELATION_WINDOW_SEC = 300
_recent_behavior_events = deque(maxlen=3000)


def apply_correlation_weight(logs):
    """
    같은 host_ip + 같은 PID에서 최근 5분 동안
    4104와 Sysmon 1/22/3이 이어질 경우 최종 위험도를 높인다.

    가중치:
    - Event 1  Process Create       +10
    - Event 22 DNS Query            +15
    - Event 3  Network Connection   +20
    - Event 5  Process Terminate    경로만 기록, 점수 가산 없음

    Fileless 4104의 행위 점수를 기준으로 연계 점수를 계산하므로
    4104(50) + 1(10) + 22(15) + 3(20) = 95점 같은 흐름이 가능하다.
    """

    if not logs:
        return logs

    now_ts = time.time()

    while (
        _recent_behavior_events
        and now_ts - _recent_behavior_events[0]["time"] > CORRELATION_WINDOW_SEC
    ):
        _recent_behavior_events.popleft()

    for log in logs:
        host_ip = str(log.get("host_ip") or "")
        process_id = safe_int(log.get("process_id"), 0)
        event_id = safe_int(log.get("event_id"), 0)

        try:
            current_base_score = float(log.get("final_score") or 0)
        except Exception:
            current_base_score = 0.0

        related = []
        if process_id > 0:
            related = [
                item
                for item in _recent_behavior_events
                if item["host_ip"] == host_ip and item["process_id"] == process_id
            ]

        related_event_ids = {item["event_id"] for item in related}
        related_event_ids.add(event_id)

        fileless_base_scores = [
            float(item.get("base_score") or 0)
            for item in related
            if item.get("event_id") == 4104
        ]

        if event_id == 4104:
            fileless_base_scores.append(current_base_score)

        if 4104 in related_event_ids:
            base_score = max(
                [current_base_score] + fileless_base_scores
            )

            bonus = 0
            path = ["PowerShell ScriptBlock(4104)"]

            if 1 in related_event_ids:
                bonus += 10
                path.append("Process Create(1)")

            if 22 in related_event_ids:
                bonus += 15
                path.append("DNS Query(22)")

            if 3 in related_event_ids:
                bonus += 20
                path.append("Network Connection(3)")

            if 5 in related_event_ids:
                path.append("Process Terminate(5)")

            if bonus > 0:
                log["final_score"] = round(min(base_score + bonus, 100.0), 2)
                log["attack_path"] = " → ".join(path)

                old_reason = str(log.get("ai_reason") or "").strip()
                correlation_reason = f"Fileless/Sysmon 행위 연계 +{bonus}점"

                log["ai_reason"] = (
                    f"{old_reason} | {correlation_reason}"
                    if old_reason
                    else correlation_reason
                )

        _recent_behavior_events.append(
            {
                "time": now_ts,
                "host_ip": host_ip,
                "process_id": process_id,
                "event_id": event_id,
                "base_score": current_base_score,
                "process_name": str(log.get("process_name") or ""),
            }
        )

    return logs


# ============================================================
# 규칙 기반 위험도 계산
# ============================================================


def calculate_rule_score(log):
    score = 0
    reasons = []

    event_id = int(log.get("event_id") or 0)
    process_name = str(log.get("process_name") or "").lower()
    command_line = str(log.get("command_line") or "").lower()
    destination_ip = str(log.get("destination_ip") or "")
    destination_port = str(log.get("destination_port") or "")
    query_name = str(log.get("query_name") or "").lower()

    if event_id == 1:
        score += 10
    elif event_id == 3:
        score += 25
    elif event_id == 5:
        score += 5
    elif event_id == 22:
        score += 10

    danger_tools = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin",
        "schtasks",
        "net.exe",
        "wmic",
        "reg.exe",
    ]

    if any(tool in process_name for tool in danger_tools):
        score += 35
        reasons.append("위험 도구 실행")

    suspicious_keywords = [
        "-enc",
        "encodedcommand",
        "bypass",
        "hidden",
        "downloadstring",
        "invoke-webrequest",
        "iwr ",
        "iex",
        "frombase64string",
        "new-object net.webclient",
    ]

    if any(keyword in command_line for keyword in suspicious_keywords):
        score += 35
        reasons.append("의심 명령어 사용")

    if event_id == 3 and destination_port not in ["", "80", "443", "53"]:
        score += 20
        reasons.append("비표준 포트 통신")

    if event_id == 3 and destination_ip and not is_private_ip(destination_ip):
        score += 15
        reasons.append("외부 IP 통신")

    suspicious_domains = [
        ".top",
        ".xyz",
        ".ru",
        "duckdns",
        "no-ip",
        "pastebin",
        "raw.githubusercontent",
    ]

    if event_id == 22 and any(domain in query_name for domain in suspicious_domains):
        score += 25
        reasons.append("의심 DNS 요청")

    security_processes = [
        "msmpeng",
        "defender",
        "v3",
        "alyac",
        "edr",
        "agent",
        "security",
    ]

    if event_id == 5 and any(name in process_name for name in security_processes):
        score += 60
        reasons.append("보안 프로세스 종료 의심")

    if score >= 75:
        risk = "High"
        rule_level = "중요"
        status = "알림"
    elif score >= 40:
        risk = "Medium"
        rule_level = "주의"
        status = "의심"
    else:
        risk = "Low"
        rule_level = "일반"
        status = "신규"

    log["rule_score"] = score
    log["risk"] = risk
    log["rule_level"] = rule_level
    log["status"] = status
    log["alert_reason"] = ", ".join(reasons) if reasons else "특이사항 없음"

    return log


# ============================================================
# XGBoost 입력/예측
# ============================================================


def make_xgboost_input(log):
    return {
        "event_id": safe_int(log.get("event_id"), 0),
        "process_id": safe_int(log.get("process_id"), 0),
        "parent_process_id": safe_int(log.get("parent_process_id"), 0),
        "image": log.get("image", ""),
        "process_name": log.get("process_name", ""),
        "command_line": log.get("command_line", ""),
        "user": log.get("user", ""),
        "parent_image": log.get("parent_image", ""),
        "destination_ip": log.get("destination_ip", ""),
        "destination_port": safe_int(log.get("destination_port"), 0),
        "source_ip": log.get("source_ip", ""),
        "source_port": safe_int(log.get("source_port"), 0),
        "query_name": log.get("query_name", ""),
    }


def add_xgboost_prediction(logs):
    if not logs:
        return logs

    if not PREDICTOR_READY or THREAT_PREDICTOR is None:
        for log in logs:
            log["ai_score"] = None
            log["ai_risk"] = "Unknown"
            log["final_score"] = 0
            log["ai_reason"] = "Prediction Disabled"
        return logs

    for log in logs:
        try:
            xgb_input = make_xgboost_input(log)
            result = THREAT_PREDICTOR.predict(xgb_input)

            if result.get("success"):
                probability = float(result.get("probability", 0.0))
                log["ai_score"] = round(probability * 100, 2)
                log["ai_risk"] = result.get("risk_label", "Unknown")
                log["final_score"] = log["ai_score"]
                log["ai_reason"] = build_ai_reason(log)
            else:
                log["ai_score"] = None
                log["ai_risk"] = "Unknown"
                log["final_score"] = 0
                log["ai_reason"] = "Prediction Failed"

        except Exception as e:
            print("[XGBoost 예측 실패]", e)
            log["ai_score"] = None
            log["ai_risk"] = "Unknown"
            log["final_score"] = 0
            log["ai_reason"] = "Prediction Failed"

    return logs


# ============================================================
# 최종 알람 정책
# ============================================================


def apply_alert_policy(logs):
    """
    Sysmon은 AI 점수, Fileless는 행위 점수를 final_score의 시작점으로 사용한다.
    상관관계 가중치까지 반영된 final_score가 90 이상이면 Critical 처리한다.
    """

    for log in logs:
        try:
            final_score = log.get("final_score")
            ai_score = log.get("ai_score")

            if final_score is not None:
                score = float(final_score)
            elif ai_score is not None:
                score = float(ai_score)
            else:
                score = 0.0
        except Exception:
            score = 0.0

        log["final_score"] = round(score, 2)

        if score >= 90:
            log["ai_risk"] = "Critical"
            log["status"] = "알림"
            log["rule_level"] = "중요"

            if not str(log.get("action_desc", "")).startswith("[ALERT]"):
                log["action_desc"] = (
                    f"[ALERT] 최종 위험도 {score:.2f}점 | "
                    + str(log.get("action_desc", ""))
                )

        elif score >= 50:
            log["ai_risk"] = "High"
            log["status"] = "의심"
            log["rule_level"] = "주의"

        elif score >= 25:
            log["ai_risk"] = "Medium"
            log["status"] = "의심"
            log["rule_level"] = "주의"

        else:
            log["ai_risk"] = "Low"
            log["status"] = "신규"
            log["rule_level"] = "일반"

    return logs


# ============================================================
# 알람 출력 및 파일 저장
# ============================================================


def notify_alerts(logs):
    alerts = [log for log in logs if log.get("status") == "알림"]

    if not alerts:
        return

    try:
        import winsound

        winsound.MessageBeep(winsound.MB_ICONHAND)
    except Exception:
        pass

    print("\n" + "=" * 70)
    print("[실시간 알람] 위험 이벤트 감지:", len(alerts), "건")
    print("=" * 70)

    with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
        for log in alerts:
            alert_data = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event_id": log.get("event_id"),
                "process_name": log.get("process_name"),
                "risk": log.get("risk"),
                "ai_score": log.get("ai_score"),
                "ai_risk": log.get("ai_risk"),
                "final_score": log.get("final_score"),
                "reason": log.get("ai_reason") or log.get("alert_reason"),
                "action_desc": log.get("action_desc"),
            }

            print("EventID:", alert_data["event_id"])
            print("Process:", alert_data["process_name"])
            print("Risk:", alert_data["risk"])
            print("AI:", str(alert_data["ai_score"]) + " / " + str(alert_data["ai_risk"]))
            print("Final Score:", alert_data["final_score"])
            print("Reason:", alert_data["reason"])
            print("Action:", alert_data["action_desc"])
            print("-" * 70)

            f.write(json.dumps(alert_data, ensure_ascii=False) + "\n")

    print("=" * 70 + "\n")


# ============================================================
# PowerShell로 Sysmon 이벤트 조회
# ============================================================


def run_powershell_get_events(last_record_id, max_records=BATCH_SIZE):
    last_record_id = safe_int(last_record_id)
    max_records = max(1, safe_int(max_records, BATCH_SIZE))

    ps_script = r"""
$xpath = "*[System[
    (EventID=1 or EventID=3 or EventID=5 or EventID=22)
    and
    (EventRecordID > %d)
]]"

$events = Get-WinEvent `
    -LogName '%s' `
    -FilterXPath $xpath `
    -Oldest `
    -MaxEvents %d `
    -ErrorAction Stop

$result = @()
foreach ($e in $events) {
    $result += [PSCustomObject]@{
        Id          = $e.Id
        RecordId    = $e.RecordId
        TimeCreated = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        Message     = $e.Message
    }
}

$result | ConvertTo-Json -Depth 5
""" % (
        last_record_id,
        SYSMON_CHANNEL,
        max_records,
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        if result.returncode != 0:
            print("[PowerShell 오류]")
            print(result.stderr)
            return []

        output = result.stdout.strip()
        if not output:
            return []

        data = json.loads(output)

        if data is None:
            return []

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return []

        return data

    except Exception as e:
        print("[Sysmon 로그 조회 실패]", e)
        return []


# ============================================================
# 최근 Sysmon 로그 수집
# ============================================================


def collect_recent_logs(last_record_id=None, batch_size=BATCH_SIZE):
    if last_record_id is None:
        last_record_id = load_last_record_id()

    events = run_powershell_get_events(last_record_id, batch_size)

    logs = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_ip = get_local_ip()
    os_name = platform.platform()

    for event in events:
        try:
            event_id = int(event.get("Id", 0))
            record_id = int(event.get("RecordId", 0))
        except Exception:
            continue

        if event_id not in TARGET_EVENT_IDS:
            continue

        message = event.get("Message", "")
        gen_time = event.get("TimeCreated", now_str)
        image = get_field(message, "Image")
        process_name = get_process_name(image)
        parent_image = get_field(message, "ParentImage")
        parent_process_id = get_field(message, "ParentProcessId")

        if event_id == 3:
            network = get_network_peer(message, host_ip)
        else:
            network = {
                "direction": "",
                "remote_ip": "",
                "source_ip": "",
                "source_port": "",
                "destination_ip": "",
                "destination_port": "",
            }

        mitre = MITRE_MAP.get(event_id, {})

        log = {
            "recv_time": now_str,
            "gen_time": gen_time,
            "host_ip": host_ip,
            "os_name": os_name,
            "rule_level": "일반",
            "risk": mitre.get("risk", "Low"),
            "detect_type": mitre.get("detect_type", "기타"),
            "tactic_id": mitre.get("tactic_id"),
            "tactic_name": mitre.get("tactic_name"),
            "technique_id": mitre.get("technique_id"),
            "technique_name": mitre.get("technique_name"),
            "action_desc": make_action_desc(event_id, message),
            "process_name": process_name,
            "process_path": image,
            "event_id": event_id,
            "command_line": get_field(message, "CommandLine"),
            "destination_ip": network.get("remote_ip", ""),
            "destination_port": network.get("destination_port", ""),
            "query_name": get_field(message, "QueryName"),
            "status": "신규",
            "_record_id": record_id,
            "process_id": get_field(message, "ProcessId"),
            "parent_process_id": parent_process_id,
            "image": image,
            "user": get_field(message, "User"),
            "parent_image": parent_image,
            "source_ip": network.get("source_ip", ""),
            "source_port": network.get("source_port", ""),
            "attack_stage": "",
            "attack_path": "",
            "ai_reason": "",
            "final_score": 0,
        }

        log = calculate_rule_score(log)
        log["attack_stage"] = get_attack_stage(log["tactic_name"])
        log["attack_path"] = log["attack_stage"]

        logs.append(log)

    return logs


# ============================================================
# FastAPI 전송
# ============================================================


def send_logs_to_fastapi(logs):
    if not logs:
        return True

    clean_logs = []

    for log in logs:
        copied = dict(log)

        copied.pop("_record_id", None)
        copied.pop("rule_score", None)
        copied.pop("alert_reason", None)

        # DB 스키마에 없는 상관관계/XGBoost 내부 필드 제거
        copied.pop("process_id", None)
        copied.pop("parent_process_id", None)
        copied.pop("image", None)
        copied.pop("user", None)
        copied.pop("parent_image", None)
        copied.pop("source_ip", None)
        copied.pop("source_port", None)

        clean_logs.append(copied)

    payload = {"logs": clean_logs}

    try:
        response = requests.post(API_URL, json=payload, timeout=10)

        if response.status_code in (200, 201):
            print("[전송 성공] " + str(len(clean_logs)) + "건")
            return True

        print("[전송 실패] " + str(response.status_code))
        print(response.text)
        return False

    except Exception as e:
        print("[FastAPI 연결 실패]", e)
        return False


# ============================================================
# Fileless 로그 수집 및 EDR 형식 변환
# ============================================================


def collect_fileless_logs(last_record_id, batch_size=BATCH_SIZE):
    if not FILELESS_READY or _detect_fileless is None:
        return [], int(last_record_id or 0)

    try:
        threats, last_seen_record_id = _detect_fileless(
            last_record_id=last_record_id,
            max_records=batch_size,
            return_meta=True,
        )
    except Exception as e:
        print("[Fileless 탐지 오류]", e)
        return [], int(last_record_id or 0)

    logs = []
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_ip = get_local_ip()
    os_name = platform.platform()

    risk_map = {
        "H": "High",
        "M": "Medium",
        "L": "Low",
    }

    for threat in threats:
        risk = risk_map.get(threat.get("risk_level", "M"), "Medium")

        try:
            behavior_score = round(float(threat.get("risk_score", 0)) * 100, 2)
        except Exception:
            behavior_score = 0.0

        keyword_names = []
        for item in threat.get("keywords_detected", []):
            if isinstance(item, dict):
                keyword = str(item.get("keyword", "")).strip()
                if keyword:
                    keyword_names.append(keyword)

        obfuscation_flags = [
            str(value)
            for value in threat.get("obfuscation_flags", [])
            if str(value).strip()
        ]

        behavior_categories = [
            str(value)
            for value in threat.get("behavior_categories", [])
            if str(value).strip()
        ]

        reason_parts = keyword_names + obfuscation_flags + behavior_categories
        reason_text = ", ".join(dict.fromkeys(reason_parts))

        log = {
            "recv_time": now_str,
            "gen_time": str(threat.get("timestamp") or now_str),
            "host_ip": host_ip,
            "os_name": os_name,
            "rule_level": "주의",
            "risk": risk,
            "detect_type": "Fileless 공격",
            "tactic_id": "TA0002",
            "tactic_name": "Execution",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "action_desc": (
                "[ID:4104] PowerShell Fileless 의심 행위"
                + (f" | {reason_text[:500]}" if reason_text else "")
            ),
            "process_name": "powershell.exe",
            "process_path": "powershell.exe",
            "event_id": 4104,
            "command_line": str(threat.get("command_snippet", "")),
            "destination_ip": "",
            "destination_port": "",
            "query_name": "",
            "status": "의심",
            "_record_id": safe_int(threat.get("record_id"), 0),
            "process_id": safe_int(threat.get("process_id"), 0),
            "parent_process_id": 0,
            "image": "powershell.exe",
            "user": "",
            "parent_image": "",
            "source_ip": "",
            "source_port": "",
            # 4104는 기존 XGBoost 학습 Event ID가 아니므로 모델 예측하지 않는다.
            "ai_score": None,
            "ai_risk": "Unknown",
            "attack_stage": "실행/방어 우회",
            "attack_path": "PowerShell ScriptBlock(4104)",
            "ai_reason": (
                "Fileless Behavior Detection"
                + (f" | {reason_text[:600]}" if reason_text else "")
            ),
            "final_score": behavior_score,
        }

        logs.append(log)

    return logs, int(last_seen_record_id or last_record_id or 0)


# ============================================================
# 메인 루프
# ============================================================


def main():
    print("=" * 60)
    print("Sysmon + PowerShell Fileless 실시간 로그 수집기를 시작합니다.")
    print(f"Sysmon 수집 대상 Event ID: {TARGET_EVENT_IDS}")
    print("PowerShell 수집 대상 Event ID: 4104")
    print(f"전송 주소: {API_URL}")
    print(f"수집 주기: {POLL_INTERVAL}초")
    print(f"한 번에 조회할 이벤트 수: {BATCH_SIZE}개")
    print("=" * 60)

    last_record_id = load_last_record_id()
    last_fileless_record_id = initialize_fileless_record_id()

    print(f"[Sysmon 시작 위치] 마지막 RecordId: {last_record_id}")
    print(f"[Fileless 시작 위치] 마지막 RecordId: {last_fileless_record_id}")

    while True:
        try:
            # ----------------------------------------------------
            # 1. Sysmon 1/3/5/22: 매 주기 최대 BATCH_SIZE개 처리
            # ----------------------------------------------------
            sysmon_logs = collect_recent_logs(last_record_id, BATCH_SIZE)

            sysmon_logs = [
                log
                for log in sysmon_logs
                if safe_int(log.get("_record_id"), 0) > last_record_id
            ]

            sysmon_logs.sort(
                key=lambda log: safe_int(log.get("_record_id"), 0)
            )

            if sysmon_logs:
                batch_last_record_id = max(
                    safe_int(log.get("_record_id"), 0)
                    for log in sysmon_logs
                )

                upload_logs = []
                excluded_count = 0

                for log in sysmon_logs:
                    if is_agent_backend_log(log):
                        excluded_count += 1
                        continue
                    upload_logs.append(log)

                if excluded_count:
                    print(f"[자체 통신 제외] {excluded_count}건")

                sysmon_success = True

                if upload_logs:
                    upload_logs = add_xgboost_prediction(upload_logs)
                    upload_logs = apply_correlation_weight(upload_logs)
                    upload_logs = apply_alert_policy(upload_logs)
                    sysmon_success = send_logs_to_fastapi(upload_logs)

                    if sysmon_success:
                        notify_alerts(upload_logs)

                if sysmon_success:
                    last_record_id = batch_last_record_id
                    save_last_record_id(last_record_id)

                    print(
                        f"[Sysmon 처리 완료] 조회 {len(sysmon_logs)}건 / "
                        f"전송 {len(upload_logs)}건 / "
                        f"마지막 RecordId {last_record_id}"
                    )

                    for log in upload_logs:
                        print(
                            "[수집/전송] "
                            f"RecordId={log.get('_record_id')} | "
                            f"EventID={log.get('event_id')} | "
                            f"Process={log.get('process_name')} | "
                            f"Destination={log.get('destination_ip')}:{log.get('destination_port')} | "
                            f"AI={log.get('ai_score')} / {log.get('ai_risk')} | "
                            f"Final={log.get('final_score')}"
                        )
                else:
                    print("[Sysmon 전송 실패] RecordId를 갱신하지 않습니다.")

            # ----------------------------------------------------
            # 2. Fileless 4104: Sysmon backlog와 무관하게 매 주기 확인
            # ----------------------------------------------------
            fileless_logs, fileless_last_seen = collect_fileless_logs(
                last_fileless_record_id,
                BATCH_SIZE,
            )

            if fileless_last_seen > last_fileless_record_id:
                if fileless_logs:
                    fileless_logs = apply_correlation_weight(fileless_logs)
                    fileless_logs = apply_alert_policy(fileless_logs)

                    fileless_success = send_logs_to_fastapi(fileless_logs)

                    if fileless_success:
                        notify_alerts(fileless_logs)
                        last_fileless_record_id = fileless_last_seen
                        save_last_fileless_record_id(last_fileless_record_id)

                        print(
                            f"[Fileless 탐지/처리 완료] {len(fileless_logs)}건 | "
                            f"마지막 4104 RecordId {last_fileless_record_id}"
                        )

                        for log in fileless_logs:
                            print(
                                "[Fileless] "
                                f"RecordId={log.get('_record_id')} | "
                                f"PID={log.get('process_id')} | "
                                f"Final={log.get('final_score')} | "
                                f"Risk={log.get('ai_risk')} | "
                                f"Path={log.get('attack_path')}"
                            )
                    else:
                        print(
                            "[Fileless 전송 실패] "
                            "4104 RecordId를 갱신하지 않아 다음 주기에 재시도합니다."
                        )

                else:
                    # 새 4104가 있었지만 위험 행위로 판정되지 않은 경우에도
                    # 확인한 위치까지 상태 파일을 갱신하여 중복 분석을 막는다.
                    last_fileless_record_id = fileless_last_seen
                    save_last_fileless_record_id(last_fileless_record_id)
                    print(
                        "[Fileless 정상 4104 처리] "
                        f"마지막 RecordId {last_fileless_record_id}"
                    )

        except KeyboardInterrupt:
            print("\n수집기를 종료합니다.")
            break

        except Exception as e:
            print(f"[수집 중 오류] {e}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()