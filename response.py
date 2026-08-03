import subprocess
import psutil
import time
import ipaddress
from datetime import datetime
from backend.database import SessionLocal, ResponseResult, SysmonLog, ToggleState


def load_toggle_state():
    db = SessionLocal()
    try:
        toggle = db.query(ToggleState).first()
        if toggle is None:
            return {"auto_response": True, "on_time": None}
        return {
            "auto_response": bool(toggle.auto_response),
            "on_time": toggle.on_time
        }
    finally:
        db.close()


def kill_process(process_path):
    process_name = get_process_name(process_path).lower()

    if not process_name:
        return False

    killed = False

    for proc in psutil.process_iter(["name"]):
        try:
            current_name = str(proc.info.get("name") or "").lower()

            if current_name == process_name:
                proc.kill()
                killed = True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    return killed


def block_process_network(process_path):
    rule_name = f"BLOCK_PROCESS_{process_path.split('\\')[-1]}"

    for direction in ["out", "in"]:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"program={process_path}",
            "enable=yes"
        ]
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True,
            encoding="utf-8", errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        if result.returncode != 0:
            return False

    return True


def block_ip(ip_address):
    """
    원격 IP의 인바운드/아웃바운드 통신을 모두 차단한다.
    """

    if not ip_address:
        return False

    ip_address = str(ip_address).strip()

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        print(f"[IP 차단 실패] 잘못된 IP 주소: {ip_address}")
        return False

    safe_rule_ip = ip_address.replace(":", "_")

    rules = [
        (f"BLOCK_IP_{safe_rule_ip}_IN", "in"),
        (f"BLOCK_IP_{safe_rule_ip}_OUT", "out"),
    ]

    all_success = True

    for rule_name, direction in rules:
        # 같은 이름의 기존 규칙 제거
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={rule_name}",
            ],
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip_address}",
            "enable=yes",
            "profile=any",
        ]

        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

        if result.returncode != 0:
            all_success = False
            print(
                f"[IP 차단 실패] IP={ip_address}, "
                f"방향={direction}, 오류={result.stderr}"
            )
        else:
            print(f"[IP 차단 성공] IP={ip_address}, 방향={direction}")

    return all_success


def isolate_ip(ip_address):
    cmd = [
        "route", "add", ip_address,
        "mask", "255.255.255.255",
        "0.0.0.0"
    ]
    result = subprocess.run(
        cmd, shell=False, capture_output=True, text=True,
        encoding="utf-8", errors="ignore",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    return result.returncode == 0


def get_process_name(process_path):
    if process_path:
        return process_path.split("\\")[-1]
    return ""

def is_blockable_process_path(process_path):
    """
    실제 실행 파일 경로인 경우에만 프로세스 차단을 수행한다.
    System, svchost.exe 같은 핵심 프로세스는 자동 종료하지 않는다.
    """

    if not process_path:
        return False

    process_path = str(process_path).strip().strip('"')
    process_name = get_process_name(process_path).lower()

    protected_processes = {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "winlogon.exe",
    }

    if process_name in protected_processes:
        return False

    if "\\" not in process_path:
        return False

    if not process_name.endswith(".exe"):
        return False

    return True

def manual_response(process_path, destination_ip):
    """수동 대응 - 프로세스 또는 원격 IP 차단"""

    response_methods = []

    process_blocked = False
    ip_blocked = False

    if is_blockable_process_path(process_path):
        process_blocked = block_process_network(process_path)

        if process_blocked:
            kill_process(process_path)

    if destination_ip:
        ip_blocked = block_ip(destination_ip)

    if process_blocked and ip_blocked:
        response_methods.append("프로세스/IP 차단")

    elif process_blocked:
        response_methods.append("프로세스 차단")

    elif ip_blocked:
        response_methods.append("IP 차단")

    else:
        response_methods.append("차단 실패")

    status = (
        "처리 완료"
        if process_blocked or ip_blocked
        else "처리 실패"
    )

    return response_methods, status


def response_by_risk(
    risk_level,
    process_path=None,
    destination_ip=None
):
    if risk_level == "Low":
        return None

    response_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    process_name = get_process_name(process_path)

    response_methods = []
    status = "처리 완료"

    if risk_level == "Medium":
        response_methods.append("수동 대응 필요")
        status = "대기 중"

    elif risk_level == "High":
        process_blocked = False
        ip_blocked = False

        # 실제 실행 파일이며 시스템 핵심 프로세스가 아닌 경우만 차단
        if is_blockable_process_path(process_path):
            process_blocked = block_process_network(process_path)

            if process_blocked:
                kill_process(process_path)

        # 프로세스 경로가 없어도 공격자 IP가 있으면 IP 차단 수행
        if destination_ip:
            ip_blocked = block_ip(destination_ip)

        if process_blocked and ip_blocked:
            response_methods.append("프로세스/IP 차단")

        elif process_blocked:
            response_methods.append("프로세스 차단")

        elif ip_blocked:
            response_methods.append("IP 차단")

        else:
            response_methods.append("차단 실패")

        status = (
            "처리 완료"
            if process_blocked or ip_blocked
            else "처리 실패"
        )

    response_result = {
        "대응 시간": response_time,
        "위험도": risk_level,
        "프로세스 이름": process_name,
        "대응 방법": ", ".join(response_methods),
        "대응 현황": status,
        "process_path": process_path,
        "destination_ip": destination_ip,
    }

    return response_result

def load_and_respond(on_time=None):
    """sysmon_logs DB에서 읽어서 대응 실행, 결과를 DB에 저장"""

    db = SessionLocal()

    try:
        # 중복 체크용 set (DB에서 기존 결과 불러오기)
        existing = db.query(ResponseResult).all()
        processed_set = set(
            (r.process_path, r.destination_ip)
            for r in existing
        )

        # sysmon_logs에서 ai_risk가 Critical 또는 High인 것만 가져오기
        query = db.query(SysmonLog).filter(
            SysmonLog.ai_risk.in_(["Critical", "High"])
        )

        # ON 시간 이후 로그만 가져오기
        if on_time:
            query = query.filter(SysmonLog.recv_time > on_time)

        logs = query.all()

        for log in logs:
            process_path = log.process_path
            destination_ip = log.destination_ip
            key = (process_path, destination_ip)

            if key in processed_set:
                continue

            # ai_risk에 따라 위험도 결정
            if log.ai_risk == "Critical":
                risk_level = "High"
            elif log.ai_risk == "High":
                risk_level = "Medium"
            else:
                risk_level = "Low"

            result = response_by_risk(
                risk_level=risk_level,
                process_path=process_path,
                destination_ip=destination_ip
            )

            if result:
                db.add(ResponseResult(
                    response_time   = datetime.strptime(result["대응 시간"], "%Y-%m-%d %H:%M:%S"),
                    risk_level      = result["위험도"],
                    process_name    = result["프로세스 이름"],
                    process_path    = result["process_path"],
                    destination_ip  = result["destination_ip"],
                    response_method = result["대응 방법"],
                    status          = result["대응 현황"]
                ))
                processed_set.add(key)

        db.commit()

    finally:
        db.close()


def main():
    print("자동 대응 모듈 시작")
    while True:
        try:
            toggle = load_toggle_state()
            auto_response = toggle.get("auto_response", True)
            on_time = toggle.get("on_time", None)

            if auto_response:
                print("자동 대응 실행 중...")
                load_and_respond(on_time=on_time)
            else:
                print("자동 대응 중지")

            time.sleep(5)

        except KeyboardInterrupt:
            print("자동 대응 종료")
            break
        except Exception as e:
            print("[오류]", e)


if __name__ == "__main__":
    main()