import subprocess
import psutil
import json
from datetime import datetime
from backend.database import SessionLocal, ResponseResult


def kill_process(process_path):
    process_name = get_process_name(process_path)
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] == process_name:
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


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
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding="utf-8", errors="ignore")

        if result.returncode != 0:
            return False

    return True


def block_ip(ip_address):
    rule_name = f"BLOCK_IP_{ip_address}"

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=out",
        "action=block",
        f"remoteip={ip_address}",
        "enable=yes"
    ]

    result = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    return result.returncode == 0


def isolate_ip(ip_address):
    cmd = [
        "route", "add", ip_address,
        "mask", "255.255.255.255",
        "0.0.0.0"
    ]
    result = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    return result.returncode == 0


def get_process_name(process_path):
    if process_path:
        return process_path.split("\\")[-1]
    return ""


def manual_response(process_path, destination_ip):
    """수동 대응 - Medium일 때 버튼 누르면 High 수준으로 대응"""
    response_methods = []
    status = "처리 완료"

    if process_path:
        success = block_process_network(process_path)
        kill_process(process_path)
        response_methods.append("프로세스 네트워크 차단")

        if not success:
            status = "처리 실패"
    else:
        status = "처리 실패"
        response_methods.append("프로세스 경로 없음")

    if destination_ip:
        success = block_ip(destination_ip)
        response_methods.append("IP 차단")

        if not success:
            status = "처리 실패"

        success = isolate_ip(destination_ip)
        response_methods.append("IP 격리")

        if not success:
            status = "처리 실패"

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

        if process_path:
            success = block_process_network(process_path)
            kill_process(process_path)
            response_methods.append("프로세스 네트워크 차단")

            if not success:
                status = "처리 실패"

        else:
            status = "처리 실패"
            response_methods.append("프로세스 경로 없음")

        if destination_ip:
            success = block_ip(destination_ip)
            response_methods.append("IP 차단")

            if not success:
                status = "처리 실패"

            success = isolate_ip(destination_ip)
            response_methods.append("IP 격리")

            if not success:
                status = "처리 실패"

        else:
            response_methods.append("차단된 IP 없음")

    response_result = {
        "대응 시간": response_time,
        "위험도": risk_level,
        "프로세스 이름": process_name,
        "대응 방법": ", ".join(response_methods),
        "대응 현황": status,
        "process_path": process_path,
        "destination_ip": destination_ip
    }

    return response_result


def load_and_respond():
    """test_data.json 읽어서 대응 실행, 결과를 DB에 저장"""

    db = SessionLocal()

    try:
        # 중복 체크용 set (DB에서 기존 결과 불러오기)
        existing = db.query(ResponseResult).all()
        processed_set = set(
            (r.process_path, r.destination_ip)
            for r in existing
        )

        # test_data.json 읽기
        try:
            with open("test_data.json", "r", encoding="utf-8") as f:
                test_data = json.load(f)
        except FileNotFoundError:
            return

        for item in test_data:
            process_path = item.get("process_path")
            destination_ip = item.get("destination_ip")
            key = (process_path, destination_ip)

            if key in processed_set:
                continue

            result = response_by_risk(
                risk_level=item["risk_level"],
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


if __name__ == "__main__":
    load_and_respond()