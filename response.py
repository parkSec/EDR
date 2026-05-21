import subprocess
import psutil
from datetime import datetime


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


def get_process_name(process_path):
    if process_path:
        return process_path.split("\\")[-1]
    return ""


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

        if process_path:
            success = block_process_network(process_path)
            kill_process(process_path)
            response_methods.append("프로세스 네트워크 차단")

            if not success:
                status = "처리 실패"

        else:
            status = "처리 실패"
            response_methods.append("프로세스 경로 없음")

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

        else:
            response_methods.append("차단된 IP 없음")

    response_result = {
        "대응 시간": response_time,
        "위험도": risk_level,
        "프로세스 이름": process_name,
        "대응 방법": ", ".join(response_methods),
        "차단된 IP": destination_ip if risk_level == "High" and destination_ip else "차단된 IP 없음",
        "대응 현황": status
    }

    return response_result