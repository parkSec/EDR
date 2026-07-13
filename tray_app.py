"""
tray_app.py - EDR 시스템 트레이 앱
트레이 아이콘으로 에이전트 시작/중지, 대시보드 열기를 제공한다.
"""

import threading
import subprocess
import webbrowser
import time
import socket
import sys
import os
import tkinter as tk

import pystray

from PIL import Image, ImageDraw
import requests

from collector.sysmon_collector import collect_all_logs, apply_alert_policy
from response import response_by_risk

try:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "xgboost"))
    from threat_predictor import ThreatPredictor
    _predictor = ThreatPredictor()
    _PREDICTOR_READY = _predictor.is_ready()
except Exception:
    _predictor = None
    _PREDICTOR_READY = False

# 대시보드 자식 프로세스로 재실행된 경우 (자기 자신의 EXE를 재호출)
_IS_DASHBOARD_CHILD = "--run-dashboard" in sys.argv

def _ask_server_ip() -> str:
    BG       = "#0d1117"
    PANEL    = "#161b22"
    ACCENT   = "#0078d4"
    FG       = "#e6edf3"
    FG_SUB   = "#8b949e"
    BORDER   = "#30363d"
    BTN_HOV  = "#1f6feb"

    result = {"ip": None}

    root = tk.Tk()
    root.title("EDR Agent")
    root.configure(bg=BG)
    root.resizable(False, False)

    W, H = 400, 260
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"{W}x{H}+{(sw-W)//2}+{(sh-H)//2}")
    root.overrideredirect(True)

    # ── 타이틀바
    bar = tk.Frame(root, bg=PANEL, height=36)
    bar.pack(fill="x")
    tk.Label(bar, text="  🛡  EDR Agent — 서버 연결",
             bg=PANEL, fg=FG, font=("Segoe UI", 10, "bold")).pack(side="left", pady=8)
    tk.Button(bar, text="✕", bg=PANEL, fg=FG_SUB,
              relief="flat", bd=0, font=("Segoe UI", 11),
              activebackground="#c0392b", activeforeground="white",
              command=sys.exit).pack(side="right", padx=6)

    def _drag_start(e): bar._x, bar._y = e.x, e.y
    def _drag_move(e):  root.geometry(f"+{root.winfo_x()+e.x-bar._x}+{root.winfo_y()+e.y-bar._y}")
    bar.bind("<ButtonPress-1>", _drag_start)
    bar.bind("<B1-Motion>",     _drag_move)

    # ── 본문
    body = tk.Frame(root, bg=BG, padx=30, pady=20)
    body.pack(fill="both", expand=True)

    tk.Label(body, text="서버 IP 주소 입력",
             bg=BG, fg=FG, font=("Segoe UI", 13, "bold")).pack(anchor="w")
    tk.Label(body, text="관리자 PC의 IP 주소를 입력하세요.",
             bg=BG, fg=FG_SUB, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 16))

    entry_frame = tk.Frame(body, bg=BORDER, bd=0)
    entry_frame.pack(fill="x")
    entry = tk.Entry(entry_frame, bg=PANEL, fg=FG, insertbackground=FG,
                     relief="flat", font=("Consolas", 12), bd=8,
                     highlightthickness=0)
    entry.insert(0, "192.168.0.")
    entry.pack(fill="x")
    entry.focus_set()
    entry.icursor("end")

    tk.Label(body, text="예: 192.168.0.10",
             bg=BG, fg=FG_SUB, font=("Segoe UI", 8)).pack(anchor="w", pady=(4, 16))

    def _confirm(e=None):
        val = entry.get().strip()
        if val:
            result["ip"] = val
            root.destroy()

    tk.Button(body, text="연결", bg=ACCENT, fg="white",
              relief="flat", bd=0, font=("Segoe UI", 10, "bold"),
              padx=20, pady=8, cursor="hand2",
              activebackground=BTN_HOV, activeforeground="white",
              command=_confirm).pack(fill="x")

    root.bind("<Return>", _confirm)
    root.bind("<Escape>", lambda e: sys.exit())

    root.mainloop()

    if not result["ip"]:
        sys.exit(0)
    return result["ip"]

SERVER_URL      = "" if _IS_DASHBOARD_CHILD else f"http://{_ask_server_ip()}:8000"
DASHBOARD_PORT  = 8500
INTERVAL_SEC    = 10
MAX_RECORDS     = 100
HOST_IP         = socket.gethostbyname(socket.gethostname())

_agent_running     = False
_agent_thread      = None
_dashboard_started = False
_dashboard_pid     = None



# ── 아이콘 생성 (파란 방패 모양) ─────────────────────────────────────
def _make_icon(active: bool) -> Image.Image:
    size  = 64
    img   = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw  = ImageDraw.Draw(img)
    color = (0, 120, 215) if active else (120, 120, 120)
    # 방패 외곽
    draw.polygon(
        [(size//2, 4), (size-6, 16), (size-6, 38), (size//2, 60), (6, 38), (6, 16)],
        fill=color,
    )
    # 가운데 흰 글자 E
    draw.text((22, 20), "E", fill="white")
    return img


# ── 에이전트 루프 ─────────────────────────────────────────────────────
def _to_payload(log: dict) -> dict:
    return {
        "recv_time":        log.get("recv_time"),
        "gen_time":         log.get("gen_time"),
        "host_ip":          HOST_IP,
        "os_name":          log.get("os_name"),
        "rule_level":       log.get("rule_level"),
        "risk":             log.get("risk"),
        "detect_type":      log.get("detect_type"),
        "tactic_id":        log.get("tactic_id"),
        "tactic_name":      log.get("tactic_name"),
        "technique_id":     log.get("technique_id"),
        "technique_name":   log.get("technique_name"),
        "action_desc":      log.get("action_desc"),
        "process_name":     log.get("process_name"),
        "event_id":         log.get("event_id"),
        "command_line":     log.get("command_line"),
        "destination_ip":   log.get("destination_ip"),
        "destination_port": log.get("destination_port"),
        "query_name":       log.get("query_name"),
        "status":           log.get("status", "신규"),
        "ai_risk":          log.get("ai_risk"),
        "ai_score":         log.get("ai_score"),
    }


def _apply_xgboost(logs: list[dict]) -> list[dict]:
    if not _PREDICTOR_READY or not _predictor:
        return logs
    for log in logs:
        try:
            result = _predictor.predict(log)
            if result.get("success"):
                log["ai_risk"]  = result.get("risk_label", "Unknown")
                log["ai_score"] = round(result.get("probability", 0.0), 4)
        except Exception:
            pass
    return logs


def _agent_loop():
    global _agent_running
    while _agent_running:
        try:
            logs = collect_all_logs()
            if logs:
                logs = _apply_xgboost(logs)
                logs = apply_alert_policy(logs)
                requests.post(
                    f"{SERVER_URL}/logs",
                    json={"logs": [_to_payload(l) for l in logs]},
                    timeout=10,
                )
                for log in logs:
                    risk = log.get("risk", "Low")
                    if risk != "Low":
                        response_by_risk(
                            risk_level     = risk,
                            process_path   = (log.get("command_line") or "").split()[0] or None,
                            destination_ip = log.get("destination_ip") or None,
                        )
        except Exception:
            pass
        time.sleep(INTERVAL_SEC)


# ── 트레이 메뉴 콜백 ─────────────────────────────────────────────────
def _start_agent(icon, item):
    global _agent_running, _agent_thread
    if _agent_running:
        return
    _agent_running = True
    _agent_thread  = threading.Thread(target=_agent_loop, daemon=True)
    _agent_thread.start()
    icon.icon  = _make_icon(True)
    icon.title = "EDR Agent — 실행 중"
    _update_menu(icon)


def _stop_agent(icon, item):
    global _agent_running
    _agent_running = False
    icon.icon  = _make_icon(False)
    icon.title = "EDR Agent — 중지됨"
    _update_menu(icon)


def _run_elevated_tracked(exe_path: str, args: str, base_dir: str):
    """runas로 프로세스를 실행하고 PID를 반환한다 (종료 시 추적용)."""
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFO(ctypes.Structure):
        _fields_ = [
            ("cbSize",       wintypes.DWORD),
            ("fMask",        ctypes.c_ulong),
            ("hwnd",         wintypes.HWND),
            ("lpVerb",       wintypes.LPCWSTR),
            ("lpFile",       wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory",  wintypes.LPCWSTR),
            ("nShow",        ctypes.c_int),
            ("hInstApp",     wintypes.HINSTANCE),
            ("lpIDList",     ctypes.c_void_p),
            ("lpClass",      wintypes.LPCWSTR),
            ("hKeyClass",    wintypes.HANDLE),
            ("dwHotKey",     wintypes.DWORD),
            ("hIcon",        wintypes.HANDLE),
            ("hProcess",     wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040

    sei = SHELLEXECUTEINFO()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = exe_path
    sei.lpParameters = args
    sei.lpDirectory = base_dir
    sei.nShow = 1

    ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(sei))
    if not ok or not sei.hProcess:
        return None

    pid = ctypes.windll.kernel32.GetProcessId(sei.hProcess)
    ctypes.windll.kernel32.CloseHandle(sei.hProcess)
    return pid


def _launch_dashboard_inprocess():
    """자식 프로세스(--run-dashboard)에서 streamlit을 내부 호출로 직접 실행한다.
    외부 시스템 Python에 의존하지 않는다."""
    if getattr(sys, "frozen", False):
        dashboard = os.path.join(sys._MEIPASS, "dashboards", "user_dashboard.py")
    else:
        base = os.path.dirname(os.path.abspath(__file__))
        dashboard = os.path.join(base, "dashboards", "user_dashboard.py")

    idx = sys.argv.index("--run-dashboard")
    forwarded_args = sys.argv[idx + 1:]

    # PyInstaller로 번들되면 streamlit 파일 경로에 site-packages가 없어
    # developmentMode가 자동으로 켜지며 --server.port와 충돌한다. 강제로 끈다.
    os.environ["STREAMLIT_GLOBAL_DEVELOPMENT_MODE"] = "false"

    from streamlit.web import cli as stcli
    sys.argv = ["streamlit", "run", dashboard] + forwarded_args
    stcli.main()


def _open_dashboard(icon, item):
    global _dashboard_started, _dashboard_pid

    if not _dashboard_started:
        # 외부 Python을 찾지 않고 자기 자신(EXE 또는 현재 인터프리터)을 재실행
        if getattr(sys, "frozen", False):
            exe_path = sys.executable
            base_dir = os.path.dirname(sys.executable)
            script_prefix = ""
        else:
            exe_path = sys.executable
            base_dir = os.path.dirname(os.path.abspath(__file__))
            script_prefix = f'"{os.path.abspath(__file__)}" '

        args = f'{script_prefix}--run-dashboard --server.port {DASHBOARD_PORT} --server.headless true -- --server-url {SERVER_URL}'
        pid = _run_elevated_tracked(exe_path, args, base_dir)

        if not pid:
            return  # 실행 실패 시 다음 클릭에서 재시도 가능하도록 플래그를 세우지 않음

        _dashboard_pid = pid
        _dashboard_started = True
        time.sleep(2)

    webbrowser.open(f"http://localhost:{DASHBOARD_PORT}")


def _quit_app(icon, item):
    global _agent_running
    _agent_running = False

    if _dashboard_pid:
        try:
            import psutil
            parent = psutil.Process(_dashboard_pid)
            for child in parent.children(recursive=True):
                child.kill()
            parent.kill()
        except Exception:
            pass

    icon.stop()


def _update_menu(icon):
    icon.menu = pystray.Menu(
        pystray.MenuItem(
            "에이전트 시작",
            _start_agent,
            enabled=lambda item: not _agent_running,
        ),
        pystray.MenuItem(
            "에이전트 중지",
            _stop_agent,
            enabled=lambda item: _agent_running,
        ),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("대시보드 열기", _open_dashboard),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("종료", _quit_app),
    )


# ── Sysmon 시작 ──────────────────────────────────────────────────────
def _start_sysmon():
    try:
        subprocess.run(
            ["sc", "start", "Sysmon64"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


# ── 진입점 ────────────────────────────────────────────────────────────
def main():
    _start_sysmon()
    icon = pystray.Icon(
        name  = "EDR Agent",
        icon  = _make_icon(False),
        title = "EDR Agent — 중지됨",
    )
    _update_menu(icon)
    icon.run()


def _require_admin():
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

if __name__ == "__main__":
    if _IS_DASHBOARD_CHILD:
        _launch_dashboard_inprocess()
    else:
        _require_admin()
        main()
