import streamlit as st
import pandas as pd
import datetime

# 1. 페이지 설정
st.set_page_config(
    page_title="EDR Analyzer",
    layout="wide",
    initial_sidebar_state="expanded"
)

# UI 숨기기 및 AhnLab 스타일 다크 테마
st.markdown("""
    <style>
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    .main { background-color: #0f172a; color: #f8fafc; }
    .stMetric { background-color: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
    
    /* 헤더 바 스타일 */
    .header-bar {
        background-color: #1a2942;
        padding: 12px 20px;
        border-radius: 0px;
        border-bottom: 1px solid #334155;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }
    
    .header-left {
        display: flex;
        align-items: center;
        gap: 30px;
    }
    
    .header-title {
        color: #f8fafc;
        font-weight: bold;
        font-size: 14px;
        margin: 0;
        white-space: nowrap;
    }
    
    .header-nav {
        display: flex;
        gap: 15px;
    }
    
    .header-time-filter {
        display: flex;
        gap: 8px;
        align-items: center;
    }
    
    .header-right {
        display: flex;
        align-items: center;
        gap: 15px;
        color: #94a3b8;
        font-size: 12px;
        white-space: nowrap;
    }
    
    /* 내비게이션 버튼 스타일 */
    .nav-btn {
        background-color: transparent;
        border: none;
        color: #94a3b8;
        font-size: 12px;
        cursor: pointer;
        padding: 4px 0;
        white-space: nowrap;
    }
    
    .nav-btn:hover {
        color: #f8fafc;
    }
    
    /* 시간 필터 버튼 스타일 */
    .time-btn {
        background-color: transparent;
        border: 1px solid #334155;
        color: #94a3b8;
        font-size: 11px;
        padding: 5px 10px;
        border-radius: 4px;
        cursor: pointer;
        white-space: nowrap;
    }
    
    .time-btn:hover {
        border-color: #94a3b8;
        color: #f8fafc;
    }
    
    .time-btn.active {
        border-color: #60a5fa;
        color: #60a5fa;
        background-color: rgba(96, 165, 250, 0.1);
    }
    
    /* 버튼 메뉴 스타일 */
    .stButton>button {
        border: none;
        background-color: transparent;
        color: #94a3b8;
        font-weight: normal;
        font-size: 12px;
        padding: 4px 8px;
        border-radius: 0px;
        height: auto;
    }
    .stButton>button:hover { 
        color: #f8fafc;
        background-color: transparent;
    }
    </style>
    """, unsafe_allow_html=True)

# 2. 메뉴 상태 관리
if 'menu' not in st.session_state:
    st.session_state.menu = "대시보드"
if 'selected_period' not in st.session_state:
    st.session_state.selected_period = "최근 24시간"

# 3. 헤더 - 첫 번째 행
st.markdown('<div style="background-color: #1a2942; padding: 10px 20px; margin: -20px -20px 0 -20px; border-bottom: 1px solid #334155;">', unsafe_allow_html=True)

header_row1 = st.columns([1, 4, 1.5])

# 좌측: 데이터셋 설정 드롭다운
with header_row1[0]:
    st.markdown('<div style="padding: 8px 0;"><small>🖥️ 데이터셋 설정 ▼</small></div>', unsafe_allow_html=True)

# 중앙: 타이틀 및 메뉴 아이콘
with header_row1[1]:
    st.markdown('<div style="text-align: center; padding: 8px 0;"><b style="font-size: 14px;">AhnLab EDR Analyzer</b></div>', unsafe_allow_html=True)

# 우측: 시간 + 드롭다운 + 사용자
with header_row1[2]:
    right_cols = st.columns([2, 0.4, 0.4])
    with right_cols[0]:
        current_time = datetime.datetime.now().strftime('%Y %m %d %H:%M:%S')
        st.markdown(f'<div style="text-align: right; font-size: 11px; color: #94a3b8;">10초 터터</div><div style="text-align: right; font-size: 11px; color: #94a3b8;">{current_time}</div>', unsafe_allow_html=True)
    with right_cols[1]:
        st.markdown('<div style="text-align: center; padding: 8px 0; font-size: 18px;">▼</div>', unsafe_allow_html=True)
    with right_cols[2]:
        st.markdown('<div style="text-align: center; padding: 4px 8px; background-color: #334155; border-radius: 50%; width: 30px; height: 30px; line-height: 22px; color: #60a5fa; font-weight: bold; font-size: 14px;">K</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# 4. 헤더 - 두 번째 행
st.markdown('<div style="background-color: #1a2942; padding: 12px 20px; margin: 0 -20px 15px -20px; border-bottom: 1px solid #334155;">', unsafe_allow_html=True)

header_row2 = st.columns([1, 3, 1.5])

# 좌측: 데이터셋 설정 드롭다운
with header_row2[0]:
    st.markdown('<div style="padding: 8px 0;"><small>🖥️ 데이터셋 설정 ▼</small></div>', unsafe_allow_html=True)

# 중앙: 시간별 필터
with header_row2[1]:
    time_cols = st.columns(4)
    periods = ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"]
    
    with time_cols[0]:
        if st.button(periods[0], use_container_width=True, key="period_0"):
            st.session_state.selected_period = periods[0]
    with time_cols[1]:
        if st.button(periods[1], use_container_width=True, key="period_1"):
            st.session_state.selected_period = periods[1]
    with time_cols[2]:
        if st.button(periods[2], use_container_width=True, key="period_2"):
            st.session_state.selected_period = periods[2]
    with time_cols[3]:
        if st.button(periods[3], use_container_width=True, key="period_3"):
            st.session_state.selected_period = periods[3]

# 우측: 현재 시간
with header_row2[2]:
    current_time = datetime.datetime.now().strftime('%Y %m %d %H:%M:%S')
    st.markdown(f'<div style="text-align: right; font-size: 11px; color: #94a3b8; padding: 8px 0;">{current_time}</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)

# --- [메인 대시보드] ---
if st.session_state.menu == "대시보드":
    
    st.write("")

    # 핵심 현황 지표
    st.markdown("### 위험 현황")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("위험 현황", "7", "신규 7")
    m2.metric("확인 중", "2", "▲ 1")
    m3.metric("확인 완료", "15", "▼ 2")
    m4.metric("예외 처리", "3", "유예 중")

    st.write("")

    # 6. 메인 레이아웃 - 위협 탐지 현황과 자동 대응
    left_col, right_col = st.columns([6, 4])

    with left_col:
        st.markdown("### 최근 탐지 위협")
        log_data = pd.DataFrame([
            {"날짜": "2026-04-10 17:41:49", "위험도": "H", "의심 위협": "Ransomware.Generic", "프로세스": "powershell.exe", "상태": "신규"},
            {"날짜": "2026-04-10 17:41:49", "위험도": "H", "의심 위협": "Trojan.Win32.Generic", "프로세스": "powershell.exe", "상태": "신규"},
            {"날짜": "2026-04-10 17:41:49", "위험도": "M", "의심 위협": "PUP.Generic", "프로세스": "powershell.exe", "상태": "신규"},
            {"날짜": "2026-04-10 17:41:49", "위험도": "M", "의심 위협": "Backdoor.Generic", "프로세스": "powershell.exe", "상태": "신규"},
            {"날짜": "2026-04-10 17:41:49", "위험도": "L", "의심 위협": "Adware.Generic", "프로세스": "powershell.exe", "상태": "차단"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True)

    with right_col:
        st.markdown("### 자동 대응 설정")
        with st.container(border=True):
            auto_block = st.toggle("실시간 자동 차단 활성화", value=True)
            st.write("---")
            
            # 확장 가능한 대응 설정들
            with st.expander("🔒 IP 차단", expanded=False):
                st.write("**IP 차단 설정**")
                st.write("차단된 IP 주소 목록:")
                ip_data = pd.DataFrame([
                    {"IP 주소": "192.168.1.100", "차단 시간": "2026-04-10 17:40:00", "사유": "의심 연결 시도"},
                    {"IP 주소": "10.0.0.50", "차단 시간": "2026-04-10 16:30:15", "사유": "C2 통신 감지"},
                ])
                st.dataframe(ip_data, use_container_width=True, hide_index=True)

            with st.expander("🌐 네트워크 차단", expanded=False):
                st.write("**네트워크 차단 설정**")
                st.write("차단된 네트워크 연결:")
                net_data = pd.DataFrame([
                    {"프로토콜": "TCP", "포트": "4444", "차단 시간": "2026-04-10 17:39:22", "사유": "알려진 악성 포트"},
                    {"프로토콜": "UDP", "포트": "53", "차단 시간": "2026-04-10 15:22:10", "사유": "DNS 터널링 감지"},
                ])
                st.dataframe(net_data, use_container_width=True, hide_index=True)

            with st.expander("⚙️ 프로세스 차단", expanded=False):
                st.write("**프로세스 차단 설정**")
                st.write("차단된 프로세스 목록:")
                proc_data = pd.DataFrame([
                    {"프로세스": "malware.exe", "PID": "5432", "차단 시간": "2026-04-10 17:38:45", "사유": "악성코드 감지"},
                    {"프로세스": "suspicious.exe", "PID": "3214", "차단 시간": "2026-04-10 14:15:30", "사유": "행동 기반 탐지"},
                ])
                st.dataframe(proc_data, use_container_width=True, hide_index=True)

            st.write("---")
            st.markdown("**최근 차단 기록**")
            st.code("""
[2026-04-10 17:41:49] ✓ powershell.exe 프로세스 격리 완료
[2026-04-10 17:40:15] ✓ IP 192.168.1.100 차단 완료
[2026-04-10 17:39:22] ✓ TCP 포트 4444 네트워크 차단
[2026-04-10 17:38:45] ✓ malware.exe 프로세스 강제 종료
[2026-04-10 16:30:15] ✓ 의심 파일 격리 실행
[2026-04-10 15:22:10] ✓ DNS 터널링 연결 차단
[2026-04-10 14:15:30] ✓ 의심 레지스트리 변경 차단
[2026-04-10 13:45:00] ✓ 파일 실행 권한 제거 완료
            """, language="bash")
            
            if st.button("전체 로그 보기", use_container_width=True):
                st.toast("상세 로그 페이지로 이동합니다.")

# --- [기타 페이지] ---
else:
    st.markdown(f"## {st.session_state.menu}")
    st.info(f"{st.session_state.menu} 모듈 분석 데이터 대기 중...")
    if st.button("대시보드 복귀"):
        st.session_state.menu = "대시보드"
        st.rerun()

# 7. 사이드바
with st.sidebar:
    st.markdown("### EDR Analyzer")
    st.write(f"접속: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.write("---")
    st.caption("v1.2.0 | Enterprise Mode")