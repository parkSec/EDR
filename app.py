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
    /* 상단 네비게이션 바 스타일 */
    .nav-bar {
        background-color: #1e293b;
        padding: 15px 20px;
        border-radius: 8px;
        margin-bottom: 15px;
        border: 1px solid #334155;
    }
    .nav-title {
        color: #f8fafc;
        font-weight: bold;
        font-size: 18px;
        margin-bottom: 10px;
    }
    /* 버튼 메뉴 스타일 */
    .stButton>button {
        border: 1px solid #334155;
        background-color: #0f172a;
        color: #94a3b8;
        font-weight: bold;
        font-size: 14px;
        padding: 8px 16px;
        border-radius: 6px;
    }
    .stButton>button:hover { 
        color: #f8fafc;
        background-color: #334155;
    }
    /* 시간 필터 스타일 */
    .time-filter-label {
        color: #94a3b8;
        font-size: 12px;
        font-weight: bold;
        margin-bottom: 8px;
    }
    </style>
    """, unsafe_allow_html=True)

# 2. 메뉴 상태 관리
if 'menu' not in st.session_state:
    st.session_state.menu = "대시보드"

# 3. 상단 네비게이션 바
st.markdown('<div class="nav-bar">', unsafe_allow_html=True)
st.markdown('<div class="nav-title">AhnLab EDR Analyzer</div>', unsafe_allow_html=True)
m_col1, m_col2, m_col3, m_col4, m_col5, m_empty = st.columns([1,1,1,1,1,5])
with m_col1:
    if st.button("대시보드", use_container_width=True): st.session_state.menu = "대시보드"
with m_col2:
    if st.button("분석", use_container_width=True): st.session_state.menu = "분석"
with m_col3:
    if st.button("이벤트", use_container_width=True): st.session_state.menu = "이벤트"
with m_col4:
    if st.button("정책", use_container_width=True): st.session_state.menu = "정책"
with m_col5:
    if st.button("보고서", use_container_width=True): st.session_state.menu = "보고서"

st.markdown('</div>', unsafe_allow_html=True)

# 4. 시간별 조회 필터
st.markdown('<div class="time-filter-label">조회 범위</div>', unsafe_allow_html=True)
t_col1, t_col2, t_col3, t_col4, t_empty = st.columns([1,1,1,1,5])
time_periods = ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"]
selected_period = None
with t_col1:
    if st.button("최근 24시간", use_container_width=True):
        selected_period = "최근 24시간"
with t_col2:
    if st.button("최근 7일", use_container_width=True):
        selected_period = "최근 7일"
with t_col3:
    if st.button("최근 14일", use_container_width=True):
        selected_period = "최근 14일"
with t_col4:
    if st.button("최근 30일", use_container_width=True):
        selected_period = "최근 30일"

if 'selected_period' not in st.session_state:
    st.session_state.selected_period = "최근 24시간"
if selected_period:
    st.session_state.selected_period = selected_period

st.markdown("---")

# --- [메인 대시보드] ---
if st.session_state.menu == "대시보드":
    
    st.markdown(f"## {st.session_state.menu}")
    st.markdown(f"**선택된 기간: {st.session_state.selected_period}**")
    st.write("")

    # 5. 핵심 현황 지표
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