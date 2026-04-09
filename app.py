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

# --- [1, 2번 설정 코드는 유지합니다] ---

# 기존 스타일 정의 아래에 이어서 적용하거나 덮어씌워주세요.
st.markdown("""
    <style>
    /* 상단 여백을 완전히 제거하여 화면 끝에 붙임 */
    .block-container {
        padding-top: 0rem !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
        max-width: 100% !important;
    }
    
    /* 커스텀 헤더 전체 영역 */
    .custom-header-container {
        margin: 0 -2rem 2rem -2rem; /* 좌우 여백 상쇄 및 하단 여백 추가 */
    }

    /* 1열: 메인 네비게이션 */
    .top-nav {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 30px;
        background-color: #21293c; /* AhnLab 테마 메인 네이비 색상 */
        border-bottom: 1px solid #2d3748;
    }
    
    .nav-left { display: flex; align-items: center; gap: 50px; }
    
    .logo {
        color: #ffffff;
        font-size: 19px;
        font-weight: bold;
        font-family: 'Arial', sans-serif;
    }
    
    .menu-items { display: flex; gap: 35px; font-size: 14px; }
    
    .menu-item {
        color: #8b95a5;
        display: flex;
        align-items: center;
        gap: 8px;
        cursor: pointer;
        font-weight: 500;
    }
    
    .menu-item.active {
        color: #60a5fa; /* 활성화된 메뉴 텍스트 색상 */
        font-weight: bold;
    }
    
    .nav-right { display: flex; gap: 12px; align-items: center; }
    
    .profile-icon {
        width: 32px; height: 32px;
        background-color: #60a5fa; color: white;
        border-radius: 50%; display: flex;
        justify-content: center; align-items: center;
        font-weight: bold; font-size: 14px;
    }
    
    .help-icon {
        width: 32px; height: 32px;
        background-color: #3b455b; color: #a0aec0;
        border-radius: 50%; display: flex;
        justify-content: center; align-items: center;
        font-weight: bold; font-size: 14px;
    }

    /* 2열: 서브 네비게이션 (시간 필터 등) */
    .sub-nav {
        display: flex; justify-content: space-between; align-items: center;
        padding: 12px 30px;
        background-color: #21293c;
        border-bottom: 1px solid #2d3748;
    }
    
    .dashboard-setting {
        color: #8b95a5; font-size: 13px;
        display: flex; align-items: center; gap: 8px;
    }
    
    .time-filter-group {
        display: flex;
        background-color: #171d2b; /* 둥근 배경색 */
        border-radius: 20px;
        padding: 4px;
    }
    
    .time-btn {
        color: #8b95a5; font-size: 13px;
        padding: 6px 20px; border-radius: 16px;
    }
    
    .time-btn.active {
        background-color: #2b3b5c; color: #60a5fa; /* 활성화된 버튼 배경/글자 */
    }
    
    .status-info {
        color: #8b95a5; font-size: 13px;
        display: flex; align-items: center; gap: 12px;
    }
    
    .refresh-btn {
        background-color: #3182f6; color: white;
        border-radius: 50%; width: 24px; height: 24px;
        display: flex; justify-content: center; align-items: center;
    }
    </style>
""", unsafe_allow_html=True)

# --- 3 & 4. 상단바 렌더링 (HTML 기반 병합) ---
current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

st.markdown(f"""
    <div class="custom-header-container">
        <div class="top-nav">
            <div class="nav-left">
                <div class="logo">AhnLab EDR Analyzer</div>
                <div class="menu-items">
                    <div class="menu-item active">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path></svg>
                        대시보드
                    </div>
                    <div class="menu-item">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line></svg>
                        분석
                    </div>
                    <div class="menu-item">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="8" y1="6" x2="21" y2="6"></line><line x1="8" y1="12" x2="21" y2="12"></line><line x1="8" y1="18" x2="21" y2="18"></line><line x1="3" y1="6" x2="3.01" y2="6"></line><line x1="3" y1="12" x2="3.01" y2="12"></line></svg>
                        이벤트
                    </div>
                    <div class="menu-item">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path></svg>
                        정책 ↗
                    </div>
                    <div class="menu-item">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle></svg>
                        보고서 ↗
                    </div>
                </div>
            </div>
            <div class="nav-right">
                <div class="profile-icon">K</div>
                <div class="help-icon">?</div>
            </div>
        </div>

        <div class="sub-nav">
            <div class="dashboard-setting">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                대시보드 설정 ⌄
            </div>
            <div class="time-filter-group">
                <div class="time-btn active">최근 24시간</div>
                <div class="time-btn">최근 7일</div>
                <div class="time-btn">최근 14일</div>
                <div class="time-btn">최근 30일</div>
            </div>
            <div class="status-info">
                {current_time} &nbsp;&nbsp; 10초 마다 ⌄
                <div class="refresh-btn">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M21 2v6h-6"></path><path d="M3 12a9 9 0 0 1 15-6.7L21 8"></path><path d="M3 22v-6h6"></path><path d="M21 12a9 9 0 0 1-15 6.7L3 16"></path></svg>
                </div>
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

# --- [이후 메인 대시보드 코드를 그대로 유지하세요] ---

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