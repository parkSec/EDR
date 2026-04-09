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
    /* 버튼 메뉴 스타일 */
    .stButton>button {
        border: none;
        background: none;
        color: #94a3b8;
        font-weight: bold;
        font-size: 16px;
    }
    .stButton>button:hover { color: #f8fafc; }
    </style>
    """, unsafe_allow_html=True)

# 2. 메뉴 상태 관리
if 'menu' not in st.session_state:
    st.session_state.menu = "대시보드"

# 3. 상단 메뉴바 (텍스트 중심)
m_col1, m_col2, m_col3, m_col4, m_col5, m_empty = st.columns([1,1,1,1,1,5])
with m_col1:
    if st.button("대시보드"): st.session_state.menu = "대시보드"
with m_col2:
    if st.button("분석"): st.session_state.menu = "분석"
with m_col3:
    if st.button("이벤트"): st.session_state.menu = "이벤트"
with m_col4:
    if st.button("정책"): st.session_state.menu = "정책"
with m_col5:
    if st.button("보고서"): st.session_state.menu = "보고서"

st.markdown("---")

# --- [메인 대시보드] ---
if st.session_state.menu == "대시보드":
    
    # 4. 상단 컨트롤 (텍스트 위주)
    t_col1, t_col2 = st.columns([7, 3])
    with t_col1:
        st.markdown(f"## {st.session_state.menu}")
    with t_col2:
        time_filter = st.selectbox(
            "조회 범위", 
            ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"], 
            label_visibility="collapsed"
        )

    # 5. 핵심 현황 지표
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("위험 현황", "7", "신규 7")
    m2.metric("확인 중", "0")
    m3.metric("확인 완료", "0")
    m4.metric("예외 처리", "0")

    st.write("")

    # 6. 메인 레이아웃
    left_col, right_col = st.columns([6, 4])

    with left_col:
        st.markdown("### 최근 탐지 위협")
        log_data = pd.DataFrame([
            {"날짜": "2026-04-09 20:22:12", "위험도": "H", "프로세스": "powershell.exe", "상태": "신규"},
            {"날짜": "2026-04-09 20:18:44", "위험도": "M", "프로세스": "cmd.exe", "상태": "신규"},
            {"날짜": "2026-04-09 20:15:21", "위험도": "L", "프로세스": "explorer.exe", "상태": "신규"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True)

    with right_col:
        st.markdown("### 자동 대응 설정")
        with st.container(border=True):
            auto_block = st.toggle("실시간 자동 차단 활성화", value=True)
            st.write("---")
            st.markdown("**최근 차단 기록**")
            st.code("""
[SYSTEM] 20:22:12 - powershell.exe 차단 완료
[SYSTEM] 20:18:44 - 의심 IP 연결 강제 종료
[SYSTEM] 20:15:00 - AI 분석 기반 격리 수행
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