import streamlit as st
import pandas as pd
import datetime

# 1. 페이지 설정
st.set_page_config(
    page_title="AhnLab Style EDR Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# UI 숨기기 및 스타일 설정
st.markdown("""
    <style>
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    .main { background-color: #0f172a; color: #f8fafc; }
    .stMetric { background-color: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; }
    </style>
    """, unsafe_allow_html=True)

# 2. 메뉴 클릭 상태 관리 (세션 상태)
if 'menu' not in st.session_state:
    st.session_state.menu = "대시보드"

# 3. 상단 네비게이션 바 (안랩 사진 스타일)
# 버튼을 한 줄로 배치하여 메뉴처럼 보이게 만듭니다.
m_col1, m_col2, m_col3, m_col4, m_col5, m_empty = st.columns([1,1,1,1,1,5])
with m_col1:
    if st.button("🏠 대시보드"): st.session_state.menu = "대시보드"
with m_col2:
    if st.button("🔍 분석"): st.session_state.menu = "분석"
with m_col3:
    if st.button("📅 이벤트"): st.session_state.menu = "이벤트"
with m_col4:
    if st.button("🛡️ 정책"): st.session_state.menu = "정책"
with m_col5:
    if st.button("📋 보고서"): st.session_state.menu = "보고서"

st.write("---")

# --- [메인 대시보드 로직] ---
if st.session_state.menu == "대시보드":
    
    # 4. 시간 필터 (최근 24시간, 7일 등)
    t_col1, t_col2 = st.columns([7, 3])
    with t_col1:
        st.markdown(f"### 📊 {st.session_state.menu}")
    with t_col2:
        time_filter = st.segmented_control(
            "조회 범위", 
            ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"], 
            default="최근 24시간"
        )

    # 5. 핵심 지표
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("탐지된 총 위협", "12", "2 New")
    m2.metric("VirusTotal 탐지", "5", "Clean")
    m3.metric("AI 위험도", "High", "주의")
    m4.metric("보호 자산", "1", "Local")

    st.write("---")

    # 6. 메인 레이아웃 (좌: 로그, 우: 자동차단 및 기록)
    left_col, right_col = st.columns([6, 4])

    with left_col:
        st.subheader("📝 실시간 보안 이벤트 현황")
        log_data = pd.DataFrame([
            {"시간": "20:22:12", "이벤트": "악성코드 의심", "위험도": "Critical", "내용": "unknown_payload.exe 탐지"},
            {"시간": "20:18:44", "이벤트": "네트워크 접속", "위험도": "Medium", "내용": "45.122.x.x 접속 시도"},
            {"시간": "20:15:21", "이벤트": "프로세스 생성", "위험도": "Low", "내용": "explorer.exe 실행"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True)

    with right_col:
        st.subheader("🤖 AI 자동차단 설정")
        with st.container(border=True):
            auto_block = st.toggle("자동 차단 시스템 가동", value=True)
            block_target = st.selectbox("차단 강도 설정", ["Critical만 차단", "Medium 이상 차단", "모든 의심 활동 차단"])
            
            st.write("---")
            st.markdown("**🛡️ 최근 자동 차단 기록**")
            # 차단 기록을 리스트 형태로 보여줌
            st.code("""
[2026-04-09 20:22:12] IP 45.122.x.x 차단 완료
[2026-04-09 20:15:00] unknown_payload.exe 프로세스 강제 종료
[2026-04-09 19:40:22] 비정상 레지스트리 접근 차단
            """, language="bash")
            
            if st.button("전체 기록 보기", use_container_width=True):
                st.info("상세 로그 페이지로 이동합니다.")

# --- [다른 메뉴 선택 시 화면] ---
else:
    st.subheader(f"📂 {st.session_state.menu} 페이지")
    st.info(f"현재 {st.session_state.menu} 모듈은 준비 중입니다. 곧 데이터가 연동될 예정입니다.")
    if st.button("대시보드로 돌아가기"):
        st.session_state.menu = "대시보드"
        st.rerun()

# 7. 사이드바 및 푸터
with st.sidebar:
    st.title("EDR Control")
    st.write(f"**현재 모드:** {st.session_state.menu}")
    st.write(f"**필터:** {time_filter if 'time_filter' in locals() else 'N/A'}")
    st.write("---")
    st.caption("© 2026 EDR Project Team")