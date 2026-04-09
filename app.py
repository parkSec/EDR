import streamlit as st
import pandas as pd
import datetime

# 1. 페이지 설정 (넓은 화면 유지)
st.set_page_config(
    page_title="EDR Dashboard v2",
    page_icon="🟢",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 커스텀 CSS: 확 바뀐 느낌을 주기 위해 '해커/터미널(Neon Green)' 테마로 전면 수정!
st.markdown("""
    <style>
    .main { background-color: #000000; font-family: 'Courier New', Courier, monospace; }
    h1, h2, h3, h4, p, div, span, label { color: #00FF00 !important; }
    .stMetric { background-color: #0a0a0a; padding: 15px; border-radius: 0px; border: 1px dashed #00FF00; }
    .stSidebar { background-color: #050505; border-right: 2px solid #00FF00; }
    hr { border-color: #00FF00; }
    .stButton>button { background-color: #000000; color: #00FF00; border: 1px solid #00FF00; border-radius: 0px; }
    .stButton>button:hover { background-color: #00FF00; color: #000000; }
    div[data-testid="stDataFrame"] { border: 1px solid #00FF00; }
    </style>
    """, unsafe_allow_html=True)

# 2. 헤더 영역 (사이버 터미널 느낌)
st.title("🟢 [ SYSTEM_ROOT_ACCESS ] :: EDR_ANALYZER_v2")
st.markdown("> 터미널 접속 | 네트워크 분석 | 방화벽 로그 | 시스템 설정")

# 3. 상단 대시보드 컨트롤
col1, col2 = st.columns([8, 2])
with col1:
    st.write(f"시스템 접속 시각: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
with col2:
    if st.button("REBOOT_SYSTEM [새로고침]", use_container_width=True):
        st.rerun()

st.write("---") 

# 4. 상단 핵심 지표 (Metrics) - 기능(값)은 동일하게 유지
m_col1, m_col2, m_col3, m_col4 = st.columns(4)
with m_col1:
    st.metric(label="탐지된 총 위협", value="12", delta="CRITICAL")
with m_col2:
    st.metric(label="VirusTotal 탐지", value="5")
with m_col3:
    st.metric(label="AI(Ember) 위험도", value="High")
with m_col4:
    st.metric(label="보호 중인 자산", value="1")

st.write("---") 

# 5. 메인 레이아웃 
left_content, right_content = st.columns([6.5, 3.5])

with left_content:
    st.subheader(">> SYSMON_REALTIME_LOGS.exe")
    mock_logs = pd.DataFrame([
        {"TIME": "20:15:21", "EVENT": "프로세스 생성", "LEVEL": "Low", "DETAILS": "explorer.exe 실행"},
        {"TIME": "20:18:44", "EVENT": "네트워크 접속", "LEVEL": "Medium", "DETAILS": "45.122.x.x 접속 시도"},
        {"TIME": "20:22:12", "EVENT": "악성코드 의심", "LEVEL": "CRITICAL", "DETAILS": "unknown_payload.exe 탐지"},
    ])
    st.dataframe(mock_logs, use_container_width=True, hide_index=True)

with right_content:
    st.subheader(">> AI_THREAT_ANALYSIS")
    
    with st.expander("[+] unknown_payload.exe (PID: 9924)", expanded=True):
        st.progress(85, text="AI_MALWARE_PROBABILITY: 85%")
        st.write("[!] VirusTotal MATCH: **42/70**")
        st.write("[-] BEHAVIOR: Registry Key Modified")
    
    st.write("---") 
    
    st.subheader(">> COUNTERMEASURE_EXECUTION")
    
    action = st.selectbox("Select Action Protocol:", ["NETWORK_ISOLATION", "KILL_PROCESS", "DEEP_SCAN"])
    
    if st.button("EXECUTE_COMMAND", use_container_width=True):
        st.warning(f"COMMAND [{action}] INITIATED. (Awaiting API Implementation...)")

# 6. 하단 푸터
st.write("---")
st.caption("CONNECTION SECURE. PROJECT 2026 EDR TEAM.")