import streamlit as st
import pandas as pd
import datetime

# 1. 페이지 설정 및 다크모드 최적화 레이아웃
# AhnLab 대시보드처럼 'wide' 레이아웃을 사용합니다.
st.set_page_config(
    page_title="EDR Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 커스텀 CSS: AhnLab 대시보드와 유사한 다크 블루 톤과 테두리를 적용합니다.
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1f2937; padding: 15px; border-radius: 10px; border: 1px solid #374151; }
    .stSidebar { background-color: #111827; }
    </style>
    """, unsafe_allow_html=True)

# 2. 헤더 영역 (제목 및 메뉴바 모방)
st.title("🛡️ Project 2026 EDR Analyzer")
# AhnLab의 메뉴바를 텍스트로만 흉내 내봅니다. (뼈대)
st.markdown("대시보드 | 분석 | 이벤트 | 정책 | 보고서")

# 3. 상단 대시보드 컨트롤 (날짜/시간 표시 및 새로고침)
col1, col2 = st.columns([8, 2])
with col1:
    st.write(f"접속 시각: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
with col2:
    if st.button("🔄 새로고침", use_container_width=True):
        # 스트림릿 앱을 강제로 새로고침합니다.
        st.rerun()

st.write("---") # 구분선

# 4. 상단 핵심 지표 (Metrics)
# AhnLab 이미지의 '위험 현황' 부분을 재구성했습니다.
m_col1, m_col2, m_col3, m_col4 = st.columns(4)
with m_col1:
    st.metric(label="총 위협 파일", value="7", delta="2")
with m_col2:
    st.metric(label="VirusTotal 탐지", value="5")
with m_col3:
    st.metric(label="AI 위험도", value="High")
with m_col4:
    st.metric(label="보호 중인 호스트", value="1")

st.write("---") # 구분선

# 5. 메인 레이아웃 (좌: 실시간 로그, 우: AI 분석/대응)
left_content, right_content = st.columns([6.5, 3.5])

with left_content:
    st.subheader("📊 실시간 의심 로그 (Sysmon)")
    
    # [나중에 4단계에서 DB 연동 시 이 데이터프레임을 수정하면 됩니다]
    # AhnLab 이미지의 테이블을 흉내 낸 가짜 데이터입니다.
    mock_logs = pd.DataFrame([
        {"시간": "17:41:49", "위험도": "L", "핵심 위협": "powershell.exe", "호스트 IP": "192.168.0.1"},
        {"시간": "17:41:49", "위험도": "L", "핵심 위협": "cmd.exe", "호스트 IP": "192.168.0.1"},
        {"시간": "17:41:49", "위험도": "H", "핵심 위협": "unknown_payload.exe", "호스트 IP": "192.168.0.1"},
        {"시간": "17:41:50", "위험도": "M", "핵심 위협": "netcat.exe", "호스트 IP": "192.168.0.1"},
        {"시간": "17:41:51", "위험도": "L", "핵심 위협": "explorer.exe", "호스트 IP": "192.168.0.1"},
    ])
    
    # 위험도별 색상 강조를 위해 표 출력
    st.dataframe(
        mock_logs, 
        use_container_width=True, 
        hide_index=True
    )

with right_content:
    st.subheader("🔬 AI & 외부 분석 결과")
    
    # [나중에 2, 3단계 API/AI 연동 결과가 출력될 공간]
    # AhnLab 이미지의 도넛 차트 대신 핵심 수치를 보여줍니다.
    with st.expander("`unknown_payload.exe` 분석", expanded=True):
        # AI 모델(Ember) 악성 확률
        st.progress(85, text="AI 악성 확률: 85%")
        # VirusTotal 탐지 수
        st.write("✅ VirusTotal 탐지: **42/70**")
        st.write("⚠️ 행위분석: 레지스트리 비정상 수정 탐지")
    
    st.write("---") # 구분선
    
    st.subheader("⚡ 자동 대응 (Response)")
    
    # [나중에 6, 10단계 네트워크/프로세스 차단 코드 연결 자리]
    # 회원님이 언급하신 기능을 selectbox로 만듭니다.
    action = st.selectbox("실행할 조치", ["네트워크 격리", "프로세스 차단", "정밀 스캔"])
    
    if st.button("실행 (Execute Action)", use_container_width=True):
        st.success(f"'{action}' 조치를 실행합니다. (실제 기능은 아직 구현되지 않았습니다)")

# 6. 하단 푸터
st.write("---")
st.caption("© 2026 EDR Project Team. All rights reserved. 본 대시보드는 모니터링 목적으로만 사용됩니다.")