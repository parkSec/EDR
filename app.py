import streamlit as st
import pandas as pd
import datetime

# 1. 페이지 설정 및 다크모드 최적화 레이아웃
st.set_page_config(
    page_title="EDR Advanced Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 커스텀 CSS: 기업용 느낌의 폰트와 여백 조절
st.markdown("""
    <style>
    .main { background-color: #0e1117; }
    .stMetric { background-color: #1f2937; padding: 15px; border-radius: 10px; border: 1px solid #374151; }
    .stSidebar { background-color: #111827; }
    </style>
    """, unsafe_allow_html=True)

# 2. 사이드바 - 설정 및 상태 관리
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("EDR Control Center")
    st.info(f"📍 **환경:** Windows Home\n\n📅 **접속 시간:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.divider()
    st.subheader("🛠️ 시스템 설정")
    st.toggle("실시간 모니터링 활성화", value=True)
    st.toggle("AI 분석 자동화", value=True)
    st.divider()
    st.write("v1.0.0-Beta (Project 2026)")

# 3. 메인 헤더 영역
st.title("🛡️ Enterprise Endpoint Detection & Response")
st.markdown("---")

# 4. 상단 지표 (Metrics) - 기업 대시보드 핵심
m_col1, m_col2, m_col3, m_col4 = st.columns(4)
with m_col1:
    st.metric(label="탐지된 총 위협", value="12", delta="2 New", delta_color="inverse")
with m_col2:
    st.metric(label="VirusTotal 탐지", value="5", delta="Clean")
with m_col3:
    st.metric(label="AI (Ember) 위험도", value="High", delta="주의 요망", delta_color="off")
with m_col4:
    st.metric(label="보호 중인 자산", value="1", delta="Local Host")

st.write("") # 간격 조절

# 5. 메인 레이아웃 (좌: 실시간 모니터링 / 우: 위협 분석 및 대응)
left_content, right_content = st.columns([6.5, 3.5])

with left_content:
    st.subheader("📊 실시간 보안 이벤트 현황 (Sysmon)")
    
    # [나중에 4, 5단계에서 DB 연동 시 이 데이터프레임을 수정하면 됩니다]
    mock_logs = pd.DataFrame([
        {"시간": "20:15:21", "이벤트": "프로세스 생성", "위험도": "Low", "내용": "explorer.exe 실행"},
        {"시간": "20:18:44", "이벤트": "네트워크 접속", "위험도": "Medium", "내용": "45.122.x.x 접속 시도"},
        {"시간": "20:22:12", "이벤트": "악성코드 의심", "위험도": "Critical", "내용": "unknown_payload.exe 탐지"}
    ])
    
    # 위험도별 색상 강조를 위해 표 출력
    st.dataframe(
        mock_logs, 
        use_container_width=True, 
        hide_index=True
    )
    
    st.subheader("📈 위협 탐지 추이")
    # [나중에 7단계 이벤트 알림 구현 시 시각화 그래프 추가 자리]
    chart_data = pd.DataFrame({
        "시간": [f"{i}:00" for i in range(12, 21)],
        "탐지 건수": [0, 1, 0, 2, 5, 1, 0, 3, 2]
    })
    st.line_chart(chart_data.set_index("시간"))

with right_content:
    st.subheader("🧪 심층 분석 및 대응")
    
    # [나중에 2, 3단계 API/AI 연동 결과가 출력될 공간]
    with st.expander("🔍 VirusTotal & AI 분석 결과", expanded=True):
        st.write("**파일명:** `unknown_payload.exe` (PID: 9924)")
        st.progress(85, text="AI 악성 확률: 85%")
        st.write("✅ **VirusTotal:** 42/70 탐지")
        st.write("⚠️ **행위분석:** 레지스트리 비정상 수정 탐지")
    
    st.divider()
    
    st.subheader("⚡ 자동 대응 (Response)")
    st.warning("위협이 탐지된 엔드포인트에 대해 조치를 선택하세요.")
    
    # [나중에 6, 10단계 네트워크/프로세스 차단 코드 연결 자리]
    action = st.selectbox("실행할 액션", ["프로세스 즉시 종료", "네트워크 완전 격리", "정밀 스캔 실행"])
    
    if st.button("실행 (Execute Action)", use_container_width=True, type="primary"):
        with st.spinner('PowerShell 스크립트 실행 중...'):
            # 실제 파워셸 코드가 들어갈 자리
            st.success(f"[{action}] 처리가 완료되었습니다.")
            st.balloons()

# 6. 하단 푸터
st.markdown("---")
st.caption("© 2026 EDR Project Team. All rights reserved. 본 대시보드는 모니터링 목적으로만 사용됩니다.")