import streamlit as st
import pandas as pd
import datetime


# 1. 페이지 설정 및 보안 UI 최적화
st.set_page_config(
    page_title="AhnLab Style EDR Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ✂️ 스트림릿 흔적 지우기 및 AhnLab 스타일 커스텀 CSS
st.markdown("""
    <style>
    /* 기본 UI 숨기기 */
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    
    /* 배경 및 폰트 설정 */
    .main { background-color: #0f172a; color: #f8fafc; }
    .stMetric { 
        background-color: #1e293b; 
        padding: 20px; 
        border-radius: 12px; 
        border: 1px solid #334155;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    /* 사이드바 스타일 */
    .css-1d391kg { background-color: #020617; }
    
    /* 테이블 스타일 커스텀 */
    div[data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid #334155;
    }
    </style>
    """, unsafe_allow_html=True)

# 2. 사이드바 (시스템 상태 및 설정)
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("EDR Control Center")
    st.info(f"📍 **환경:** Windows Home\n\n📅 **접속 시간:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    st.write("---")
    st.subheader("🛠️ 시스템 설정")
    monitor_on = st.toggle("실시간 모니터링 활성화", value=True)
    ai_on = st.toggle("AI 분석 자동화", value=True)
    st.write("---")
    st.caption("v1.2.0-Beta (Project 2026)")

# 3. 메인 헤더 영역
col_title, col_status = st.columns([7, 3])
with col_title:
    st.markdown("# 🛡️ Enterprise Endpoint Detection & Response")
with col_status:
    st.write("") # 간격 맞춤
    st.success("✅ 시스템 정상 가동 중 (Active)")

# 4. 상단 핵심 요약 (Summary 카드)
st.write("")
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric(label="탐지된 총 위협", value="12", delta="2 New", delta_color="inverse")
with m2:
    st.metric(label="VirusTotal 탐지", value="5", delta="Clean", delta_color="normal")
with m3:
    st.metric(label="AI (Ember) 위험도", value="High", delta="주의 요망", delta_color="inverse")
with m4:
    st.metric(label="보호 중인 자산", value="1", delta="Local Host")

st.write("---")

# 5. 메인 대시보드 (로그 현황 & 심층 분석)
left_col, right_col = st.columns([6, 4])

with left_col:
    st.subheader("📊 실시간 보안 이벤트 현황 (Sysmon)")
    
    # 가짜 로그 데이터 (실제 데이터 연동 시 이 변수를 교체)
    log_data = pd.DataFrame([
        {"시간": "20:15:21", "이벤트": "프로세스 생성", "위험도": "Low", "내용": "explorer.exe 실행"},
        {"시간": "20:18:44", "이벤트": "네트워크 접속", "위험도": "Medium", "내용": "45.122.x.x 접속 시도"},
        {"시간": "20:22:12", "이벤트": "악성코드 의심", "위험도": "Critical", "내용": "unknown_payload.exe 탐지"},
        {"시간": "20:25:05", "이벤트": "파일 변경", "위험도": "Low", "내용": "config.ini 수정됨"},
    ])
    
    # 위험도별 색상 강조를 위한 데이터프레임 출력
    st.dataframe(log_data, use_container_width=True, hide_index=True)
    
    # 탐지 유형별 통계 (간단한 차트)
    st.write("")
    st.subheader("📈 위험 탐지 추이")
    chart_data = pd.DataFrame({
        'Day': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
        'Threats': [2, 5, 3, 8, 12, 4, 2]
    })
    st.line_chart(chart_data.set_index('Day'))

with right_col:
    st.subheader("🧪 심층 분석 및 대응")
    
    # VirusTotal & AI 분석 결과 섹션
    with st.container(border=True):
        st.markdown("🔍 **VirusTotal & AI 분석 결과**")
        st.write("**파일명:** `unknown_payload.exe` (PID: 9924)")
        
        # AI 확률 게이지
        st.write("AI 악성 확률: 85%")
        st.progress(85)
        
        # VirusTotal 결과 (나중에 API 연결)
        st.markdown("✅ **VirusTotal:** 42/70 탐지")
        
        st.write("---")
        st.markdown("⚡ **즉각 대응 조치**")
        action = st.radio("실행할 액션 선택:", ["로그만 기록", "프로세스 즉시 종료", "네트워크 격리"], index=1)
        
        if st.button("조치 실행 (Apply)", use_container_width=True):
            st.error(f"경고: {action} 조치가 즉시 실행되었습니다!")

# 6. 푸터
st.write("---")
st.caption("AhnLab EDR Analyzer 스타일 프레임워크 v1.2 | 보안 담당자 전용")