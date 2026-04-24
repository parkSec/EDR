import streamlit as st
import pandas as pd
import altair as alt  # 스트림릿에 내장된 안전한 차트 라이브러리

# 1. 페이지 설정
st.set_page_config(
    page_title="EDR User Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# 2. 안랩 스타일 다크 테마 커스텀 CSS
st.markdown("""
    <style>
    /* 기본 UI 숨기기 */
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    
    /* 전체 배경 및 폰트 색상 (안랩 네이비톤) */
    .main { background-color: #1e2233; color: #d1d5db; }
    
    /* 컨테이너 및 카드 스타일 */
    div[data-testid="stVerticalBlock"] > div[style*="flex-direction: column;"] > div[data-testid="stVerticalBlock"] {
        background-color: #262b3d;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #374151;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    }
    
    /* 텍스트 강조 색상 */
    h1, h2, h3 { color: #f3f4f6 !important; }
    
    /* 데이터프레임 스타일 */
    div[data-testid="stDataFrame"] { border-radius: 8px; border: 1px solid #374151; }
    </style>
    """, unsafe_allow_html=True)

# 3. 상단 헤더 및 시간 필터
top_col1, top_col2, top_col3 = st.columns([2, 5, 3])
with top_col1:
    st.markdown("## 🛡️ EDR Analyzer (User)")
with top_col2:
    # 사진과 동일한 시간 필터
    time_filter = st.segmented_control(
        "조회 범위",
        ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"],
        default="최근 24시간",
        label_visibility="collapsed"
    )
with top_col3:
    st.write("") # 간격 맞춤
    st.caption("2026-04-24 20:52:00 기준 | 상태: 🟢 안전")

st.markdown("---")

# 4. 상단 레이아웃 (좌측: 위험 현황 / 우측: 최근 탐지 위협)
row1_col1, row1_col2 = st.columns([3, 7])

with row1_col1:
    with st.container(border=True):
        st.markdown("### 위험 현황")
        st.markdown("<h1 style='color: #f87171; font-size: 3rem;'>7</h1>", unsafe_allow_html=True)
        
        c1, c2 = st.columns(2)
        c1.metric("신규", "7")
        c2.metric("확인 중", "0")
        c1.metric("보류", "0")
        c2.metric("확인 완료", "0")

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")
        # 가상의 탐지 로그 데이터
        log_data = pd.DataFrame([
            {"로그 수신 날짜": "2026-04-24 17:41:49", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 17:40:12", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 17:35:05", "위험도": "L", "탐지 유형": "의심", "프로세스": "cmd.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 16:22:10", "위험도": "H", "탐지 유형": "악성", "프로세스": "unknown.exe", "상태": "신규"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True, height=210)

# 5. 하단 레이아웃 (좌측: 위험도 / 중앙: 탐지유형 / 우측: VirusTotal 검사)
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 위험 현황")
        # Altair 도넛 차트 구현
        risk_data = pd.DataFrame({"위험도": ["High", "Medium", "Low"], "건수": [1, 0, 6]})
        risk_chart = alt.Chart(risk_data).mark_arc(innerRadius=60).encode(
            theta="건수:Q",
            color=alt.Color("위험도:N", scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#ef4444", "#f59e0b", "#3b82f6"])),
            tooltip=["위험도", "건수"]
        ).properties(height=250)
        st.altair_chart(risk_chart, use_container_width=True)

with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 위험 현황")
        type_data = pd.DataFrame({"유형": ["악성", "의심", "정상"], "건수": [1, 6, 0]})
        type_chart = alt.Chart(type_data).mark_arc(innerRadius=60).encode(
            theta="건수:Q",
            color=alt.Color("유형:N", scale=alt.Scale(domain=["악성", "의심", "정상"], range=["#8b5cf6", "#a78bfa", "#10b981"])),
            tooltip=["유형", "건수"]
        ).properties(height=250)
        st.altair_chart(type_chart, use_container_width=True)

with row2_col3:
    with st.container(border=True):
        # 대망의 VirusTotal 수동 검사 기능 영역
        st.markdown("### 🔍 의심 파일 수동 검사 (VirusTotal)")
        st.caption("인터넷에서 다운로드한 파일이 의심스럽다면 직접 업로드하여 검사해보세요.")
        
        uploaded_file = st.file_uploader("파일 선택 (최대 32MB)", label_visibility="collapsed")
        
        if uploaded_file is not None:
            st.info(f"📁 파일 인식 완료: `{uploaded_file.name}`")
            if st.button("🚀 VirusTotal 검사 시작", use_container_width=True):
                # 나중에 여기에 진짜 API 코드가 들어갈 자리입니다!
                st.toast("서버로 파일을 전송 중입니다...")
                st.warning("분석 중... (API 연동 대기 상태)")
        else:
            st.write("")
            st.info("여기에 파일을 드래그 앤 드롭하세요.")