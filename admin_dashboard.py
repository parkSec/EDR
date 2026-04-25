import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime, timedelta
import numpy as np

# 페이지 설정
st.set_page_config(
    page_title=" ADMIN DASHBOARD ",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS 스타일링
st.markdown("""
<style>
    .main-title {
        font-size: 28px;
        font-weight: bold;
        margin-bottom: 20px;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 8px;
        text-align: center;
    }
    .alert-high {
        background-color: #ffcccc;
    }
    .alert-medium {
        background-color: #ffffcc;
    }
    .alert-low {
        background-color: #ccffcc;
    }
</style>
""", unsafe_allow_html=True)

# 제목
col1, col2 = st.columns([0.7, 0.3])
with col1:
    st.markdown('<div class="main-title">🛡️ ADMIN DASHBOARD</div>', unsafe_allow_html=True)
with col2:
    current_time = datetime.now().strftime("%Y년 %m월 %d일 %H:%M:%S")
    st.text(current_time)

st.divider()

# 탭 구성
tab1, tab2, tab3 = st.tabs(["로그", "네트워크", "시스템"])

# 샘플 데이터 생성 함수
def generate_sample_data():
    """시계열 차트용 샘플 데이터"""
    dates = pd.date_range(start='2026-11-03 17:00', end='2026-11-04 17:00', freq='h')
    values = [100, 680, 450, 420, 380, 520, 480, 350, 200, 150, 280, 320, 320, 480, 420, 350, 280, 310, 200, 150, 420, 380, 520, 480, 350]
    return pd.DataFrame({'time': dates, 'count': values})

def generate_event_data():
    """이벤트 테이블 샘플 데이터"""
    events = [
        {
            '시작 시간': '2026-11-04 17:33:48',
            '종료 시간': '2026-11-04 17:33:48',
            'OS': 'Windows 10 x64',
            '상태': '알림',
            '설명': '프록시 네트워크 경로 위험 탐지',
            '파일': 'svchost.exe'
        },
        {
            '시작 시간': '2026-11-04 17:37:48',
            '종료 시간': '2026-11-04 17:33:48',
            'OS': 'Windows 10 x64',
            '상태': '알림',
            '설명': 'Fileless 기법 탐지',
            '파일': 'services.exe'
        },
        {
            '시작 시간': '2026-11-04 17:37:48',
            '종료 시간': '2026-11-04 17:33:48',
            'OS': 'Windows 10 x64',
            '상태': '일반',
            '설명': '의심스러운 프로세스 실행',
            '파일': 'services.exe'
        },
        {
            '시작 시간': '2026-11-04 17:37:48',
            '종료 시간': '2026-11-04 17:33:48',
            'OS': 'Windows 10 x64',
            '상태': '알림',
            '설명': 'DLL 로드',
            '파일': 'MalPost.exe'
        },
        {
            '시작 시간': '2026-11-04 17:37:48',
            '종료 시간': '2026-11-04 17:33:48',
            'OS': 'Windows 10 x64',
            '상태': '일반',
            '설명': '의심스러운 DLL 로드',
            '파일': 'wvchost.exe'
        },
    ]
    return pd.DataFrame(events)

# ============ TAB 1: EDR 행위 ============
with tab1:
    st.subheader("EDR 탐지 행위 분석")
    
    # 날짜 범위 선택
    col1, col2, col3 = st.columns([0.3, 0.3, 0.4])
    with col1:
        start_date = st.date_input("시작 날짜", value=datetime(2026, 11, 3))
    with col2:
        end_date = st.date_input("종료 날짜", value=datetime(2026, 11, 4))
    with col3:
        st.write("")  # 간격 조정
    
    # 차트 데이터
    chart_data = generate_sample_data()
    
    # 시계열 차트
    st.subheader("시간대별 탐지 이벤트")
    
    # 막대 차트
    bar_chart = alt.Chart(chart_data).mark_bar(color='#4472C4').encode(
        x=alt.X('time:T', title='시간', axis=alt.Axis(format='%m-%d %H:%M', labelAngle=0, tickCount=8)),
        y=alt.Y('count:Q', title='탐지'),
        tooltip=['time:T', 'count:Q']
    ).properties(height=300).interactive()
    
    st.altair_chart(bar_chart, use_container_width=True)
    
    # 통계 메트릭
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("총 탐지 이벤트", f"{chart_data['count'].sum():,}")
    with col2:
        st.metric("평균 시간당", f"{chart_data['count'].mean():.0f}")
    with col3:
        st.metric("최대 탐지", f"{chart_data['count'].max()}")
    
    st.divider()
    
    # 이벤트 테이블
    st.subheader("탐지 이벤트 상세 정보")
    
    col1, col2 = st.columns([0.7, 0.3])
    with col1:
        search_text = st.text_input("로그 검색", placeholder="설명 입력...")
    with col2:
        status_filter = st.multiselect("상태 필터", ["알림", "일반"], default=["알림", "일반"])
    
    event_df = generate_event_data()
    
    # 필터 적용
    if search_text:
        mask = event_df.astype(str).apply(lambda x: x.str.contains(search_text, case=False)).any(axis=1)
        event_df = event_df[mask]
    
    # 상태별 필터
    event_df = event_df[event_df['상태'].isin(status_filter)]
    
    # 테이블 표시
    st.dataframe(event_df, use_container_width=True, hide_index=True)
    
    # 페이지네이션
    col1, col2, col3 = st.columns([0.3, 0.4, 0.3])
    with col2:
        st.text("페이지 1 / 10")

# ============ TAB 2: 유입/유출 ============
with tab2:
    st.subheader("네트워크")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("의심 연결", "23", "+5")
    
    with col2:
        st.metric("차단된 연결", "45", "+12")
    
    st.divider()
    
    # 네트워크 이벤트 데이터
    network_data = pd.DataFrame({
        '소스 IP': ['192.168.1.100', '192.168.1.105', '192.168.1.110', '10.0.0.50', '10.0.0.75'],
        '대상 IP': ['8.8.8.8', '1.1.1.1', '8.8.4.4', '203.0.113.45', '198.51.100.89'],
        '포트': [443, 53, 8080, 445, 3389],
        '프로토콜': ['TLS', 'DNS', 'HTTP', 'SMB', 'RDP'],
        '상태': ['차단', '허용', '차단', '허용', '차단']
    })
    
    st.write("**네트워크 연결 기록**")
    st.dataframe(network_data, use_container_width=True, hide_index=True)


# ============ TAB 3: 시스템 ============
with tab3:
    st.subheader("시스템 로그 수집 및 파일")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("수집된 로그", "425", "")
    with col2:
        st.metric("의심 로그", "12", "")
    with col3:
        st.metric("위험 징후", "3", "")
    
    st.divider()
    
    # 로그 데이터
    로그_data = pd.DataFrame({
        '로그 유형': ['레지스트리', '프로세스 메모리', '이벤트 로그', '네트워크 소켓', '파일 시스템'],
        '수집 시간': ['2026-11-04 15:22:10', '2026-11-04 15:20:45', '2026-11-04 15:18:33', '2026-11-04 15:15:12', '2026-11-04 15:10:05'],
        '상태': ['분석 중', '완료', '완료', '대기', '완료']
    })
    
    st.write("**수집된 로그**")
    st.dataframe(로그_data, use_container_width=True, hide_index=True)



# 사이드바 - 필터 및 설정
st.sidebar.title("⚙️ 설정")
st.sidebar.divider()


time_range = st.sidebar.selectbox(
    "시간 범위",
    ["1시간", "6시간", "24시간", "7일", "30일", "사용자 정의"]
)

st.sidebar.divider()

st.sidebar.subheader("알림 설정")
auto_refresh = st.sidebar.toggle("자동 새로고침", value=True)


st.sidebar.divider()

st.sidebar.subheader("내보내기")
if st.sidebar.button("📊 보고서 생성"):
    st.sidebar.success("보고서가 생성되었습니다!")

if st.sidebar.button("📥 데이터 내보내기 (CSV)"):
    st.sidebar.info("CSV 파일로 내보내기 준비 중...")

st.sidebar.divider()

st.sidebar.info(

    "엔드포인트 탐지 및 대응(EDR) 시스템의 관리자 대시보드입니다.\n\n"
  
)
