import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests

# ------------------------------------------------------------------
# 1. VirusTotal API 연동 함수 (백엔드 로직)
# ------------------------------------------------------------------
def check_file_with_vt(uploaded_file):
    # 파일 내용을 읽어서 SHA256 해시값(지문) 추출
    bytes_data = uploaded_file.getvalue()
    file_hash = hashlib.sha256(bytes_data).hexdigest()
    
    # 🚨 여기에 발급받은 실제 API 키를 넣어야 작동합니다! 🚨
    API_KEY = "35b41543f4ab1f12d38e77b09985b149526eb8fe01ccad0b65699c08c15c1de0"
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            return {"status": "success", "hash": file_hash, "stats": stats}
            
        elif response.status_code == 404:
            return {"status": "not_found", "hash": file_hash}
            
        elif response.status_code == 401:
            return {"status": "error", "hash": file_hash, "msg": "API 키가 틀렸거나 승인되지 않았습니다."}
            
        else:
            return {"status": "error", "hash": file_hash, "msg": f"알 수 없는 에러 (상태 코드: {response.status_code})"}
            
    except Exception as e:
        return {"status": "error", "hash": file_hash, "msg": f"통신 오류: {e}"}

# ------------------------------------------------------------------
# 2. 페이지 설정 및 UI 테마 (프론트엔드 설정)
# ------------------------------------------------------------------
st.set_page_config(
    page_title="EDR User Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# 안랩 스타일 다크 테마 커스텀 CSS
st.markdown("""
    <style>
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    .main { background-color: #1e2233; color: #d1d5db; }
    div[data-testid="stVerticalBlock"] > div[style*="flex-direction: column;"] > div[data-testid="stVerticalBlock"] {
        background-color: #262b3d; padding: 20px; border-radius: 10px; border: 1px solid #374151; box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    h1, h2, h3 { color: #f3f4f6 !important; }
    div[data-testid="stDataFrame"] { border-radius: 8px; border: 1px solid #374151; }
    </style>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------------
# 3. 상단 헤더 및 시간 필터
# ------------------------------------------------------------------
top_col1, top_col2, top_col3 = st.columns([2, 5, 3])
with top_col1:
    st.markdown("## 🛡️ EDR Analyzer (User)")
with top_col2:
    time_filter = st.segmented_control(
        "조회 범위",
        ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"],
        default="최근 24시간",
        label_visibility="collapsed"
    )
with top_col3:
    st.write("") 
    st.caption("현재 PC 상태: 🟢 안전하게 보호 중")

st.markdown("---")

# ------------------------------------------------------------------
# 4. 중앙 레이아웃 (위험 현황 및 탐지 위협 리스트)
# ------------------------------------------------------------------
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
        log_data = pd.DataFrame([
            {"로그 수신 날짜": "2026-04-24 17:41:49", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 17:40:12", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 17:35:05", "위험도": "L", "탐지 유형": "의심", "프로세스": "cmd.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 16:22:10", "위험도": "H", "탐지 유형": "악성", "프로세스": "unknown.exe", "상태": "신규"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True, height=210)

# ------------------------------------------------------------------
# 5. 하단 레이아웃 (차트 및 수동 파일 검사)
# ------------------------------------------------------------------
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

# 좌측: 위험도 차트
with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 위험 현황")
        risk_data = pd.DataFrame({"위험도": ["High", "Medium", "Low"], "건수": [1, 0, 6]})
        risk_chart = alt.Chart(risk_data).mark_arc(innerRadius=60).encode(
            theta="건수:Q",
            color=alt.Color("위험도:N", scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#ef4444", "#f59e0b", "#3b82f6"])),
            tooltip=["위험도", "건수"]
        ).properties(height=250)
        st.altair_chart(risk_chart, use_container_width=True)

# 중앙: 탐지 유형 차트
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

# 우측: VirusTotal 파일 수동 검사 (API 연동)
with row2_col3:
    with st.container(border=True):
        st.markdown("### 🔍 의심 파일 수동 검사 (VirusTotal)")
        st.caption("파일을 업로드하면 고유 해시(Hash)를 추출하여 분석을 시작합니다.")
        
        uploaded_file = st.file_uploader("파일 선택", label_visibility="collapsed")
        
        if uploaded_file is not None:
            st.success(f"📁 파일 인식 완료: `{uploaded_file.name}`")
            
            if st.button("🚀 VirusTotal 분석 실행", use_container_width=True):
                with st.spinner("VirusTotal 서버에서 70여 개 백신 엔진의 결과를 조회 중입니다..."):
                    
                    # API 함수 실행
                    result = check_file_with_vt(uploaded_file)
                    
                    st.write("---")
                    st.markdown(f"**분석 대상(SHA256):**\n`{result['hash']}`")
                    
                    # API 결과에 따른 출력
                    if result['status'] == "success":
                        stats = result['stats']
                        malicious = stats['malicious'] 
                        total_scans = malicious + stats['harmless'] + stats['undetected']
                        
                        if malicious > 0:
                            st.error(f"🚨 **[위험]** 전 세계 {total_scans}개 백신 중 **{malicious}개**가 악성 파일로 판별했습니다!")
                            st.progress(malicious / total_scans, text="위험도 게이지")
                        else:
                            st.success(f"✅ **[안전]** 전 세계 {total_scans}개 백신 검사 결과, 악성 의심 내역이 없습니다.")
                            
                    elif result['status'] == "not_found":
                        st.warning("⚠️ **[주의]** VirusTotal에 단 한 번도 보고된 적 없는 새로운 파일입니다. (신종 악성코드 주의)")
                        
                    else:
                        st.error(f"❌ **[에러]** 조회를 실패했습니다: {result['msg']}")