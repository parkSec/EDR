import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests
import base64  # URL을 VirusTotal 전용 ID로 변환하기 위해 추가!

# ------------------------------------------------------------------
# 1. VirusTotal API 연동 함수 (백엔드 로직)
# ------------------------------------------------------------------
API_KEY = "35b41543f4ab1f12d38e77b09985b149526eb8fe01ccad0b65699c08c15c1de0" # 🚨 실제 키로 변경 필수!

# (1) 파일 검사 함수
def check_file_with_vt(uploaded_file):
    bytes_data = uploaded_file.getvalue()
    file_hash = hashlib.sha256(bytes_data).hexdigest()
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return {"status": "success", "target": file_hash, "stats": response.json()['data']['attributes']['last_analysis_stats']}
        elif response.status_code == 404:
            return {"status": "not_found", "target": file_hash}
        else:
            return {"status": "error", "target": file_hash, "msg": f"에러 (코드: {response.status_code})"}
    except Exception as e:
        return {"status": "error", "target": file_hash, "msg": str(e)}

# (2) URL(링크) 검사 함수 (새로 추가!)
def check_url_with_vt(target_url):
    # URL을 VirusTotal이 알아먹을 수 있게 Base64 형태로 변환
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return {"status": "success", "target": target_url, "stats": response.json()['data']['attributes']['last_analysis_stats']}
        elif response.status_code == 404:
            return {"status": "not_found", "target": target_url}
        else:
            return {"status": "error", "target": target_url, "msg": f"에러 (코드: {response.status_code})"}
    except Exception as e:
        return {"status": "error", "target": target_url, "msg": str(e)}

# ------------------------------------------------------------------
# 2. UI 및 화면 설정
# ------------------------------------------------------------------
st.set_page_config(page_title="EDR User Dashboard", page_icon="🛡️", layout="wide")

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
# 3. 상/중단 레이아웃 (위험 현황) - 이전과 동일하게 유지
# ------------------------------------------------------------------
top_col1, top_col2, top_col3 = st.columns([2, 5, 3])
with top_col1: st.markdown("## 🛡️ EDR Analyzer (User)")
with top_col2: st.segmented_control("조회 범위", ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"], default="최근 24시간", label_visibility="collapsed")
with top_col3: st.caption("현재 PC 상태: 🟢 안전하게 보호 중")

st.markdown("---")

row1_col1, row1_col2 = st.columns([3, 7])
with row1_col1:
    with st.container(border=True):
        st.markdown("### 위험 현황")
        st.markdown("<h1 style='color: #f87171; font-size: 3rem;'>7</h1>", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        c1.metric("신규", "7"); c2.metric("확인 중", "0"); c1.metric("보류", "0"); c2.metric("확인 완료", "0")

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")
        log_data = pd.DataFrame([
            {"로그 수신 날짜": "2026-04-24 17:41:49", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 16:22:10", "위험도": "H", "탐지 유형": "악성", "프로세스": "unknown.exe", "상태": "신규"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True, height=150)

# ------------------------------------------------------------------
# 4. 하단 레이아웃 (차트 및 파일/URL 수동 검사)
# ------------------------------------------------------------------
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

# 좌측: 차트 1
with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")
        risk_chart = alt.Chart(pd.DataFrame({"위험도": ["High", "Medium", "Low"], "건수": [1, 0, 6]})).mark_arc(innerRadius=60).encode(
            theta="건수:Q", color=alt.Color("위험도:N", scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#ef4444", "#f59e0b", "#3b82f6"]))).properties(height=200)
        st.altair_chart(risk_chart, use_container_width=True)

# 중앙: 차트 2
with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 현황")
        type_chart = alt.Chart(pd.DataFrame({"유형": ["악성", "의심", "정상"], "건수": [1, 6, 0]})).mark_arc(innerRadius=60).encode(
            theta="건수:Q", color=alt.Color("유형:N", scale=alt.Scale(domain=["악성", "의심", "정상"], range=["#8b5cf6", "#a78bfa", "#10b981"]))).properties(height=200)
        st.altair_chart(type_chart, use_container_width=True)

# 🚨 우측: 대망의 VirusTotal 검사 (파일 & URL 탭)
with row2_col3:
    with st.container(border=True):
        st.markdown("### 🔍 수동 정밀 검사 (VirusTotal)")
        
        # 탭(Tab) 생성
        tab_file, tab_url = st.tabs(["📁 파일 검사", "🔗 URL(링크) 검사"])
        
        # --- 탭 1: 기존 파일 검사 ---
        with tab_file:
            uploaded_file = st.file_uploader("파일 선택", label_visibility="collapsed")
            if uploaded_file and st.button("🚀 파일 분석 실행", use_container_width=True):
                with st.spinner("파일 분석 중..."):
                    result = check_file_with_vt(uploaded_file)
                    st.write("---")
                    
                    if result['status'] == "success":
                        stats = result['stats']
                        mal = stats['malicious']
                        if mal > 0: st.error(f"🚨 **위험!** {mal}개 백신에서 악성으로 판명!")
                        else: st.success("✅ **안전!** 악성 내역이 없습니다.")
                    else:
                        st.warning("결과를 찾을 수 없거나 에러가 발생했습니다.")
        
        # --- 탭 2: 새로운 URL(링크) 검사 ---
        with tab_url:
            st.caption("의심스러운 웹사이트 주소를 입력하세요.")
            # URL 입력 창
            input_url = st.text_input("URL 입력", placeholder="https://example-phishing.com", label_visibility="collapsed")
            
            if input_url and st.button("🚀 URL 분석 실행", use_container_width=True):
                with st.spinner("URL 안전성 검사 중..."):
                    result = check_url_with_vt(input_url)
                    st.write("---")
                    st.markdown(f"**검사 대상:** `{result['target']}`")
                    
                    if result['status'] == "success":
                        stats = result['stats']
                        mal = stats['malicious']
                        total = mal + stats['harmless'] + stats['undetected']
                        
                        if mal > 0:
                            st.error(f"🚨 **[피싱/악성 경고]** 전 세계 {total}개 엔진 중 **{mal}개**가 위험한 사이트로 분류했습니다!")
                            st.progress(mal / total)
                        else:
                            st.success(f"✅ **[안전 사이트]** 접속해도 안전한 링크입니다.")
                    elif result['status'] == "not_found":
                        st.warning("⚠️ VirusTotal에 정보가 없는 주소입니다. 접속 시 주의하세요!")
                    else:
                        st.error(f"❌ 조회를 실패했습니다: {result['msg']}")