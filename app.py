import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests
import base64
import time

# ------------------------------------------------------------------
# 1. 백엔드: 바이러스 토탈 API '진짜 검사' 엔진 (상세 결과 포함)
# ------------------------------------------------------------------
API_KEY = "35b41543f4ab1f12d38e77b09985b149526eb8fe01ccad0b65699c08c15c1de0" # 🚨 실제 키 필수!
HEADERS = {"accept": "application/json", "x-apikey": API_KEY}

def format_vt_response(stats, results):
    """API 응답을 대시보드에서 쓰기 쉽게 묶어주는 함수"""
    return {"stats": stats, "results": results}

def analyze_file_vt(uploaded_file):
    bytes_data = uploaded_file.getvalue()
    file_hash = hashlib.sha256(bytes_data).hexdigest()
    
    search_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    res = requests.get(search_url, headers=HEADERS)
    
    if res.status_code == 200:
        data = res.json()['data']['attributes']
        return format_vt_response(data['last_analysis_stats'], data['last_analysis_results'])
    
    elif res.status_code == 404:
        st.info("신규 파일입니다. 서버에 업로드하여 정밀 검사를 시작합니다...")
        upload_url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (uploaded_file.name, bytes_data)}
        up_res = requests.post(upload_url, headers=HEADERS, files=files)
        
        if up_res.status_code == 200:
            analysis_id = up_res.json()['data']['id']
            return wait_for_analysis(analysis_id)
    return None

def analyze_url_vt(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    search_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    res = requests.get(search_url, headers=HEADERS)
    
    if res.status_code == 200:
        data = res.json()['data']['attributes']
        return format_vt_response(data['last_analysis_stats'], data['last_analysis_results'])
    
    elif res.status_code == 404:
        st.info("처음 분석되는 주소입니다. 검사 요청을 보냅니다...")
        post_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": target_url}
        post_res = requests.post(post_url, headers=HEADERS, data=payload)
        
        if post_res.status_code == 200:
            analysis_id = post_res.json()['data']['id']
            return wait_for_analysis(analysis_id)
    return None

def wait_for_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    with st.status("전 세계 백신 엔진들이 정밀 검사를 진행 중입니다...", expanded=True) as status:
        for _ in range(12): # 최대 2분 대기
            res = requests.get(url, headers=HEADERS)
            if res.status_code == 200:
                data = res.json()['data']['attributes']
                if data['status'] == 'completed':
                    status.update(label="검사 완료!", state="complete", expanded=False)
                    # 분석 API는 키 이름이 stats, results 로 들어옵니다.
                    return format_vt_response(data['stats'], data['results'])
            time.sleep(10) 
    return None

def render_detailed_results(vt_data):
    """상세 결과를 예쁜 표(DataFrame)로 만들어 화면에 띄우는 함수"""
    stats = vt_data['stats']
    results = vt_data['results']
    
    # 1. 요약 정보 출력
    m = stats['malicious']
    total = m + stats['harmless'] + stats.get('undetected', 0)
    
    if m > 0: 
        st.error(f"🚨 **위험!** 전 세계 {total}개 백신 중 **{m}개**가 악성으로 탐지했습니다.")
    else: 
        st.success(f"✅ **안전!** {total}개 백신 엔진에서 악성 내역이 발견되지 않았습니다.")
    
    st.write("---")
    st.markdown("#### 🦠 상세 백신 엔진별 진단 결과")
    
    # 2. 개별 엔진 결과를 표 형식으로 변환
    df_list = []
    for engine, details in results.items():
        cat = details.get('category', 'undetected')
        diag_name = details.get('result', '')
        
        if cat == 'malicious':
            status = "🚨 악성"
            sort_val = 1
        elif cat == 'suspicious':
            status = "⚠️ 의심"
            sort_val = 2
        elif cat == 'harmless':
            status = "✅ 정상"
            diag_name = "안전함"
            sort_val = 3
        else:
            status = "➖ 미탐지"
            diag_name = "미탐지"
            sort_val = 4
            
        df_list.append({
            "백신 엔진 (Engine)": engine,
            "탐지 결과": status,
            "진단명 (Result)": diag_name,
            "_sort": sort_val # 정렬용 숨김 데이터
        })
        
    df = pd.DataFrame(df_list)
    # 악성(1) -> 의심(2) -> 정상(3) -> 미탐지(4) 순으로 정렬
    df = df.sort_values(by="_sort").drop(columns=["_sort"])
    
    # 3. 화면에 표 띄우기
    st.dataframe(df, use_container_width=True, hide_index=True, height=300)

# ------------------------------------------------------------------
# 2. 프론트엔드 (UI) - 프리미엄 그라데이션 테마
# ------------------------------------------------------------------
st.set_page_config(page_title="EDR User Dashboard", layout="wide")

st.markdown("""
    <style>
    /* 기본 UI 숨기기 */
    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    
    /* 🌟 전체 배경 그라데이션 (안랩 스타일의 깊은 네이비 사선 그라데이션) */
    .stApp {
        background: linear-gradient(135deg, #242b45 0%, #0d1017 100%) !important;
    }
    
    /* 메인 배경을 투명하게 만들어 그라데이션이 드러나게 함 */
    .main { background-color: transparent !important; color: #d1d5db; }
    
    /* 🌟 컨테이너(카드) 디자인: 반투명 유리 질감 효과 추가 */
    div[data-testid="stVerticalBlock"] > div[style*="flex-direction: column;"] > div[data-testid="stVerticalBlock"] {
        background-color: rgba(30, 34, 51, 0.7) !important; /* 살짝 투명한 배경 */
        backdrop-filter: blur(10px); /* 배경 흐리게 (유리 효과) */
        padding: 20px; 
        border-radius: 12px; 
        border: 1px solid rgba(255, 255, 255, 0.08); /* 은은한 테두리 */
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); /* 깊이감 있는 그림자 */
    }
    
    /* 글자 색상 뚜렷하게 */
    h1, h2, h3, h4 { color: #f3f4f6 !important; text-shadow: 0 2px 4px rgba(0,0,0,0.5); }
    </style>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------------
# 3. 대시보드 상단/중앙 현황판
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
# 4. 하단 차트 및 바이러스 토탈 상세 검사기
# ------------------------------------------------------------------
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")
        risk_chart = alt.Chart(pd.DataFrame({"위험도": ["High", "Medium", "Low"], "건수": [1, 0, 6]})).mark_arc(innerRadius=60).encode(
            theta="건수:Q", color=alt.Color("위험도:N", scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#ef4444", "#f59e0b", "#3b82f6"]))).properties(height=200)
        st.altair_chart(risk_chart, use_container_width=True)

with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 현황")
        type_chart = alt.Chart(pd.DataFrame({"유형": ["악성", "의심", "정상"], "건수": [1, 6, 0]})).mark_arc(innerRadius=60).encode(
            theta="건수:Q", color=alt.Color("유형:N", scale=alt.Scale(domain=["악성", "의심", "정상"], range=["#8b5cf6", "#a78bfa", "#10b981"]))).properties(height=200)
        st.altair_chart(type_chart, use_container_width=True)

# 🚨 우측: 바이러스 토탈 상세 결과 탭
with row2_col3:
    with st.container(border=True):
        st.markdown("### 🔍 실시간 정밀 검사 (VirusTotal)")
        t1, t2 = st.tabs(["📁 파일 업로드 검사", "🔗 URL 링크 검사"])
        
        with t1:
            f = st.file_uploader("파일 선택", label_visibility="collapsed")
            if f and st.button("🚀 정밀 분석 시작", key="f_btn", use_container_width=True):
                vt_data = analyze_file_vt(f)
                if vt_data:
                    render_detailed_results(vt_data)
                else:
                    st.error("분석 중 에러가 발생했습니다.")
                    
        with t2:
            u = st.text_input("검사할 URL 입력", placeholder="https://www.google.com", label_visibility="collapsed")
            if u and st.button("🚀 링크 분석 시작", key="u_btn", use_container_width=True):
                vt_data = analyze_url_vt(u)
                if vt_data:
                    render_detailed_results(vt_data)
                else:
                    st.error("분석 중 에러가 발생했습니다.")