import streamlit as st
import pandas as pd
import altair as alt
import hashlib
import requests
import base64
import time
import streamlit.components.v1 as components

# ------------------------------------------------------------------
# 1. 백엔드: 바이러스 토탈 API
# ------------------------------------------------------------------
API_KEY = "35b41543f4ab1f12d38e77b09985b149526eb8fe01ccad0b65699c08c15c1de0" # 🚨 실제 키 필수!
HEADERS = {"accept": "application/json", "x-apikey": API_KEY}

def format_vt_response(stats, results):
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
        upload_url = "https://www.virustotal.com/api/v3/files"
        files = {"file": (uploaded_file.name, bytes_data)}
        up_res = requests.post(upload_url, headers=HEADERS, files=files)
        if up_res.status_code == 200:
            return wait_for_analysis(up_res.json()['data']['id'])
    return None

def analyze_url_vt(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    search_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    res = requests.get(search_url, headers=HEADERS)
    
    if res.status_code == 200:
        data = res.json()['data']['attributes']
        return format_vt_response(data['last_analysis_stats'], data['last_analysis_results'])
    elif res.status_code == 404:
        post_url = "https://www.virustotal.com/api/v3/urls"
        post_res = requests.post(post_url, headers=HEADERS, data={"url": target_url})
        if post_res.status_code == 200:
            return wait_for_analysis(post_res.json()['data']['id'])
    return None

def wait_for_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    with st.status("검사를 진행 중입니다...", expanded=True) as status:
        for _ in range(12): 
            res = requests.get(url, headers=HEADERS)
            if res.status_code == 200:
                data = res.json()['data']['attributes']
                if data['status'] == 'completed':
                    status.update(label="검사 완료", state="complete", expanded=False)
                    return format_vt_response(data['stats'], data['results'])
            time.sleep(10) 
    return None

def render_detailed_results(vt_data):
    stats = vt_data['stats']
    m = stats['malicious']
    total = m + stats['harmless'] + stats.get('undetected', 0)
    
    if m > 0: st.error(f"[위험] {total}개 중 {m}개가 악성으로 탐지했습니다.")
    else: st.success(f"[안전] 악성 내역이 없습니다.")
    
    df_list = []
    for engine, details in vt_data['results'].items():
        cat = details.get('category', 'undetected')
        if cat == 'malicious': status, sort_val = "악성", 1
        elif cat == 'suspicious': status, sort_val = "의심", 2
        elif cat == 'harmless': status, sort_val = "정상", 3
        else: status, sort_val = "미탐지", 4
            
        df_list.append({"엔진": engine, "결과": status, "진단명": details.get('result', ''), "_sort": sort_val})
        
    df = pd.DataFrame(df_list).sort_values(by="_sort").drop(columns=["_sort"])
    st.dataframe(df, use_container_width=True, hide_index=True, height=200)

# ------------------------------------------------------------------
# 2. 프론트엔드 (UI) - 이모지 제거 및 세련된 새로고침 아이콘 CSS
# ------------------------------------------------------------------
st.set_page_config(page_title="EDR User Dashboard", layout="wide")

st.markdown("""
    <style>
    @font-face {
        font-family: 'NanumSquareRound';
        src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_two@1.0/NanumSquareRound.woff') format('woff');
        font-weight: normal; font-style: normal;
    }
    
    h1, h2, h3, h4, p, label, .stMarkdown, .stText { font-family: 'NanumSquareRound', sans-serif !important; }
    
    div[data-testid="stMetricValue"] { font-family: 'NanumSquareRound', sans-serif !important; font-size: 1.6rem !important; }
    div[data-testid="stMetricLabel"] { font-family: 'NanumSquareRound', sans-serif !important; font-size: 0.8rem !important; }

    h2 { font-size: 1.4rem !important; margin-bottom: 0px !important;}
    h3 { font-size: 1.1rem !important; }
    h4 { font-size: 0.9rem !important; }

    /* 🚨 새로고침 버튼 디자인 커스텀 (크기 UP & 블루톤) */
    button[kind="tertiary"] p {
        font-size: 1.8rem !important; /* 크기 키우기 */
        color: #3b82f6 !important; /* 세련된 파란색 */
        font-weight: 800 !important;
        margin-top: -5px !important;
    }
    button[kind="tertiary"]:hover p {
        color: #60a5fa !important; /* 마우스 올렸을 때 밝은 파란색 */
    }

    .material-icons, span[class*="icon"] { font-family: 'Material Symbols Rounded', 'Material Icons' !important; }

    [data-testid="stToolbar"], #MainMenu, footer, header {visibility: hidden !important;}
    .stApp { background: linear-gradient(135deg, #1e2233 0%, #0d1017 100%) !important; }
    .main { background-color: transparent !important; color: #d1d5db; }
    
    div[data-testid="stVerticalBlockBorderWrapper"] {
        background-color: rgba(30, 34, 51, 0.4) !important; 
        backdrop-filter: blur(8px); 
        border-radius: 10px !important; 
        border: 1px solid rgba(255, 255, 255, 0.05) !important; 
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3) !important; 
    }
    h1, h2, h3, h4 { color: #f3f4f6 !important; }
    </style>
    """, unsafe_allow_html=True)

# ------------------------------------------------------------------
# 3. 대시보드 상단 헤더
# ------------------------------------------------------------------
top_col1, top_col2, top_col3 = st.columns([3, 4, 3])

with top_col1: 
    st.markdown("## EDR Analyzer (사용자)")

with top_col2: 
    st.segmented_control("조회 범위", ["최근 24시간", "최근 7일", "최근 14일", "최근 30일"], default="최근 24시간", label_visibility="collapsed")

with top_col3:
    time_col, refresh_col = st.columns([5, 1])
    with time_col:
        components.html("""
        <div style="text-align: right; font-family: 'NanumSquareRound', sans-serif; color: #f3f4f6; padding-top: 5px;">
            <span id="clock" style="font-size: 0.95rem; font-weight: bold; text-shadow: 0 1px 2px rgba(0,0,0,0.5);"></span>
        </div>
        <script>
            function updateClock() {
                const now = new Date();
                const str = now.getFullYear() + '-' +
                            String(now.getMonth() + 1).padStart(2, '0') + '-' +
                            String(now.getDate()).padStart(2, '0') + ' ' +
                            String(now.getHours()).padStart(2, '0') + ':' +
                            String(now.getMinutes()).padStart(2, '0') + ':' +
                            String(now.getSeconds()).padStart(2, '0');
                document.getElementById('clock').innerText = str;
            }
            setInterval(updateClock, 1000);
            updateClock();
        </script>
        """, height=35)
        
    with refresh_col:
        # 🚨 이모지 🔄 대신 예쁜 기호 ↻ 사용
        if st.button("↻", type="tertiary", help="데이터 새로고침"):
            st.rerun()

st.markdown("---")

# ------------------------------------------------------------------
# 4. 중앙 레이아웃
# ------------------------------------------------------------------
row1_col1, row1_col2 = st.columns([3, 7])

with row1_col1:
    with st.container(border=True):
        st.markdown("### 위험 현황")
        st.markdown("<h1 style='color: #f87171; font-size: 2.5rem; margin-top:-10px;'>7</h1>", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        c1.metric("신규", "7"); c2.metric("확인 중", "0"); c1.metric("보류", "0"); c2.metric("확인 완료", "0")

with row1_col2:
    with st.container(border=True):
        st.markdown("### 최근 탐지 위협")
        log_data = pd.DataFrame([
            {"로그 수신 날짜": "2026-04-24 17:41:49", "위험도": "L", "탐지 유형": "의심", "프로세스": "powershell.exe", "상태": "신규"},
            {"로그 수신 날짜": "2026-04-24 16:22:10", "위험도": "H", "탐지 유형": "악성", "프로세스": "unknown.exe", "상태": "신규"},
        ])
        st.dataframe(log_data, use_container_width=True, hide_index=True, height=130)

# ------------------------------------------------------------------
# 5. 하단 레이아웃 (차트 & 검사기)
# ------------------------------------------------------------------
row2_col1, row2_col2, row2_col3 = st.columns([3, 3, 4])

with row2_col1:
    with st.container(border=True):
        st.markdown("### 위험도별 현황")
        risk_chart = alt.Chart(pd.DataFrame({"위험도": ["High", "Medium", "Low"], "건수": [1, 0, 6]})).mark_arc(innerRadius=50).encode(
            theta="건수:Q", color=alt.Color("위험도:N", scale=alt.Scale(domain=["High", "Medium", "Low"], range=["#ef4444", "#f59e0b", "#3b82f6"]))
        ).properties(height=180, background='transparent').configure_view(strokeWidth=0)
        st.altair_chart(risk_chart, use_container_width=True)

with row2_col2:
    with st.container(border=True):
        st.markdown("### 탐지 유형별 현황")
        type_chart = alt.Chart(pd.DataFrame({"유형": ["악성", "의심", "정상"], "건수": [1, 6, 0]})).mark_arc(innerRadius=50).encode(
            theta="건수:Q", color=alt.Color("유형:N", scale=alt.Scale(domain=["악성", "의심", "정상"], range=["#8b5cf6", "#a78bfa", "#10b981"]))
        ).properties(height=180, background='transparent').configure_view(strokeWidth=0)
        st.altair_chart(type_chart, use_container_width=True)

with row2_col3:
    with st.container(border=True):
        st.markdown("### 실시간 정밀 검사 (VirusTotal)")
        t1, t2 = st.tabs(["파일 업로드 검사", "URL 링크 검사"])
        
        with t1:
            f = st.file_uploader("검사할 파일 선택", label_visibility="collapsed")
            if f and st.button("정밀 분석 시작", key="f_btn", use_container_width=True):
                vt_data = analyze_file_vt(f)
                if vt_data: render_detailed_results(vt_data)
                else: st.error("분석 중 에러가 발생했습니다.")
                    
        with t2:
            u = st.text_input("검사할 URL 입력", placeholder="https://www.google.com", label_visibility="collapsed")
            if u and st.button("링크 분석 시작", key="u_btn", use_container_width=True):
                vt_data = analyze_url_vt(u)
                if vt_data: render_detailed_results(vt_data)
                else: st.error("분석 중 에러가 발생했습니다.")