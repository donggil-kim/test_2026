# -*- coding: utf-8 -*-
"""
통합 소프트웨어 공급망 보안위협 매트릭스 — 판정 규칙
----------------------------------------------------
분류 체계·교차매핑 원천은 data/taxonomy.yaml, 프레임워크 명칭은 data/frameworks.yaml에 있고,
이 파일에는 근거 집계·위험 산정에 쓰는 규칙만 둔다.
"""
import re

# ---------------------------------------------------------------------------
# 1) 사고 DB 집계 규칙 — AI 매트릭스 v3.2 · 클라우드 v5 · OT와 같은 기준
# ---------------------------------------------------------------------------
REAL_KINDS = {"사고", "캠페인", "정부 경보", "공시", "사례연구(익명)"}
RESEARCH_KINDS = {"연구·시연"}
INTEL_KINDS = {"위협인텔"}
EXCLUDED_VERIFICATION = {"행위자 주장", "논란·원인 번복"}
VERIFICATIONS = ["정부·사법 확인", "피해기관 확인", "보안업체·연구기관 분석", "언론 보도", "행위자 주장", "논란·원인 번복"]
KINDS = ["사고", "캠페인", "정부 경보", "공시", "사례연구(익명)", "연구·시연", "위협인텔"]
RECENT_FROM = "2025-01"      # 최근 사고 기준(통합 매트릭스 v1과 같은 2025년 이후)
LIKELY_HIGH_REAL = 2         # 발생가능성 '상' = 실제 사고 2건 이상


def incident_status(e):
    """사고 DB 항목의 집계 상태 — 실제 사고 / 실증·연구 / 위협인텔 / 제외(검증)"""
    if e["kind"] in RESEARCH_KINDS:
        return "실증·연구"
    if e["kind"] in INTEL_KINDS:
        return "위협인텔"
    if e["verification"] in EXCLUDED_VERIFICATION:
        return "제외(검증)"
    return "실제 사고"


RISK_MATRIX = {
    ("상", "상"): "매우 높음", ("상", "중"): "높음", ("상", "하"): "보통",
    ("중", "상"): "높음", ("중", "중"): "보통", ("중", "하"): "낮음",
    ("하", "상"): "보통", ("하", "중"): "낮음", ("하", "하"): "낮음",
}
RISK_ORDER = ["매우 높음", "높음", "보통", "낮음"]
LEVELS = ["실제 사고 확인", "실사용 기법 포함", "실증·공개 취약점", "이론·시나리오"]

# 생태계·경로(사고 DB ecosystem 어휘) — 앞쪽이 '생태계 요약' 시트 순서
ECOSYSTEMS = [
    "npm", "PyPI", "RubyGems", "PHP(Packagist·PEAR)", "기타 패키지 생태계", "컨테이너 이미지",
    "CI/CD 구성요소(Actions 등)", "IDE·브라우저 확장", "AI 생태계", "개발 도구·툴체인",
    "소스 저장소 플랫폼", "CI/CD·개발 SaaS", "오픈소스 프로젝트 인프라", "상용 소프트웨어",
    "서드파티 SaaS·MSP", "웹 스크립트·CDN",
]
ECOSYSTEM_GROUP = {
    "npm": "오픈소스 패키지", "PyPI": "오픈소스 패키지", "RubyGems": "오픈소스 패키지",
    "PHP(Packagist·PEAR)": "오픈소스 패키지", "기타 패키지 생태계": "오픈소스 패키지", "컨테이너 이미지": "오픈소스 패키지",
    "CI/CD 구성요소(Actions 등)": "개발·빌드 경로", "IDE·브라우저 확장": "개발·빌드 경로", "AI 생태계": "개발·빌드 경로",
    "개발 도구·툴체인": "개발·빌드 경로", "소스 저장소 플랫폼": "개발·빌드 경로", "CI/CD·개발 SaaS": "개발·빌드 경로",
    "오픈소스 프로젝트 인프라": "배포·소비 경로", "상용 소프트웨어": "배포·소비 경로",
    "서드파티 SaaS·MSP": "배포·소비 경로", "웹 스크립트·CDN": "배포·소비 경로",
}
IMPACTS = ["백도어·원격 제어", "자격증명·비밀 탈취", "소스 코드 유출", "데이터 반출", "금전 탈취", "크립토재킹",
           "파괴·사보타주", "서비스 중단", "영향 없음(사전 차단)"]

# ---------------------------------------------------------------------------
# 2) ATT&CK 사례 수(공급망 맥락) — 기법을 쓰는 주체(그룹·소프트웨어·캠페인) 수
#    공급망 고유 기법은 절차 전체를, 범용 기법은 절차 설명에 공급망 단서가 있는 것만 센다.
# ---------------------------------------------------------------------------
ATTACK_SC_SPECIFIC = {
    "T1195.001", "T1195.002", "T1677", "T1176.002", "T1072", "T1199", "T1553.002", "T1553.003", "T1588.003",
    "T1587.002", "T1546.016", "T1213.003", "T1567.001", "T1593.003", "T1204.005", "T1525",
}
# 범용 기법의 절차 중 '공급망 메커니즘 자체'를 서술한 것만 고르는 단서 — 파일 확장자(extension)·가짜 설치 파일(installer)·
# 캠페인 이름만으로는 세지 않음(예: SolarWinds 캠페인 중 계정 이동 절차는 공급망 단서가 아님)
ATTACK_SC_KEYWORDS = re.compile(
    r"(?<!3CX )supply[- ]chain|\bnpm\b|pypi|rubygems|nuget|crates\.io|packagist|open ?vsx|marketplace|chrome web store|"
    r"malicious (?:package|librar|dependenc|extension|commit)|package (?:registr|manager|repositor)|"
    r"dependency confusion|typosquat\w* (?:package|librar)|github actions?|ci/cd|\bpipeline|workflow|"
    r"self-hosted runner|runner\.worker|actions runner|build (?:server|system|environment|process|pipeline)|"
    r"code repositor|source code repositor|git repositor|\bcommits?\b|pull request|"
    r"(?:ide|vs ?code|browser|chrome) extension|code[- ]signing|stolen certificate|"
    r"update (?:server|mechanism|channel)|trojanized (?:software )?update|"
    r"personal access token|npm token|publish(?:ing)? token|\boidc\b|"
    r"publish(?:ed|ing)? (?:a |new |malicious )?(?:package|version|extension|release)|"
    r"targeted developers|developer (?:machine|workstation|account|system|environment)",
    re.I)

# ---------------------------------------------------------------------------
# 3) SAP Risk Explorer 문헌 근거 — 공격 사례('attack' 태그)는 사고 DB로 옮겼으므로 제외하고,
#    연구·실증 성격의 문헌만 세부 AV 매핑으로 센다('standard'·'tool'은 근거에서 제외).
# ---------------------------------------------------------------------------
SAP_RESEARCH_TAGS = {"peer-reviewed", "proof-of-concept", "vulnerability", "thesis", "presentation"}

# ---------------------------------------------------------------------------
# 4) CISA KEV(2026-10-02판) 공급망 판정 — CVE: (구분, [세부위협], 비고)
#    실사용 근거('중' 상한)로만 반영. 같은 사건이 사고 DB에도 있으면 사고 수와 별도로 표시된다.
# ---------------------------------------------------------------------------
KEV_CATEGORIES = [
    "침해된 소프트웨어(악성 코드 내장)", "업데이트 무결성 검증 결함", "CI/CD·빌드 서버", "소스 관리(SCM) 플랫폼",
    "아티팩트 저장소", "MSP·원격 관리(RMM) 도구", "내부 배포·패치 관리 도구", "오픈소스 구성요소(라이브러리)",
]
_K1, _K2, _K3, _K4, _K5, _K6, _K7, _K8 = KEV_CATEGORIES
KEV_SUPPLYCHAIN = {
    # 침해된 소프트웨어 — CWE-506 등 공급망 침해 자체가 CVE로 등재된 사례
    "CVE-2026-48027": (_K1, ["SCT-PB-01", "SCT-DE-02.1"], "Nx Console 확장 악성 버전(SCI-163)"),
    "CVE-2026-45321": (_K1, ["SCT-PB-01", "SCT-BD-01.1"], "TanStack npm 악성 버전(SCI-162)"),
    "CVE-2026-8398": (_K1, ["SCT-PB-02.1", "SCT-PB-03.1"], "DAEMON Tools Lite 서명 설치 파일(SCI-161)"),
    "CVE-2026-33634": (_K1, ["SCT-BD-04", "SCT-PB-01"], "Trivy 릴리스·액션 변조(SCI-153)"),
    "CVE-2025-54313": (_K1, ["SCT-PB-01", "SCT-DP-03.2"], "eslint-config-prettier 악성 버전(SCI-139)"),
    "CVE-2025-59374": (_K1, ["SCT-PB-02.2"], "ASUS Live Update 변조(SCI-039)"),
    "CVE-2025-30154": (_K1, ["SCT-BD-04"], "reviewdog/action-setup 변조(SCI-133)"),
    "CVE-2025-30066": (_K1, ["SCT-BD-04", "SCT-SR-02.2"], "tj-actions/changed-files 태그 변조(SCI-133)"),
    "CVE-2024-4978": (_K1, ["SCT-PB-02.1"], "JAVS Viewer 설치 파일 백도어(SCI-113)"),
    "CVE-2019-15107": (_K1, ["SCT-BD-02.1"], "Webmin 빌드 서버 백도어(SCI-042)"),
    # 업데이트 무결성 검증 결함(CWE-494) — 업데이트 경로 가로채기의 전제
    "CVE-2025-15556": (_K2, ["SCT-PB-02.2", "SCT-CS-01"], "Notepad++ WinGUp 업데이터(SCI-151)"),
    "CVE-2026-3502": (_K2, ["SCT-PB-02.2", "SCT-CS-01"], "TrueConf 클라이언트 업데이트(SCI-159)"),
    # CI/CD·빌드 서버
    "CVE-2024-23897": (_K3, ["SCT-BD-03.1"], "Jenkins CLI 파일 읽기(SCI-130)"),
    "CVE-2017-1000353": (_K3, ["SCT-BD-03.1"], "Jenkins 원격 코드 실행"),
    "CVE-2018-1000861": (_K3, ["SCT-BD-03.1"], "Jenkins Stapler 역직렬화"),
    "CVE-2019-1003029": (_K3, ["SCT-BD-03.1"], "Jenkins Script Security 샌드박스 우회"),
    "CVE-2019-1003030": (_K3, ["SCT-BD-03.1"], "Jenkins Matrix Project 원격 코드 실행"),
    "CVE-2015-5317": (_K3, ["SCT-BD-03.1"], "Jenkins UI 정보 노출"),
    "CVE-2023-42793": (_K3, ["SCT-BD-03.1"], "TeamCity 인증 우회(SCI-109)"),
    "CVE-2024-27198": (_K3, ["SCT-BD-03.1"], "TeamCity 인증 우회"),
    "CVE-2024-27199": (_K3, ["SCT-BD-03.1"], "TeamCity 경로 조작"),
    "CVE-2026-63077": (_K3, ["SCT-BD-03.1"], "TeamCity 역직렬화"),
    # 소스 관리 플랫폼
    "CVE-2021-22205": (_K4, ["SCT-SR-03"], "GitLab 원격 코드 실행"),
    "CVE-2023-7028": (_K4, ["SCT-SR-03"], "GitLab 계정 탈취(비밀번호 재설정)"),
    "CVE-2021-22175": (_K4, ["SCT-SR-03"], "GitLab SSRF"),
    "CVE-2021-39935": (_K4, ["SCT-SR-03"], "GitLab SSRF"),
    "CVE-2026-85706": (_K4, ["SCT-SR-03"], "GitLab 경로 조작"),
    "CVE-2022-36804": (_K4, ["SCT-SR-03"], "Bitbucket Server 명령 주입"),
    "CVE-2026-60004": (_K4, ["SCT-SR-03"], "Gitea 코드 주입"),
    "CVE-2025-8110": (_K4, ["SCT-SR-03"], "Gogs 경로 조작"),
    # 아티팩트 저장소(내부 레지스트리)
    "CVE-2019-7238": (_K5, ["SCT-PB-04"], "Nexus Repository 접근 통제 결함"),
    "CVE-2020-10199": (_K5, ["SCT-PB-04"], "Nexus Repository 원격 코드 실행"),
    "CVE-2026-42016": (_K5, ["SCT-PB-04"], "JFrog Artifactory 권한 결함"),
    "CVE-2026-42018": (_K5, ["SCT-PB-04"], "JFrog Artifactory 인증 결함"),
    "CVE-2026-82329": (_K5, ["SCT-PB-04"], "JFrog Artifactory 인증 결함"),
    "CVE-2026-66384": (_K5, ["SCT-PB-04"], "JFrog Artifactory 경로 조작"),
    # MSP·원격 관리(RMM) 도구
    "CVE-2021-30116": (_K6, ["SCT-CS-02.1"], "Kaseya VSA(SCI-061)"),
    "CVE-2017-18362": (_K6, ["SCT-CS-02.1"], "Kaseya VSA SQL 주입"),
    "CVE-2018-20753": (_K6, ["SCT-CS-02.1"], "Kaseya VSA 원격 코드 실행"),
    "CVE-2024-1709": (_K6, ["SCT-CS-02.1"], "ConnectWise ScreenConnect 인증 우회"),
    "CVE-2024-1708": (_K6, ["SCT-CS-02.1"], "ConnectWise ScreenConnect 경로 조작"),
    "CVE-2025-3935": (_K6, ["SCT-CS-02.1"], "ConnectWise ScreenConnect 인증 결함"),
    "CVE-2026-84869": (_K6, ["SCT-CS-02.1"], "ConnectWise ScreenConnect 권한 결함"),
    "CVE-2024-57727": (_K6, ["SCT-CS-02.1"], "SimpleHelp 경로 조작(SCI-138)"),
    "CVE-2024-57728": (_K6, ["SCT-CS-02.1"], "SimpleHelp 경로 조작(SCI-138)"),
    "CVE-2024-57726": (_K6, ["SCT-CS-02.1"], "SimpleHelp 권한 결함(SCI-138)"),
    "CVE-2026-48558": (_K6, ["SCT-CS-02.1"], "SimpleHelp OIDC 인증 우회"),
    "CVE-2025-8875": (_K6, ["SCT-CS-02.1"], "N-able N-central 역직렬화"),
    "CVE-2025-8876": (_K6, ["SCT-CS-02.1"], "N-able N-central 명령 주입"),
    "CVE-2026-18556": (_K6, ["SCT-CS-02.1"], "N-able N-central 인증 우회"),
    "CVE-2026-18577": (_K6, ["SCT-CS-02.1"], "N-able N-central 인증 우회"),
    "CVE-2026-86218": (_K6, ["SCT-CS-02.1"], "N-able N-central 코드 주입"),
    # 내부 배포·패치 관리 도구
    "CVE-2024-43468": (_K7, ["SCT-CS-02.2"], "Microsoft Configuration Manager SQL 주입"),
    "CVE-2025-59287": (_K7, ["SCT-CS-02.2"], "Windows Server Update Service(WSUS) 역직렬화"),
    "CVE-2024-29824": (_K7, ["SCT-CS-02.2"], "Ivanti Endpoint Manager SQL 주입"),
    "CVE-2024-13159": (_K7, ["SCT-CS-02.2"], "Ivanti Endpoint Manager 경로 조작"),
    "CVE-2024-13160": (_K7, ["SCT-CS-02.2"], "Ivanti Endpoint Manager 경로 조작"),
    "CVE-2024-13161": (_K7, ["SCT-CS-02.2"], "Ivanti Endpoint Manager 경로 조작"),
    "CVE-2026-1603": (_K7, ["SCT-CS-02.2"], "Ivanti Endpoint Manager 인증 우회"),
    "CVE-2020-10189": (_K7, ["SCT-CS-02.2"], "ManageEngine Desktop Central 파일 업로드"),
    "CVE-2021-44515": (_K7, ["SCT-CS-02.2"], "ManageEngine Desktop Central 인증 우회"),
    "CVE-2020-11651": (_K7, ["SCT-CS-02.2"], "SaltStack 인증 우회"),
    "CVE-2020-11652": (_K7, ["SCT-CS-02.2"], "SaltStack 경로 조작"),
    "CVE-2020-16846": (_K7, ["SCT-CS-02.2"], "SaltStack 셸 주입"),
    # 오픈소스 구성요소(라이브러리) — 제품에 내장되어 대량 악용된 취약점
    "CVE-2021-44228": (_K8, ["SCT-DP-04"], "Apache Log4j2(SCI-067)"),
    "CVE-2021-45046": (_K8, ["SCT-DP-04"], "Apache Log4j2(SCI-067)"),
    "CVE-2022-22965": (_K8, ["SCT-DP-04"], "Spring Framework(Spring4Shell)"),
    "CVE-2022-22963": (_K8, ["SCT-DP-04"], "Spring Cloud Function"),
    "CVE-2021-39144": (_K8, ["SCT-DP-04"], "XStream"),
    "CVE-2020-11023": (_K8, ["SCT-DP-04"], "jQuery"),
    "CVE-2021-21315": (_K8, ["SCT-DP-04"], "systeminformation(npm)"),
    "CVE-2016-10033": (_K8, ["SCT-DP-04"], "PHPMailer"),
    "CVE-2017-9841": (_K8, ["SCT-DP-04"], "PHPUnit"),
    "CVE-2014-0160": (_K8, ["SCT-DP-04"], "OpenSSL(Heartbleed)"),
    "CVE-2017-5638": (_K8, ["SCT-DP-04"], "Apache Struts"),
    "CVE-2018-11776": (_K8, ["SCT-DP-04"], "Apache Struts"),
    "CVE-2017-9805": (_K8, ["SCT-DP-04"], "Apache Struts"),
    "CVE-2020-17530": (_K8, ["SCT-DP-04"], "Apache Struts"),
    "CVE-2023-4863": (_K8, ["SCT-DP-04"], "libwebp(Chromium WebP)"),
    "CVE-2022-47966": (_K8, ["SCT-DP-04"], "ManageEngine — 구버전 Apache Santuario 내장(SCI-105)"),
}

# ---------------------------------------------------------------------------
# 5) 프레임워크 항목 중 세부위협에 매핑하지 않은 것과 사유('프레임워크 연계' 시트)
# ---------------------------------------------------------------------------
FRAMEWORK_NOT_MAPPED = {
    ("owasp_oss", "OSS-RISK-7"): "라이선스·법적 위험 — 보안위협 범위 밖(라이선스 점검 S2C2F SCA-2와 함께 별도 관리)",
    ("owasp_oss", "OSS-RISK-8"): "성숙도(품질) 위험 — 공격자 행위가 아닌 프로젝트 품질 지표, Scorecard 지표로 간접 반영",
    ("owasp_oss", "OSS-RISK-10"): "의존성 크기 적정성 — 공격면을 넓히는 설계 요인으로 간접 반영(SCT-DP-03.2 대응에 의존성 최소화 포함)",
    ("s2c2f", "SCA-2"): "라이선스 점검 — 보안위협 범위 밖",
    ("ssdf", "PO.2"): "역할·책임 — 공급망 위협과 직접 대응하지 않는 조직 공통 실천",
    ("ssdf", "PO.4"): "보안 점검 기준 — 조직 공통 실천",
    ("ssdf", "PW.1"): "보안 설계 — 제품 자체 취약점 영역(공급망 매트릭스 범위 밖)",
    ("ssdf", "PW.2"): "설계 검토 — 제품 자체 취약점 영역",
    ("ssdf", "PW.8"): "실행 코드 시험 — 제품 자체 취약점 영역",
    ("ssdf", "PW.9"): "안전한 기본 설정 — 제품 자체 취약점 영역",
    ("scorecard", "CI-Tests"): "품질 지표 — 위협과 직접 대응 없음",
    ("scorecard", "CII-Best-Practices"): "종합 성숙도 배지 — 개별 위협과 직접 대응 없음",
    ("scorecard", "Fuzzing"): "제품 자체 취약점 발굴 지표",
    ("scorecard", "License"): "라이선스 — 보안위협 범위 밖",
    ("scorecard", "Security-Policy"): "취약점 신고 창구 — 대응 절차 지표(직접 대응 위협 없음)",
}

# 매트릭스 뷰·요약용 적용 프로파일 순서
PROFILES = ["오픈소스", "상용 SW", "CI/CD", "AI", "서드파티"]
