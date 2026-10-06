# -*- coding: utf-8 -*-
"""
통합 신원(아이덴티티)·계정 보안위협 매트릭스 — 판정 규칙
------------------------------------------------------
분류 체계·교차매핑 원천은 data/taxonomy.yaml, 프레임워크 명칭은 data/frameworks.yaml에 있고,
이 파일에는 근거 집계·위험 산정에 쓰는 규칙만 둔다(공급망 매트릭스 taxonomy_rules.py와 같은 구성).
"""
import re

# ---------------------------------------------------------------------------
# 1) 사고 DB 집계 규칙 — AI v3.2 · 클라우드 v5 · OT · 공급망 매트릭스와 같은 기준
# ---------------------------------------------------------------------------
REAL_KINDS = {"사고", "캠페인", "정부 경보", "공시", "사례연구(익명)"}
RESEARCH_KINDS = {"연구·시연"}
INTEL_KINDS = {"위협인텔"}
EXCLUDED_VERIFICATION = {"행위자 주장", "논란·원인 번복"}
VERIFICATIONS = ["정부·사법 확인", "피해기관 확인", "보안업체·연구기관 분석", "언론 보도", "행위자 주장", "논란·원인 번복"]
KINDS = ["사고", "캠페인", "정부 경보", "공시", "사례연구(익명)", "연구·시연", "위협인텔"]
RECENT_FROM = "2025-01"      # 최근 사고 기준(통합 매트릭스와 같은 2025년 이후)
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

# 신원 유형·ID 환경(사고 DB id_type·id_env 어휘) — 앞쪽이 요약 시트 순서
ID_TYPES = ["인력", "특권", "NHI", "고객"]
ID_ENVS = ["온프레미스 AD", "클라우드 IdP", "SaaS", "원격 접속", "CIAM·고객 서비스", "통신", "개발·CI/CD", "클라우드 인프라"]
IMPACTS = ["계정 탈취", "자격증명·토큰 탈취", "데이터 반출", "금전 탈취", "랜섬웨어·파괴", "서비스 중단",
           "테넌트·도메인 장악", "영향 없음(사전 차단)"]

# ---------------------------------------------------------------------------
# 2) ATT&CK 사례 수(신원 맥락) — 기법을 쓰는 주체(그룹·소프트웨어·캠페인) 수
#    신원 기법(자격증명 접근·유효 계정·계정 조작·인증 변조 등)은 절차 전체를,
#    범용 기법(공개 앱 악용·피싱·신뢰 관계·영향 등)은 절차 설명에 신원 단서가 있는 것만 센다.
# ---------------------------------------------------------------------------
ATTACK_ID_GENERIC = {
    "T1190", "T1133", "T1199", "T1195", "T1566.002", "T1566.003", "T1566.004", "T1684.001", "T1219", "T1068",
    "T1210", "T1657", "T1114.002", "T1530", "T1213", "T1486", "T1485", "T1490", "T1005", "T1185", "T1222.001",
    "T1685.002", "T1593.003", "T1212", "T1557",
}
ATTACK_ID_KEYWORDS = re.compile(
    r"credential|password|passphrase|\baccounts?\b|log-?on|log-?in|sign-?in|authenticat|multi-?factor|\bMFA\b|\b2FA\b|"
    r"one-time|\bOTP\b|token|session|cookie|oauth|\bSAML\b|\bSSO\b|single sign|identity provider|\bIdP\b|kerberos|"
    r"\bNTLM\b|hash|active directory|domain admin|domain controller|impersonat|help ?desk|service desk|"
    r"privileged|administrator|\bVPN\b|remote access",
    re.I)


def attack_counts_all(tid):
    """True면 절차 전체를 신원 사례로 센다(범용 기법이 아니면 전체)"""
    return tid not in ATTACK_ID_GENERIC


# ---------------------------------------------------------------------------
# 3) CISA KEV(2026-10-02판) 신원 판정 — CVE: (구분, [세부위협], 비고)
#    판정: ① 인증 계열 CWE 후보 + ② 신원·접근 인프라 제품 후보(375건) → ③ 수동 판정.
#    신원 체계를 직접 노리는 것(인증 우회·세션 노출·하드코딩 자격증명·디렉터리/Kerberos/NTLM·서명 검증·IdP 제품·
#    자격증명 노출)만 넣고, 일반 원격 코드 실행·소비자 기기·OT 장비(OT 매트릭스 범위)는 제외.
#    실사용 근거('중' 상한)로만 반영.
# ---------------------------------------------------------------------------
KEV_CATEGORIES = [
    "원격 접속·경계 장비 인증 우회", "세션·토큰 노출·탈취", "하드코딩·기본 자격증명·고정 키",
    "디렉터리·Kerberos·NTLM", "서명·인증서·신원 검증 결함", "IdP·SSO·신원 관리 제품·계정 복구", "자격증명·인증 정보 노출",
]
_K1, _K2, _K3, _K4, _K5, _K6, _K7 = KEV_CATEGORIES
_A41, _A42 = "IDT-AU-04.1", "IDT-AU-04.2"
KEV_IDENTITY = {
    # 원격 접속·경계 장비(VPN·게이트웨이·방화벽 관리면) 인증 우회
    "CVE-2020-12812": (_K1, [_A41, "IDT-AU-03.3"], "FortiOS SSL VPN 사용자 이름 대소문자로 2단계 인증 우회"),
    "CVE-2021-22893": (_K1, [_A41], "Pulse Connect Secure 인증 우회"),
    "CVE-2020-8193": (_K1, [_A41], "Citrix ADC·Gateway 인가 우회"),
    "CVE-2022-1040": (_K1, [_A41], "Sophos Firewall 사용자 포털·관리 화면 인증 우회"),
    "CVE-2022-40684": (_K1, [_A41], "Fortinet 관리 인터페이스 인증 우회"),
    "CVE-2022-1388": (_K1, [_A41], "F5 BIG-IP iControl REST 인증 누락"),
    "CVE-2023-46747": (_K1, [_A41], "F5 BIG-IP 구성 유틸리티 인증 우회"),
    "CVE-2023-20269": (_K1, [_A41, "IDT-AU-01.1"], "Cisco ASA·FTD VPN 무단 접근(대입 공격 허용, IDI-092)"),
    "CVE-2023-38035": (_K1, [_A41], "Ivanti Sentry 인증 우회"),
    "CVE-2023-46805": (_K1, [_A41], "Ivanti Connect Secure 인증 우회(IDI-087)"),
    "CVE-2024-21887": (_K1, [_A41], "Ivanti Connect Secure 명령 주입 — 인증 우회와 연결 악용(IDI-087)"),
    "CVE-2023-28461": (_K1, [_A41], "Array Networks AG SSL VPN 인증 누락"),
    "CVE-2024-0012": (_K1, [_A41], "PAN-OS 관리 인터페이스 인증 우회"),
    "CVE-2025-0108": (_K1, [_A41], "PAN-OS 인증 우회"),
    "CVE-2024-55591": (_K1, [_A41], "FortiOS·FortiProxy 인증 우회(최고 관리자 권한)"),
    "CVE-2025-24472": (_K1, [_A41], "FortiOS·FortiProxy 인증 우회"),
    "CVE-2026-24858": (_K1, [_A41], "Fortinet 여러 제품 대체 경로 인증 우회"),
    "CVE-2026-0257": (_K1, [_A41], "PAN-OS 인증 우회"),
    "CVE-2026-50751": (_K1, [_A41], "Check Point Security Gateway 부적절한 인증"),
    "CVE-2026-16232": (_K1, [_A41], "Check Point SmartConsole 부적절한 인증"),
    "CVE-2026-19490": (_K1, [_A41], "Citrix NetScaler 대체 경로 인증 우회"),
    "CVE-2026-20079": (_K1, [_A41], "Cisco 방화벽 관리 센터 대체 경로 인증 우회"),
    "CVE-2024-1709": (_K1, [_A41], "ConnectWise ScreenConnect 원격 지원 인증 우회"),
    "CVE-2024-12356": (_K1, [_A41, "IDT-NH-01.1"], "BeyondTrust 원격 지원 명령 주입 — API 키 탈취 사건과 함께 조사(IDI-084)"),
    "CVE-2026-94127": (_K1, [_A41], "F5 BIG-IP APM(접근 정책·SSO 관리) 힙 오버플로"),
    # 세션·토큰 노출·탈취
    "CVE-2023-4966": (_K2, ["IDT-TS-01.3"], "Citrix Bleed — 메모리 노출로 세션 토큰 탈취(IDI-088·089)"),
    "CVE-2025-5777": (_K2, ["IDT-TS-01.3"], "CitrixBleed 2 — 로그인 전 세션 토큰 노출(IDI-090)"),
    "CVE-2024-53704": (_K2, ["IDT-TS-01.3", _A41], "SonicOS SSLVPN 부적절한 인증 — 활성 VPN 세션 가로채기"),
    "CVE-2020-3259": (_K2, ["IDT-TS-01.3"], "Cisco ASA·FTD 메모리 정보 노출(Akira 악용)"),
    "CVE-2019-11510": (_K2, ["IDT-TS-01.3", _A41], "Pulse Connect Secure 임의 파일 읽기 — 평문 자격증명·세션 정보 노출"),
    "CVE-2026-102489": (_K2, ["IDT-TS-01.1"], "Zammad 헬프데스크 세션 고정"),
    # 하드코딩·기본 자격증명·고정 키
    "CVE-2020-8657": (_K3, ["IDT-AU-02"], "EyesOfNetwork 하드코딩 자격증명"),
    "CVE-2020-29583": (_K3, ["IDT-AU-02"], "Zyxel 방화벽·VPN 하드코딩 계정"),
    "CVE-2022-26138": (_K3, ["IDT-AU-02"], "Atlassian Questions for Confluence 하드코딩 자격증명"),
    "CVE-2023-45249": (_K3, ["IDT-AU-02"], "Acronis Cyber Infrastructure 기본 비밀번호"),
    "CVE-2024-28987": (_K3, ["IDT-AU-02"], "SolarWinds Web Help Desk 하드코딩 자격증명"),
    "CVE-2024-20439": (_K3, ["IDT-AU-02"], "Cisco Smart Licensing Utility 고정 관리자 자격증명"),
    "CVE-2019-6693": (_K3, ["IDT-AU-02", "IDT-CR-02.1"], "FortiOS 구성 내 비밀번호 암호화용 하드코딩 키"),
    "CVE-2021-44207": (_K3, ["IDT-AU-02", "IDT-TS-03.3"], "USAHERDS 하드코딩 머신 키"),
    "CVE-2025-14611": (_K3, ["IDT-AU-02", "IDT-TS-03.3"], "Gladinet CentreStack·Triofox 하드코딩 암호 키"),
    "CVE-2026-22769": (_K3, ["IDT-AU-02"], "Dell RecoverPoint 하드코딩 자격증명"),
    "CVE-2026-20316": (_K3, ["IDT-AU-02"], "Cisco 방화벽 관리 센터 하드코딩 비밀번호"),
    "CVE-2015-7755": (_K3, ["IDT-AU-02"], "Juniper ScreenOS 인증 우회 백도어 비밀번호"),
    "CVE-2019-18988": (_K3, ["IDT-AU-02", "IDT-CR-02.1"], "TeamViewer 공통 키로 저장 비밀번호 복호화"),
    "CVE-2020-0688": (_K3, ["IDT-AU-02", "IDT-TS-03.3"], "Exchange 설치마다 같은 검증 키(고정 키)"),
    # 디렉터리·Kerberos·NTLM
    "CVE-2020-1472": (_K4, ["IDT-DI-01.4"], "Netlogon(Zerologon) — 도메인 컨트롤러 자격증명 재설정(IDI-096)"),
    "CVE-2021-42278": (_K4, ["IDT-DI-01.4"], "AD 도메인 서비스 권한 상승(noPac)"),
    "CVE-2021-42287": (_K4, ["IDT-DI-01.4"], "AD 도메인 서비스 권한 상승(noPac)"),
    "CVE-2014-6324": (_K4, ["IDT-DI-01.4", "IDT-TS-03.1"], "Kerberos KDC PAC 위조 권한 상승(MS14-068)"),
    "CVE-2022-26923": (_K4, ["IDT-DI-01.3"], "AD 인증서 서비스 경유 권한 상승(Certifried)"),
    "CVE-2014-1812": (_K4, ["IDT-CR-02.1", "IDT-DI-01.2"], "그룹 정책 기본 설정(GPP)에 저장된 비밀번호"),
    "CVE-2021-36942": (_K4, ["IDT-TS-02.3", "IDT-DI-01.3"], "LSA 스푸핑(PetitPotam) — 강제 인증·NTLM 릴레이(IDI-118)"),
    "CVE-2022-26925": (_K4, ["IDT-TS-02.3"], "LSA 스푸핑 — 도메인 컨트롤러 NTLM 릴레이"),
    "CVE-2023-23397": (_K4, ["IDT-TS-02.3"], "Outlook 알림으로 NTLM 해시 유출"),
    "CVE-2024-43451": (_K4, ["IDT-TS-02.3"], "NTLMv2 해시 노출"),
    "CVE-2025-24054": (_K4, ["IDT-TS-02.3"], "NTLM 해시 노출"),
    "CVE-2024-21410": (_K4, ["IDT-TS-02.3"], "Exchange NTLM 릴레이 권한 상승"),
    # 서명·인증서·신원 검증 결함
    "CVE-2020-2021": (_K5, [_A42, _A41], "PAN-OS SAML 서명 검증 우회"),
    "CVE-2025-59718": (_K5, [_A42, _A41], "Fortinet 여러 제품 암호 서명 검증 결함(SSO 로그인 우회)"),
    "CVE-2026-48558": (_K5, [_A42], "SimpleHelp OIDC 인증 우회(서명 검증)"),
    "CVE-2023-29357": (_K5, [_A42, "IDT-TS-03.3"], "SharePoint 위조 JWT로 권한 상승"),
    "CVE-2019-5591": (_K5, [_A41], "FortiOS 기본 설정에서 LDAP 서버 신원 검증 누락(자격증명 가로채기)"),
    # IdP·SSO·신원 관리 제품·계정 복구
    "CVE-2021-35464": (_K6, [_A42], "ForgeRock Access Management 원격 코드 실행"),
    "CVE-2022-22954": (_K6, [_A42], "VMware Workspace ONE Access·Identity Manager 템플릿 주입"),
    "CVE-2021-22506": (_K6, [_A42], "Micro Focus Access Manager 정보 노출"),
    "CVE-2021-40539": (_K6, [_A42, "IDT-SE-03"], "ManageEngine ADSelfService Plus(셀프 비밀번호 재설정) 인증 우회"),
    "CVE-2022-28810": (_K6, [_A42, "IDT-SE-03"], "ManageEngine ADSelfService Plus 원격 코드 실행"),
    "CVE-2022-27518": (_K6, [_A42, _A41], "Citrix ADC·Gateway SAML 구성 시 인증 우회"),
    "CVE-2025-61757": (_K6, [_A42], "Oracle Fusion Middleware(Identity Manager) 인증 누락"),
    "CVE-2025-20281": (_K6, [_A41], "Cisco Identity Services Engine(네트워크 접근 인증) 주입"),
    "CVE-2025-20337": (_K6, [_A41], "Cisco Identity Services Engine 주입"),
    "CVE-2026-76460": (_K6, [_A41], "Cisco Identity Services Engine 특권 API 오용"),
    "CVE-2018-0147": (_K6, [_A41], "Cisco Secure ACS(AAA 인증 서버) 역직렬화"),
    "CVE-2026-56155": (_K6, [_A42, "IDT-DI-04"], "AD FS 접근 통제 세분화 부족"),
    "CVE-2023-7028": (_K6, ["IDT-SE-03"], "GitLab 비밀번호 재설정 메일 우회로 계정 탈취"),
    # 자격증명·인증 정보 노출
    "CVE-2018-13379": (_K7, [_A41, "IDT-AU-01.2"], "FortiOS SSL VPN 경로 조작 — 평문 VPN 자격증명 노출(IDI-091)"),
    "CVE-2024-24919": (_K7, [_A41, "IDT-CR-02.1"], "Check Point Quantum 게이트웨이 정보 노출(원격 접속 계정 해시 등)"),
    "CVE-2021-20016": (_K7, [_A41], "SonicWall SSLVPN SMA100 SQL 주입(자격증명 접근)"),
    "CVE-2019-7481": (_K7, [_A41], "SonicWall SMA100 SQL 주입"),
    "CVE-2026-20128": (_K7, ["IDT-CR-02.1"], "Cisco Catalyst SD-WAN Manager 복구 가능한 형식으로 비밀번호 저장"),
    "CVE-2021-30116": (_K7, ["IDT-CR-02.1"], "Kaseya VSA 자격증명 정보 노출"),
}

# ---------------------------------------------------------------------------
# 4) 프레임워크 항목 중 세부위협에 매핑하지 않은 것과 사유('프레임워크 연계' 시트)
# ---------------------------------------------------------------------------
FRAMEWORK_NOT_MAPPED = {
    ("asvs", "V6.1"): "인증 설계 문서화 요건 — 특정 위협과 직접 대응하지 않는 공통 요건",
    ("asvs", "V7.1"): "세션 관리 문서화 요건 — 공통 요건",
    ("asvs", "V7.3"): "세션 만료 시간 요건 — IDT-TS-01.1·01.2 대응(재인증·세션 관리)에 포함",
    ("asvs", "V7.6"): "페더레이션 재인증 — IDT-TS-01.2 대응에 간접 반영",
    ("asvs", "V10.1"): "OAuth·OIDC 공통 요건 — 세부 절(V10.2~V10.7)로 매핑",
    ("oat", "OAT-002"): "토큰 대입(쿠폰·상품권 번호) — 계정 신원보다 업무 로직 위협(범위 밖)",
    ("ccm", "IAM-01"): "정책·절차 수립 — 조직 공통 통제",
}

# 매트릭스 뷰·요약용 신원 유형 순서(적용 프로파일)
PROFILES = ID_TYPES
