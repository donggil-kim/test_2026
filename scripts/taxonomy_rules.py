# -*- coding: utf-8 -*-
"""통합 클라우드 보안위협 매트릭스 — 분류·평가 기준표"""

# ATT&CK 전술 → (도메인 코드, 한글명)
TACTIC_CODE = {
    "Resource Development": ("RD", "자원 개발"),
    "Initial Access": ("IA", "초기 침투"),
    "Execution": ("EX", "실행"),
    "Persistence": ("PE", "지속성"),
    "Privilege Escalation": ("PV", "권한 상승"),
    "Stealth": ("ST", "은닉"),
    "Defense Impairment": ("DI", "방어 무력화"),
    "Credential Access": ("CA", "자격증명 접근"),
    "Discovery": ("DS", "탐색"),
    "Lateral Movement": ("LM", "횡적 이동"),
    "Collection": ("CO", "수집"),
    "Command and Control": ("C2", "명령·제어"),
    "Exfiltration": ("EF", "반출"),
    "Impact": ("IM", "영향"),
}

# CSA Top Threats to Cloud Computing 2026 — 11대 위협
CSA_NAMES = {
    1: "부적절한 IAM", 2: "AI를 이용한 공격", 3: "안전하지 않은 서드파티 리소스",
    4: "안전하지 않은 인터페이스·API", 5: "잘못된 구성·변경통제 미흡", 6: "AI 시스템 침해",
    7: "APT", 8: "클라우드 보안전략·거버넌스 부재", 9: "안전하지 않은 소프트웨어 개발",
    10: "의도치 않은 클라우드 데이터 노출", 11: "시스템 취약점",
}

# CSA 이슈별 연계 기준(CSA 2026 연계 시트 '연계 기준' 열). 미기재 이슈는 아래 CSA_MAP의 기법 주제 기준
CSA_NOTE = {
    2: "기법 비종속 교차 위협(공격자가 AI로 기존 기법을 가속·자동화) — 개별 세부위협 미연계, 보고서 사례로만 참조",
    6: "AI 시스템 자체 위협(프롬프트 주입·모델/데이터 오염·에이전트 악용)은 통합 AI 매트릭스 v3.2(UT) 영역 — "
       "본 매트릭스는 관리형 AI 자원 악용(LLMjacking, T1496.004)만 연계",
    8: "비기술 거버넌스 위협 — 개별 세부위협 미연계, 보고서 사례로만 참조",
}

# ATT&CK 기법 → CSA 이슈. 하위기법 키가 있으면 상위기법 매핑을 대체
# (SI-02·SI-08은 기법 비종속 교차 위협이라 개별 매핑하지 않음)
CSA_MAP = {
    "T1078": [1, 7], "T1098": [1], "T1136": [1], "T1556": [1], "T1528": [1, 3],
    "T1550": [1], "T1621": [1], "T1548": [1], "T1484": [1, 5], "T1606": [1],
    "T1539": [1], "T1555": [1, 10], "T1649": [1], "T1110": [1], "T1566": [1],
    "T1671": [1, 3], "T1087": [1], "T1069": [1],
    "T1195": [3, 9], "T1199": [3, 7], "T1525": [3], "T1204": [3], "T1072": [3],
    "T1190": [4, 11], "T1059": [4], "T1651": [4], "T1648": [4], "T1538": [4],
    "T1580": [4, 5], "T1526": [4, 5],
    "T1578": [5], "T1619": [5, 10], "T1530": [5, 10], "T1535": [5], "T1666": [5],
    "T1685": [5], "T1686": [5], "T1537": [5, 10],
    # 자원 악용(T1496)은 영향 기법이라 다른 영향 기법(T1485·T1486 등)처럼 상위기법은 미연계 —
    # 침투 경로(취약점·노출 서비스·자격증명)는 사고마다 달라 기법 단위로 붙이면 SI별 사고 수가 부풀려짐.
    # 기법 정의 자체가 약점을 특정하는 하위기법만 연계: SMS 펌핑 = 레이트 제한 없는 API(SI-04),
    # LLMjacking = 탈취 키로 관리형 AI 자원 악용(SI-01·SI-06). SI-06은 이 행에만 연계
    "T1496.003": [4], "T1496.004": [1, 6],
    "T1552": [9, 10], "T1213": [9, 10], "T1677": [9],
    "T1210": [11], "T1211": [11], "T1212": [11], "T1687": [11],
    "T1021": [7], "T1114": [7, 10], "T1119": [10], "T1567": [10], "T1048": [10],
}

# 통합 AI 보안위협 매트릭스 v3.2 연계(UT-ID)
AI_UT_MAP = {
    "T1496.004": "UT-30.2 과금 폭탄",
    "T1195.002": "UT-28.2 악성 의존성 유입",
    "T1677": "UT-28.5 배포 파이프라인 악용",
    "T1552.001": "UT-25.1 평문 저장 자격증명 수집",
    "T1528": "UT-25.3 인증 토큰 및 세션 쿠키 탈취",
    "T1078.004": "UT-25.4 탈취 자격증명 재사용",
    "T1190": "UT-02.4 일반 초기 침투 · UT-31.1 외부 노출 AI 서비스",
}

# 전술 기준 심각도
TACTIC_SEVERITY = {
    "Impact": "상", "Credential Access": "상", "Exfiltration": "상",
    "Initial Access": "상", "Privilege Escalation": "상",
    "Persistence": "중", "Lateral Movement": "중", "Collection": "중",
    "Execution": "중", "Defense Impairment": "중", "Stealth": "중",
    "Command and Control": "중", "Discovery": "하", "Resource Development": "하",
}

_HIGH = {
    "데이터 파괴·암호화·서비스 중단으로 업무 영속성 직접 훼손": ["T1485", "T1486", "T1490", "T1489", "T1531", "T1491"],
    "클라우드 자원·과금 대량 손실": ["T1496", "T1657"],
    "민감 데이터 대량 유출": ["T1530", "T1213", "T1537", "T1567"],
    "자격증명·토큰·키 탈취로 계정·테넌트 장악 가능": ["T1555", "T1552", "T1528", "T1550", "T1649", "T1606", "T1539", "T1621"],
    "권한·신뢰 관계 변경으로 계정·테넌트 장악 가능": ["T1098", "T1078", "T1484", "T1666", "T1548"],
    "외부에서 환경 진입 경로 확보": ["T1190", "T1195", "T1199"],
}
_LOW = {
    "열람·탐색 위주로 직접 피해 없음(후속 공격 준비)": [
        "T1087", "T1069", "T1526", "T1580", "T1538", "T1619", "T1082", "T1518",
        "T1201", "T1049", "T1046", "T1614", "T1654", "T1680", "T1613"],
}

# 상위기법 ID → (심각도, 근거)
SEVERITY = {}
for why, ids in _HIGH.items():
    for t in ids:
        SEVERITY[t] = ("상", why)
for why, ids in _LOW.items():
    for t in ids:
        SEVERITY[t] = ("하", why)

# ATT&CK v19.2에서 폐기·이동된 ID 변환
DEPRECATED = {
    "T1562": "T1685", "T1562.001": "T1685", "T1562.008": "T1685.002",
    "T1562.007": "T1686.001",
}

# ---------------------------------------------------------------------------
# v3 클라우드 특화 검토 — 삭제·통합 판정
#   DROP  : 클라우드 맥락이 없는 일반 엔터프라이즈 기법, 연결용 상위기법
#   MERGE : 원 기법 → 통합 대상 기법 (근거·벤더 항목은 대상 행으로 합산)
# ---------------------------------------------------------------------------
DROP = {
    "T1189",   # Drive-by Compromise
    "T1211",   # Exploitation for Stealth
    "T1687",   # Exploitation for Defense Impairment
    "T1212",   # Exploitation for Credential Access
    "T1040",   # Network Sniffing
    "T1201",   # Password Policy Discovery
    "T1680",   # Local Storage Discovery
    "T1048",   # Exfiltration Over Alternative Protocol
    "T1036", "T1686", "T1020",   # 연결용 상위기법(하위기법만 유지)
}
MERGE = {
    # 클라우드 외 연관 → 클라우드 관련 기법으로
    "T1583": "T1583.001", "T1543": "T1543.005", "T1546.004": "T1546",
    "T1021.004": "T1609", "T1078.003": "T1098.003",
    # 상위기법 '(일반)' 행 → 클라우드 하위기법
    "T1078": "T1078.004", "T1059": "T1059.009", "T1098": "T1098.001",
    "T1136": "T1136.003", "T1578": "T1578.002", "T1555": "T1555.006",
    "T1087": "T1087.004", "T1069": "T1069.003", "T1550": "T1550.001",
    "T1110": "T1110.001", "T1110.002": "T1110.001", "T1074": "T1074.002",
    # 일반 탐색 → 클라우드 인프라·서비스 탐색
    "T1046": "T1580", "T1082": "T1580", "T1614": "T1580", "T1049": "T1580",
    "T1518": "T1526", "T1518.001": "T1526",
    # 서비스 거부 하위기법 통합
    "T1498": "T1499", "T1498.001": "T1499", "T1498.002": "T1499",
    "T1499.002": "T1499", "T1499.003": "T1499", "T1499.004": "T1499",
    # 기타
    "T1491.002": "T1491", "AZT704.3": "AZT704",
}

# 통합으로 범위가 넓어진 행의 이름 보정
NAME_OVERRIDE = {"T1499": "Denial of Service (Endpoint·Network 통합)"}

# ---------------------------------------------------------------------------
# 사고 DB 키워드 매핑(v5) — 초안 ATT&CK ID를 보완하는 2차 매핑
#   (기법, 키워드 정규식, 조건) — 키워드는 사고 제목·요약·원문 필드(초기침투·확산·영향·사용 기법·공격 대상·도구)에서
#   대소문자 무시로 찾는다. 조건: root(근본원인)·layer(서비스 계층)·impact(영향유형)는 나열값 중 하나 포함,
#   skip_kind는 해당 사례유형 제외, neg는 일치하면 제외하는 정규식.
#   초안에 상위기법만 있고 키워드가 하위기법을 가리키면 상위 태그를 하위기법으로 세분한다(근거 '초안ID→키워드 세분').
#   하위기법 규칙을 상위기법 규칙보다 먼저 둔다(하위기법이 잡히면 상위기법은 붙이지 않음).
# ---------------------------------------------------------------------------
_A, _Z = r"(?<![a-z0-9])", r"(?![a-z0-9])"   # ASCII 경계(한글 조사가 붙어도 동작)
_MAIL = r"(" + _A + r"ses" + _Z + r"|simple email service|sendgrid|mailgun|workmail)"
_ABUSE = r"(악용|abus|발송|스팸|spam|피싱|phish|노리|노렸|탈취|exploit|hijack|bec)"

KEYWORD_RULES = [
    # 자원 악용(T1496) 세분
    ("T1496.001", r"crypto ?jack|crypto-?min|coin ?min(er|ing)|크립토재킹|크립토마이닝|채굴|xmrig|monero|모네로|coinhive|"
                  + _A + r"mining" + _Z + r"|miners?" + _Z + r"|마이너|kinsing|teamtnt|graboid|cetus|8220 gang|headcrab|bondnet|c3pool", {}),
    ("T1496.002", r"proxy-?jack|프록시재킹|proxyware|프록시웨어|bandwidth (hijack|shar)|대역폭(을)? (판매|공유|탈취)|"
                  r"(ddos|디도스)[^.]{0,40}(봇넷|botnet|kaiji|gafgyt|mirai|lucifer)|(봇넷|botnet|kaiji|gafgyt|mirai|lucifer)[^.]{0,40}(ddos|디도스)|"
                  r"외부 대상 ddos|mineping", {}),
    ("T1496.003", r"sms ?pump|sms 펌핑|toll fraud", {}),
    ("T1496.004", r"llm ?jack|llm재킹|bedrock|invokemodel|" + _MAIL + r"[^.]{0,40}" + _ABUSE + r"|" + _ABUSE + r"[^.]{0,15}" + _MAIL, {}),
    ("T1496", r".", dict(impact=["자원 탈취", "Denial of wallet"])),

    # 피싱(T1566) 세분
    ("T1566.004", r"vishing|비싱|voice phish|음성 피싱|전화(로|를 걸|통화)|phone call", {}),
    ("T1566.002", r"phishing (link|url|page|site)|피싱 (링크|사이트|페이지)|악성 링크|malicious link|가짜 로그인|fake login|smishing|스미싱", {}),
    ("T1566", r"피싱|phish|스미싱|smish|비싱|vish", dict(root=["최종사용자 침해"])),

    # 무차별 대입
    ("T1110.003", r"password spray|(패스워드|비밀번호) 스프레이", {}),
    ("T1110.004", r"credential stuffing|(크리덴셜|자격증명) 스터핑", {}),
    ("T1110.001", r"brute ?forc|무차별 대입|password guess|약한 (비밀번호|패스워드)|weak password", {}),

    # 자격증명 접근
    ("T1552.005", _A + r"imds" + _Z + r"|169\.254\.169\.254|instance metadata|메타데이터 (서비스|엔드포인트|api)|metadata (service|endpoint)", {}),
    ("T1552.001", r"(github|gitlab|bitbucket|gist|커밋|commit|저장소|repo|소스 ?코드|source code|\.env|환경 ?변수|설정 파일|config(uration)? file|pastebin|postman|docker ?hub|apk|javascript|js 파일|html)"
                  r"[^.]{0,40}(자격증명|credential|access key|액세스 키|api 키|api key|secret|시크릿|(?<!oauth )(토큰|token)|private key|비밀번호|password)|"
                  r"(credentials?|access keys?|secrets?|tokens?) (in|on|from|committed to|exposed (in|on|via)|stolen from|leaked (in|on|via)|stored in)[^.]{0,20}"
                  r"(github|gitlab|repo|code|commit|file|gist|apk|javascript|html)", {}),
    ("T1555.006", r"secrets? manager|key vault|키 ?볼트", {}),
    ("T1528", r"(oauth|앱|app|통합|integration|커넥터|connector)[^.]{0,20}(토큰|token)[^.]{0,20}(탈취|도난|stolen|steal|유출|leak|침해|compromis)", {}),
    ("T1539", r"세션 (쿠키|토큰)(을|를)? (탈취|도난|훔)|session (cookie|token)s? (theft|stolen|hijack)|쿠키(를)? (탈취|도난)|cookie theft|세션 하이재킹|session hijack", {}),
    ("T1606.002", r"golden saml|saml (토큰 )?(위조|forg)|token signing", {}),
    ("T1557", r"aitm|adversary-in-the-middle|evilginx|중간자|dns (하이재킹|hijack)|man-in-the-middle|" + _A + r"mitm" + _Z, {}),

    # 유효 계정·지속성·권한
    ("T1078.004", r"access key|액세스 키|(aws|azure|gcp|iam|클라우드) (자격증명|credential|계정|account|키|key)|root credential|루트 (계정|자격증명)|"
                  r"서비스 계정 키|service account key|콘솔 (자격증명|계정|로그인)|console credential",
     dict(root=["자격증명", "패스워드 공격", "내부자"], skip_kind=["연구·노출"])),
    ("T1136.003", r"create new cloud user|creat(e|ed) (an? )?(new )?(administrator |admin )?iam user|created additional account|createuser|"
                  r"iam 사용자(를)? (생성|만들)|(새|신규|백도어) (관리자 )?iam (사용자|계정)", {}),
    ("T1098.003", r"attach administrative role|administratoraccess|관리자 (권한|역할|정책)(을|를)? (부여|연결|추가)", {}),
    ("T1098.001", r"createaccesskey|create(d)? (new )?access keys?|액세스 키(를)? (추가 )?(생성|발급)|새 액세스 키|추가 계정과 액세스 키를 생성", {}),
    ("T1098.004", r"ssh backdoor|authorized_keys|ssh 키(를)? (추가|등록)", dict(neg=r"ebury|windigo")),
    ("T1098.005", r"mfa enrollment|mfa (장치|디바이스|기기)(를)? (등록|추가)|device registration|장치 등록|device enrollment", {}),
    ("T1484.002", r"attacker-controlled idp|공격자(가)? (제어|통제)하는 idp|페더레이션 (신뢰|도메인|설정)(을|를)? (추가|변경)", {}),
    ("T1556.007", r"pass-?through auth|ad ?connect|entra connect", {}),

    # 초기 침투
    ("T1190", r"cve-\d{4}-\d+|" + _A + r"rce" + _Z + r"|원격 코드 실행|remote code execution|sql injection|sql 인젝션|ssrf|역직렬화|deserializ|"
              r"1-day|0-day|zero-?day|제로데이|web vulnerability|웹 취약점|" + _A + r"xxe" + _Z + r"|익스플로잇|exploit",
     dict(root=["취약점 악용"], layer=["노출 워크로드", "엣지·네트워크 장비"], neg=r"xz utils|backdoor \(cve|공급망 (침해|공격)|supply chain")),
    ("T1133", r"(docker|도커) ?(api|데몬|daemon|엔진|engine)|kubelet|(k8s|kubernetes|쿠버네티스) (api|대시보드|dashboard|console|콘솔)|weave scope|"
              + _A + r"vpn (자격증명|credential|계정|account)|(노출|exposed|인증(이)? 없는|unauthenticated)[^.]{0,20}(제어 평면|control plane)", {}),
    ("T1195.002", r"npm|pypi|rubygems|crates|nuget|maven|패키지|package|의존성|dependency|github action|액션|이미지|image|플러그인|plugin|확장|extension|"
                  r"메인테이너|maintainer|라이브러리|library|업데이트|update|빌드|build|" + _A + r"sdk" + _Z,
     dict(root=["공급망·서드파티"], layer=["패키지·공급망"], neg=r"oauth (토큰|token|통합|integration)")),
    ("T1677", r"pull_request_target|워크플로(우)?[^.]{0,15}(취약|주입|오염|악용)|workflow (injection|poison)|github actions?[^.]{0,30}(악용|취약|탈취|주입|오염|캐시|cache)|"
              r"cache poison|캐시 오염|태그 포이즈닝|tag poison|runner abuse", {}),
    ("T1199", r"(서드파티|third[- ]party|파트너|협력(사|업체)|공급업체|계약업체|contractor|" + _A + r"vendor|" + _A + r"msp" + _Z + r"|제공업체|위탁|아웃소싱)"
              r"[^.]{0,15}(침해|compromis|통해|경유|로부터|via|account|abus|악용)",
     dict(root=["공급망·서드파티"])),

    # 실행·은닉·방어 무력화
    ("T1610", r"(악성|malicious|채굴)[^.]{0,20}(컨테이너|container)[^.]{0,15}(배포|실행|생성|deploy|run|launch|투입)|(악성|malicious)[^.]{0,10}(docker )?(이미지|image)[^.]{0,20}(투입|배포|deploy)",
     dict(neg=r"docker ?hub (계정|account)(으로|로)")),
    ("T1204.003", r"docker ?hub (계정|account)[^.]{0,20}(악성|malicious)", {}),
    ("T1611", r"escape to host|컨테이너 탈출|container escape|호스트(로)? 탈출|release_agent|host mount", {}),
    ("T1053", r"cron persistence|crontab|크론(탭)?|cron job|" + _A + r"cron" + _Z, {}),
    ("T1648", r"(lambda|cloud functions?|azure functions?|서버리스|serverless)[^.]{0,20}(실행|생성|주입|변조|수정|지속성|악용|백도어|배포|표적|"
              r"modif|inject|persist|abuse|backdoor|deploy|creat|execut)", {}),
    ("T1651", r"send-?command|run commands?|systems manager|" + _A + r"ssm" + _Z + r"|remotely execute commands or scripts on a vm", {}),
    ("T1059.009", r"cloud api e|aws cli|" + _A + r"az cli|gcloud|pacu", {}),
    ("T1072", r"intune|" + _A + r"sccm" + _Z + r"|kaseya|jamf", {}),
    ("T1090", r"tor anonymiz|" + _A + r"tor" + _Z + r" (네트워크|노드|를 통해)|residential prox|주거용 프록시", {}),
    ("T1578.001", r"(스냅샷|snapshot)(을|를)? (생성|만들|create)|create(d)? (an? )?(ebs )?snapshot", {}),
    ("T1578.002", r"launch new cloud resources|(인스턴스|instance|ec2|가상 ?머신)(\s?\d+대)?(을|를|가|이)? (생성|만들|기동|launch)|create(d)? (new )?(ec2 )?instances?|runinstances", {}),
    ("T1578.005", r"(할당량|quota|service limit|서비스 한도)[^.]{0,20}(상향|증가|increase|raise)", {}),
    ("T1686.001", r"security group|보안 그룹|firewall rule|방화벽 (규칙|정책)", {}),
    ("T1685.002", r"disable logging|cloudtrail[^.]{0,20}(중지|삭제|비활성|stop|delet|disabl)|(로깅|로그 수집)(을|를)? (중지|비활성|끄)|stoplogging|deletetrail", {}),
    ("T1684.001", r"사칭", {}),
    ("T1583.001", r"유사 도메인|lookalike domain|도메인(을|를)? (등록|구매)|피싱용 도메인|domain registra", {}),
    ("T1580", r"getcalleridentity|get-caller-identity|describe-?instances|list-?buckets|pacu|scoutsuite|cloudfox|클라우드 (자원|인프라|환경)[^.]{0,10}(탐색|열거|정찰)", {}),

    # 수집·반출
    ("T1530", r"(" + _A + r"s3" + _Z + r"|버킷|bucket|blob|스토리지 (계정|컨테이너)|storage account|" + _A + r"gcs" + _Z + r"|cloud storage|google drive|onedrive)"
              r"[^.]{0,40}(유출|탈취|접근|열람|다운로드|노출|exfil|download|access|expos|stolen|훔|leak)",
     dict(impact=["데이터 유출", "연구·책임있는 공개"], neg=r"삽입|변조|inject|쓰기 권한|write access|탈취 데이터가 담긴")),
    ("T1213.006", r"(elasticsearch|mongodb|clickhouse|redis|postgres|mysql|" + _A + r"rds" + _Z + r"|redshift|dynamodb|cosmos ?db|firebase|supabase|데이터베이스|database|" + _A + r"db" + _Z + r")"
                  r"[^.]{0,30}(유출|탈취|접근|덤프|dump|exfil|복사|copy|leak|expos|노출|조회|훔|stolen|download|다운로드|스냅샷)",
     dict(impact=["데이터 유출", "연구·책임있는 공개"])),
    ("T1213.003", r"(비공개|private|내부|internal) (github )?(저장소|repo|레포)|코드 저장소|code repositor|소스 ?코드(를|가)? (탈취|유출|복제|도난)|source code (theft|stolen|leak|exfil)", {}),
    ("T1213.004", r"(salesforce|" + _A + r"crm" + _Z + r"|hubspot|zendesk)[^.]{0,40}(데이터|data|레코드|record|조회|탈취|유출|exfil|접근|access|인스턴스|instance|조직)",
     dict(neg=r"(hubspot|salesforce)\s?(폼|form)")),
    ("T1114.003", r"(전달|forwarding|forward) (규칙|rule)|inbox rule|받은 편지함 규칙", {}),
    ("T1114.002", r"(메일함|mailbox|이메일|email)[^.]{0,20}(접근|열람|수집|탈취|exfil|dump)", {}),
    ("T1567", r"rclone|" + _A + r"mega" + _Z + r"|transfer\.sh|gofile|file\.io|telegram bot|텔레그램 봇", {}),
    ("T1537", r"(외부|공격자(의)?|다른) (aws |클라우드 )?계정(으로|에)[^.]{0,20}(공유|복사|전송)|share(d)? (snapshot|ami)s?", {}),

    # 영향
    ("T1486", r"랜섬웨어|ransomware|ransomop|(데이터|파일|버킷|객체|디스크|데이터베이스|서버|vm|가상 ?머신)(를|을)? (모두 )?암호화(했|하|해)|sse-c",
     dict(neg=r'"랜섬웨어"형|랜섬웨어로 버킷이 삭제|ransomware scam')),
    ("T1485.001", r"lifecycle (policy|rule|configuration)|수명 ?주기 (정책|규칙)", {}),
    ("T1485", r"data destruction|데이터(를)? (파괴|삭제)|disk wipe|wiped|wiper|와이퍼|(서버|인스턴스|버킷|데이터|저장소|repositor|database|데이터베이스|구성요소)[^.]{0,20}(삭제|delet)|"
              r"delet(ed|ion)[^.]{0,20}(server|instance|bucket|data|repo|database)|유출·삭제", {}),
    ("T1490", r"(백업|backup|스냅샷|snapshot|복구 지점|recovery point)[^.]{0,20}(삭제|delet|비활성|disabl)", {}),
    ("T1657", r"cryptocurrency (theft|stolen)|(암호화폐|가상자산)(\s?지갑)?(이|가|을|를)?\s?(\S+\s)?(탈취|도난|훔)|extortion|갈취|협박|몸값|ransom note|랜섬 노트|wire fraud|송금 사기", {}),
    ("T1491", r"defac|웹 ?변조|홈페이지 변조", {}),
]
