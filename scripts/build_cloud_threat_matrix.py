# -*- coding: utf-8 -*-
"""
통합 클라우드 보안위협 매트릭스 빌더
----------------------------------
뼈대   : MITRE ATT&CK Cloud 킬체인(전술 → 기법 → 하위기법/벤더 항목)
교차   : AWS TTC · Azure ATRM · K8s 매트릭스 · CSA Top Threats 2026
근거   : ATT&CK 클라우드 실제 사례 + 클라우드 보안사고 DB(680건)
논리   : 통합 AI 보안위협 매트릭스 v3.2의 위험평가·근거수준 로직을 이식

입력(data/):
  - Cloud_ATTACK_Matrix_Integrated_v19.2.xlsx  (사용자 파생 ATT&CK+벤더 통합본)
  - Cloud_IncidentDB_v2_LITE.xlsx              (클라우드 보안사고 DB)
출력(output/):
  - 통합_클라우드보안위협_매트릭스_v1.xlsx
"""
import openpyxl, re, collections, datetime, os
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_MATRIX = os.path.join(HERE, "data", "Cloud_ATTACK_Matrix_Integrated_v19.2.xlsx")
SRC_INC    = os.path.join(HERE, "data", "Cloud_IncidentDB_v2_LITE.xlsx")
OUT        = os.path.join(HERE, "output", "통합_클라우드보안위협_매트릭스_v1.xlsx")

# ----------------------------------------------------------------------------
# 전술 → 도메인 코드 / 한글명
# ----------------------------------------------------------------------------
TACTIC_CODE = {
    "Resource Development": ("RD", "자원 개발"),
    "Initial Access":       ("IA", "초기 침투"),
    "Execution":            ("EX", "실행"),
    "Persistence":          ("PE", "지속성"),
    "Privilege Escalation": ("PV", "권한 상승"),
    "Stealth":              ("ST", "은닉(탐지 회피)"),
    "Defense Impairment":   ("DI", "방어 무력화"),
    "Credential Access":    ("CA", "자격증명 접근"),
    "Discovery":            ("DS", "탐색"),
    "Lateral Movement":     ("LM", "횡적 이동"),
    "Collection":           ("CO", "수집"),
    "Command and Control":  ("C2", "명령·제어"),
    "Exfiltration":         ("EF", "반출"),
    "Impact":               ("IM", "영향"),
}
# 킬체인 표시 순서
TACTIC_ORDER = ["Resource Development","Initial Access","Execution","Persistence",
    "Privilege Escalation","Credential Access","Discovery","Lateral Movement",
    "Collection","Command and Control","Exfiltration","Stealth","Defense Impairment","Impact"]

# ----------------------------------------------------------------------------
# CSA Top Threats to Cloud Computing 2026 (11대 위협) 연계
#   기법(상위 ATT&CK ID) → 해당 CSA 이슈 번호 목록
# ----------------------------------------------------------------------------
CSA_NAMES = {
    1:"부적절한 IAM", 2:"AI를 이용한 공격", 3:"안전하지 않은 서드파티 리소스",
    4:"안전하지 않은 인터페이스·API", 5:"잘못된 구성·변경통제 미흡", 6:"AI 시스템 침해",
    7:"APT", 8:"클라우드 보안전략·거버넌스 부재", 9:"안전하지 않은 소프트웨어 개발",
    10:"의도치 않은 클라우드 데이터 노출", 11:"시스템 취약점",
}
CSA_MAP = {
    # SI-01 IAM 관련 (신원·자격증명·권한)
    "T1078":[1,7], "T1098":[1], "T1136":[1], "T1556":[1], "T1528":[1,3],
    "T1550":[1], "T1621":[1], "T1548":[1], "T1484":[1,5], "T1606":[1],
    "T1539":[1], "T1555":[1,10], "T1649":[1], "T1110":[1], "T1671":[1,3],
    "T1087":[1], "T1069":[1], "T1621.000":[1],
    # SI-03 서드파티
    "T1195":[3,9], "T1199":[3,7], "T1525":[3], "T1072":[3],
    # SI-04 인터페이스·API
    "T1190":[4,11], "T1059":[4], "T1651":[4], "T1538":[4], "T1580":[4,5], "T1526":[4,5],
    # SI-05 오설정·변경통제
    "T1578":[5], "T1619":[5,10], "T1530":[5,10], "T1535":[5], "T1666":[5],
    "T1562":[5], "T1685":[5], "T1686":[5], "T1537":[5,10], "T1646":[5],
    # SI-06 AI 시스템 침해 (클라우드 LLM/모델 서비스)
    "T1496":[6,2],
    # SI-09 안전하지 않은 개발 (SSRF/IMDS/코드저장소)
    "T1552":[9,10], "T1213":[9,10],
    # SI-11 시스템 취약점
    "T1210":[11], "T1211":[11], "T1212":[11], "T1203":[11], "T1068":[11],
    # 수집/반출 → 데이터 노출
    "T1119":[10], "T1114":[10], "T1074":[10], "T1048":[10], "T1567":[10],
}

# ----------------------------------------------------------------------------
# 심각도 기준: 전술 baseline + 고영향 기법 가중
# ----------------------------------------------------------------------------
TACTIC_SEVERITY = {
    "Impact":"상", "Credential Access":"상", "Exfiltration":"상",
    "Initial Access":"상", "Privilege Escalation":"상",
    "Persistence":"중", "Lateral Movement":"중", "Collection":"중",
    "Execution":"중", "Defense Impairment":"중", "Stealth":"중",
    "Discovery":"하", "Resource Development":"하", "Command and Control":"중",
}
# 특정 상위 기법 심각도 상향(상) — 데이터/파괴/핵심자원
SEV_HIGH = {"T1485","T1486","T1491","T1496","T1490","T1489","T1531","T1657",
    "T1530","T1213","T1537","T1555","T1552","T1528","T1098","T1078","T1484",
    "T1190","T1195","T1199","T1666","T1621","T1550","T1649"}
# 심각도 하향(하) — 탐색/열람 위주
SEV_LOW = {"T1087","T1069","T1526","T1580","T1538","T1619","T1082","T1518",
    "T1201","T1049","T1046","T1614","T1654","T1680","T1613"}

RISK_MATRIX = {  # (발생가능성, 심각도) -> 위험도
    ("상","상"):"매우 높음", ("상","중"):"높음",  ("상","하"):"보통",
    ("중","상"):"높음",     ("중","중"):"보통",  ("중","하"):"낮음",
    ("하","상"):"보통",     ("하","중"):"낮음",  ("하","하"):"낮음",
}

def parent_tid(tid):
    return tid.split(".")[0] if tid and tid.startswith("T") else tid

# ----------------------------------------------------------------------------
# 1) 사고 DB 적재 : 기법별 사고 건수 + 대표 예시
# ----------------------------------------------------------------------------
def load_incidents():
    wb = openpyxl.load_workbook(SRC_INC, read_only=True)
    rows = list(wb.worksheets[0].iter_rows(min_row=2, values_only=True))
    by_tid = collections.defaultdict(list)   # tid -> [incident dict]
    all_inc = []
    for r in rows:
        rec = dict(id=r[0], title=r[1], summary=r[2], kind=r[3], src=r[4],
                   org=r[5], actor=r[6], date=r[7], rel=r[8], layer=r[9],
                   root=r[10], impact=r[12], att=r[21])
        all_inc.append(rec)
        if r[21]:
            for t in set(re.findall(r"T\d{4}(?:\.\d{3})?", r[21])):
                by_tid[t].append(rec)
                p = parent_tid(t)
                if p != t:
                    by_tid[p].append(rec)
    return all_inc, by_tid

# ----------------------------------------------------------------------------
# 2) ATT&CK 통합 매트릭스 적재 : 전술/기법/하위기법 계층
# ----------------------------------------------------------------------------
def load_matrix():
    wb = openpyxl.load_workbook(SRC_MATRIX, read_only=True)
    ws = wb["통합 매트릭스"]
    rows = []
    for r in ws.iter_rows(min_row=2, values_only=True):
        rows.append(r)
    # 하위기법을 가진 상위기법 id 집합(= Lv2 그룹)
    has_child = set()
    for r in rows:
        gubun = r[1] or ""
        if "하위기법" in gubun:
            m = re.match(r"(T\d{4})\.", (r[2] or ""))
            if m: has_child.add(m.group(1))
    return rows, has_child

def vendor_items(cell):
    """벤더 셀에서 '• ID 이름: ...' 항목 수와 ID 목록 추출"""
    if not cell: return 0, []
    ids = re.findall(r"•\s*([A-Za-z0-9.\-]+)\s", cell)
    return len(ids), ids

# ----------------------------------------------------------------------------
# 3) 평가 로직
# ----------------------------------------------------------------------------
def evidence_level(inc, atk, vendor_n, scope):
    if inc >= 1:      return "실제 사고 확인"
    if atk >= 1:      return "실사용 기법 포함"
    if vendor_n >= 1: return "실증·공개 취약점"
    return "이론·시나리오"

def likelihood(inc, atk, vendor_n):
    if inc >= 5 or atk >= 10:            return "상"
    if inc >= 1 or atk >= 4 or vendor_n >= 2: return "중"
    if atk >= 1 or vendor_n >= 1:        return "중"
    return "하"

def severity(tid, tactic):
    p = parent_tid(tid)
    if p in SEV_HIGH: return "상"
    if p in SEV_LOW:  return "하"
    return TACTIC_SEVERITY.get(tactic, "중")

def likelihood_reason(inc, atk, vendor_n):
    return f"실제 사고 {inc}건 · ATT&CK 클라우드 사례 {atk}건 · 벤더 특화기법 {vendor_n}건"

def csa_tags(tid):
    return sorted(set(CSA_MAP.get(parent_tid(tid), [])))

# ----------------------------------------------------------------------------
# 4) 매트릭스 조립
# ----------------------------------------------------------------------------
def build():
    all_inc, by_tid = load_incidents()
    rows, has_child = load_matrix()

    tactic_seq = collections.Counter()   # 전술별 기법 순번
    sub_seq = collections.Counter()      # Lv2별 하위 순번
    cur_tactic = None
    cur_tactic_label = None
    cur_lv2 = None                        # 현재 Lv2 (기법) 정보
    out = []                              # 최종 Lv3 행 목록
    domains = []                          # 전술 도메인 메타

    for r in rows:
        tactic, gubun, tid, name = r[0], (r[1] or ""), (r[2] or ""), (r[3] or "")
        summary, scope = r[4], (r[5] or "")
        plat_cloud, plat_other = r[6], r[7]
        aws, azure, k8s = r[8], r[9], r[10]
        cases_txt, atk_cases = r[11], (r[12] or 0)
        link, raw_en = r[13], r[14]

        if gubun == "전술":
            cur_tactic = tactic
            code = TACTIC_CODE.get(tactic, ("XX",tactic))[0]
            cur_tactic_label = f"[{code}] {TACTIC_CODE.get(tactic,('',tactic))[1]}"
            domains.append(dict(tactic=tactic, code=code, name=name, summary=summary,
                                link=link, order=TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else 99))
            continue

        # 기법명 추출 (ID 제거)
        disp = re.sub(r"^"+re.escape(tid)+r"\s*", "", name).strip() if tid else name
        pt = parent_tid(tid)
        is_sub = "하위기법" in gubun
        is_leaf = True
        # 상위기법인데 하위기법을 가지면 Lv2 그룹(리프 아님)
        if (gubun.startswith("기법")) and pt in has_child and "연결용" not in gubun:
            # Lv2 헤더로 기록하고 리프 생성 안 함
            code = TACTIC_CODE.get(cur_tactic,("XX",""))[0]
            tactic_seq[cur_tactic]+=1
            n2 = tactic_seq[cur_tactic]
            cur_lv2 = dict(code=f"CTC-{code}-{n2:02d}", name=disp, tid=tid)
            sub_seq[cur_lv2["code"]] = 0
            continue

        code = TACTIC_CODE.get(cur_tactic,("XX",""))[0]
        # Lv2 결정
        if is_sub and cur_lv2 and cur_lv2["tid"] == pt:
            lv2 = cur_lv2
        else:
            # 하위기법 없는 기법 또는 벤더 전용(미대응) → 자신이 Lv2
            tactic_seq[cur_tactic]+=1
            n2 = tactic_seq[cur_tactic]
            lv2 = dict(code=f"CTC-{code}-{n2:02d}", name=disp, tid=tid)
            cur_lv2 = lv2
            sub_seq[lv2["code"]] = 0

        # Lv3 ID
        if is_sub and lv2 is cur_lv2 and lv2["tid"] == pt:
            sub_seq[lv2["code"]] += 1
            ctc = f"{lv2['code']}.{sub_seq[lv2['code']]}"
            lv3_name = disp
        else:
            ctc = lv2["code"]
            lv3_name = disp

        av_n,av=vendor_items(aws); az_n,az=vendor_items(azure); k_n,k=vendor_items(k8s)
        vendor_n = av_n+az_n+k_n
        incs = by_tid.get(tid, [])
        # 하위기법이면 자신 id만, 상위-전용 리프면 자신 id 사례
        inc_n = len({x["id"] for x in incs})
        atk = int(atk_cases) if isinstance(atk_cases,(int,float)) else 0

        lvl = evidence_level(inc_n, atk, vendor_n, scope)
        lk = likelihood(inc_n, atk, vendor_n)
        sv = severity(tid, cur_tactic)
        risk = RISK_MATRIX[(lk,sv)]
        csa = csa_tags(tid)
        csa_label = " · ".join(f"SI-{i:02d} {CSA_NAMES[i]}" for i in csa)

        # 대표 사례 예시(최대 3건, 최신순)
        def dkey(x):
            return str(x["date"] or "")
        ex = sorted({x["id"]:x for x in incs}.values(), key=dkey, reverse=True)[:3]
        ex_txt = "\n".join(
            f"- [{e['date']}] {e['title']} ({e['id']}, 출처:{e['src']}): {(e['summary'] or '')[:160]}"
            for e in ex)
        inc_ids = ", ".join(sorted({x["id"] for x in incs}))

        out.append(dict(
            tactic=cur_tactic, domain=cur_tactic_label,
            ctc=ctc, lv2=lv2["name"], lv2code=lv2["code"], lv3=lv3_name,
            tid=tid, gubun=gubun, scope=scope,
            plat_cloud=plat_cloud or "", plat_other=plat_other or "",
            aws="\n".join(av), azure="\n".join(az), k8s="\n".join(k),
            vendor_n=vendor_n, csa=csa_label,
            summary=(summary or "").strip(),
            likelihood=lk, severity=sv, risk=risk,
            lk_reason=likelihood_reason(inc_n, atk, vendor_n),
            atk_cases=atk, inc_cases=inc_n, level=lvl,
            inc_ids=inc_ids, examples=ex_txt, link=link,
        ))
    return domains, out, all_inc, by_tid

if __name__ == "__main__":
    domains, out, all_inc, by_tid = build()
    print("도메인(전술):", len(domains))
    print("세부위협(Lv3) 행:", len(out))
    import collections as C
    print("위험도:", C.Counter(o["risk"] for o in out))
    print("근거수준:", C.Counter(o["level"] for o in out))
    print("CSA 연계 있는 행:", sum(1 for o in out if o["csa"]))


# ============================================================================
#  xlsx 출력
# ============================================================================
def _col_w(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w

THIN = Side(style="thin", color="D0D0D0")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)

RISK_FILL = {
    "매우 높음": PatternFill("solid", fgColor="C0392B"),
    "높음":     PatternFill("solid", fgColor="E67E22"),
    "보통":     PatternFill("solid", fgColor="F1C40F"),
    "낮음":     PatternFill("solid", fgColor="A9DFBF"),
}
RISK_FONT = {
    "매우 높음": Font(color="FFFFFF", bold=True),
    "높음":     Font(color="FFFFFF", bold=True),
    "보통":     Font(color="000000"),
    "낮음":     Font(color="000000"),
}
SCOPE_FILL = {
    "Cloud 전용":   PatternFill("solid", fgColor="D6EAF8"),
    "혼합":         PatternFill("solid", fgColor="FEF9E7"),
    "Cloud 외 연관":PatternFill("solid", fgColor="F2F3F4"),
    "연결용":       PatternFill("solid", fgColor="F2F3F4"),
    "ATT&CK 미대응":PatternFill("solid", fgColor="FADBD8"),
}
LEVEL_RANK = {"실제 사고 확인":1,"실사용 기법 포함":2,"실증·공개 취약점":3,"이론·시나리오":4}
HDR_FILL = PatternFill("solid", fgColor="1F3864")
GRP_FILLS = ["2E5496","3A6EA5","1F7A5A","8A5A1F"]  # 분류/매핑/위험/근거


def write_xlsx(domains, out, all_inc, by_tid):
    wb = openpyxl.Workbook()
    today = datetime.date.today().isoformat()

    # ---------- 개요 ----------
    ws = wb.active; ws.title = "개요"
    meta = [
        ("통합 클라우드 보안위협 매트릭스 v1", ""),
        ("", ""),
        ("기준", "MITRE ATT&CK Cloud 킬체인(전술→기법→하위기법) 뼈대 · 통합 AI 보안위협 매트릭스 v3.2의 위험평가·근거 로직 이식"),
        ("생성일", today),
        ("", ""),
        ("■ 기준 데이터", ""),
        ("MITRE ATT&CK", "Enterprise v19.2 Cloud(IaaS·SaaS·Office Suite·Identity Provider) · github.com/mitre-attack/attack-stix-data"),
        ("AWS TTC", "aws-samples.github.io/threat-technique-catalog-for-aws"),
        ("Azure ATRM", "github.com/microsoft/Azure-Threat-Research-Matrix"),
        ("K8s 매트릭스", "github.com/microsoft/Threat-Matrix-for-Kubernetes"),
        ("CSA Top Threats", "Top Threats to Cloud Computing 2026 (11대 위협) — 연계 표시만 사용(원문 미수록)"),
        ("클라우드 보안사고 DB", "Wiz·ramimac·SEC·GTI·MS 등 출처 680건(2010~2026)"),
        ("", ""),
        ("■ 시트 구성", ""),
        ("통합 매트릭스", "도메인(전술)→위협분류(기법)→세부위협(하위기법/벤더)별 분류·교차매핑·위험평가·실제근거 전체"),
        ("통합매트릭스_LITE", "핵심 열만 발췌한 요약본(필터·보고용)"),
        ("역매핑_사고사례", "클라우드 보안사고 680건과 매핑된 ATT&CK 기법·전술(근거 추적용)"),
        ("평가 기준", "발생가능성·심각도·위험도·근거수준 산정 규칙"),
        ("", ""),
        ("■ 분류 체계", ""),
        ("Lv1 도메인", "ATT&CK 전술(킬체인 순). 코드 예: [IA] 초기 침투, [IM] 영향"),
        ("Lv2 위협분류", "ATT&CK 기법. ID 예: CTC-IA-02 (= T1190)"),
        ("Lv3 세부위협", "ATT&CK 하위기법 또는 벤더 특화 항목. ID 예: CTC-IA-04.4 (= T1078.004)"),
        ("Cloud 범위", "Cloud 전용 / 혼합(Cloud+기타 플랫폼) / Cloud 외 연관(하위기법만 Cloud) / 연결용 / ATT&CK 미대응(벤더 전용)"),
        ("", ""),
        ("■ 위험도 분포", ""),
    ]
    rc = collections.Counter(o["risk"] for o in out)
    for k in ["매우 높음","높음","보통","낮음"]:
        meta.append((f"  {k}", f"{rc.get(k,0)} 건"))
    meta.append(("", ""))
    meta.append(("■ 근거수준 분포", ""))
    lc = collections.Counter(o["level"] for o in out)
    for k in ["실제 사고 확인","실사용 기법 포함","실증·공개 취약점","이론·시나리오"]:
        meta.append((f"  {k}", f"{lc.get(k,0)} 건"))
    meta.append(("", ""))
    meta.append(("■ 커버리지", ""))
    meta.append(("  세부위협(Lv3) 행", f"{len(out)} 건"))
    meta.append(("  도메인(전술)", f"{len(domains)} 개"))
    meta.append(("  CSA Top Threats 연계 행", f"{sum(1 for o in out if o['csa'])} 건"))
    meta.append(("  사고DB 연계 행(실제 사고 확인)", f"{sum(1 for o in out if o['inc_cases'])} 건"))
    meta.append(("", ""))
    meta.append(("■ 주의", ""))
    meta.append(("사례 매핑", "사고DB→기법 매핑은 DB의 ATT&CK 초안 ID 기준(보수적). 매핑 없는 사고는 '역매핑_사고사례' 시트에 전수 보존"))
    meta.append(("위험평가", "발생가능성은 근거에서 자동 산정, 심각도는 전술·기법 기반 기준값 → 조직 맥락에 맞게 검토 권장"))
    meta.append(("출처 표기", "MITRE ATT&CK © The MITRE Corporation / CSA·AWS·Microsoft 각 원저작권자. 배포 전 각 출처 이용약관 확인"))
    for i,(a,c) in enumerate(meta,1):
        ws.cell(i,1,a); ws.cell(i,2,c)
        ws.cell(i,2).alignment = WRAP
    ws.cell(1,1).font = Font(size=15, bold=True, color="1F3864")
    for i,(a,c) in enumerate(meta,1):
        if a.startswith("■"): ws.cell(i,1).font = Font(bold=True, color="1F3864")
    _col_w(ws, [26, 110])

    # ---------- 통합 매트릭스 (full) ----------
    ws = wb.create_sheet("통합 매트릭스")
    groups = [("분류 체계", 9), ("교차 매핑", 4), ("위험 평가", 4), ("실제 근거", 6)]
    cols = ["도메인(Lv1)","CTC-ID","위협분류(Lv2)","세부위협(Lv3)","ATT&CK ID","구분",
            "Cloud 범위","Cloud 플랫폼","기타 플랫폼",
            "CSA Top Threats 연계","AWS (TTC)","Azure (ATRM)","Kubernetes",
            "발생가능성","심각도","위험도","발생가능성 근거",
            "ATT&CK 사례 수","사고DB 사례 수","근거 수준","관련 사고 ID","대표 사례","ATT&CK 링크"]
    ws.cell(1,1,"통합 클라우드 보안위협 매트릭스 v1 — ATT&CK Cloud 킬체인 기준")
    ws.cell(1,1).font = Font(size=13, bold=True, color="FFFFFF")
    ws.cell(1,1).fill = HDR_FILL
    ws.merge_cells(start_row=1,start_column=1,end_row=1,end_column=len(cols))
    ws.cell(2,1,f"분류체계(A~I) · 교차매핑(J~M) · 위험평가(N~Q) · 실제근거(R~W) · 생성 {today}")
    ws.merge_cells(start_row=2,start_column=1,end_row=2,end_column=len(cols))
    # group band (row3)
    c0=1
    for (gname,span),gf in zip(groups,GRP_FILLS):
        ws.merge_cells(start_row=3,start_column=c0,end_row=3,end_column=c0+span-1)
        cell=ws.cell(3,c0,gname); cell.fill=PatternFill("solid",fgColor=gf)
        cell.font=Font(bold=True,color="FFFFFF"); cell.alignment=CENTER
        c0+=span
    # column header (row4)
    for j,c in enumerate(cols,1):
        cell=ws.cell(4,j,c); cell.fill=PatternFill("solid",fgColor="34495E")
        cell.font=Font(bold=True,color="FFFFFF"); cell.alignment=CENTER; cell.border=BORDER
    r=5
    for o in out:
        vals=[o["domain"],o["ctc"],o["lv2"],o["lv3"],o["tid"],o["gubun"],
              o["scope"],o["plat_cloud"],o["plat_other"],
              o["csa"],o["aws"],o["azure"],o["k8s"],
              o["likelihood"],o["severity"],o["risk"],o["lk_reason"],
              o["atk_cases"],o["inc_cases"],o["level"],o["inc_ids"],o["examples"],o["link"]]
        for j,v in enumerate(vals,1):
            cell=ws.cell(r,j,v); cell.alignment=WRAP; cell.border=BORDER
        # 색: Cloud 범위, 위험도
        ws.cell(r,7).fill = SCOPE_FILL.get(o["scope"], PatternFill())
        ws.cell(r,16).fill = RISK_FILL.get(o["risk"], PatternFill())
        ws.cell(r,16).font = RISK_FONT.get(o["risk"], Font())
        ws.cell(r,16).alignment = CENTER
        for cc in (14,15,18,19): ws.cell(r,cc).alignment=CENTER
        r+=1
    ws.freeze_panes="E5"
    ws.auto_filter.ref=f"A4:{get_column_letter(len(cols))}{r-1}"
    _col_w(ws,[16,13,22,26,11,14,13,16,16, 26,30,30,26, 8,7,9,34, 8,8,13,22,60,30])

    # ---------- LITE ----------
    ws=wb.create_sheet("통합매트릭스_LITE")
    lcols=["도메인(Lv1)","CTC-ID","위협분류(Lv2)","세부위협(Lv3)","ATT&CK ID","Cloud 범위",
           "CSA Top Threats 연계","발생가능성","심각도","위험도","근거 수준",
           "ATT&CK 사례","사고DB 사례","관련 사고 ID"]
    ws.cell(1,1,"통합 클라우드 보안위협 매트릭스 v1 — LITE")
    ws.cell(1,1).font=Font(size=12,bold=True,color="1F3864")
    ws.merge_cells(start_row=1,start_column=1,end_row=1,end_column=len(lcols))
    for j,c in enumerate(lcols,1):
        cell=ws.cell(2,j,c); cell.fill=PatternFill("solid",fgColor="34495E")
        cell.font=Font(bold=True,color="FFFFFF"); cell.alignment=CENTER; cell.border=BORDER
    r=3
    for o in out:
        vals=[o["domain"],o["ctc"],o["lv2"],o["lv3"],o["tid"],o["scope"],o["csa"],
              o["likelihood"],o["severity"],o["risk"],o["level"],
              o["atk_cases"],o["inc_cases"],o["inc_ids"]]
        for j,v in enumerate(vals,1):
            cell=ws.cell(r,j,v); cell.alignment=WRAP; cell.border=BORDER
        ws.cell(r,6).fill=SCOPE_FILL.get(o["scope"],PatternFill())
        ws.cell(r,10).fill=RISK_FILL.get(o["risk"],PatternFill())
        ws.cell(r,10).font=RISK_FONT.get(o["risk"],Font()); ws.cell(r,10).alignment=CENTER
        for cc in (8,9,12,13): ws.cell(r,cc).alignment=CENTER
        r+=1
    ws.freeze_panes="E3"; ws.auto_filter.ref=f"A2:{get_column_letter(len(lcols))}{r-1}"
    _col_w(ws,[16,13,24,28,11,13,26,8,7,9,13,8,8,24])

    # ---------- 역매핑_사고사례 ----------
    ws=wb.create_sheet("역매핑_사고사례")
    icols=["사건ID","대표 제목","기준일","사례유형","출처","클라우드 관련도","서비스 계층",
           "근본원인","영향유형","ATT&CK 매핑","사건 요약"]
    for j,c in enumerate(icols,1):
        cell=ws.cell(1,j,c); cell.fill=PatternFill("solid",fgColor="34495E")
        cell.font=Font(bold=True,color="FFFFFF"); cell.alignment=CENTER; cell.border=BORDER
    r=2
    for e in sorted(all_inc, key=lambda x:str(x["date"])):
        vals=[e["id"],e["title"],str(e["date"] or ""),e["kind"],e["src"],e["rel"],
              e["layer"],e["root"],e["impact"],e["att"] or "",(e["summary"] or "")]
        for j,v in enumerate(vals,1):
            cell=ws.cell(r,j,v); cell.alignment=WRAP; cell.border=BORDER
        r+=1
    ws.freeze_panes="A2"; ws.auto_filter.ref=f"A1:{get_column_letter(len(icols))}{r-1}"
    _col_w(ws,[10,36,10,14,8,14,20,18,16,18,70])

    # ---------- 평가 기준 ----------
    ws=wb.create_sheet("평가 기준")
    txt=[
      ("■ 발생가능성 (근거 자동 산정)",""),
      ("상","실제 사고 ≥5건 또는 ATT&CK 클라우드 사례 ≥10건"),
      ("중","실제 사고 1~4건 또는 ATT&CK 사례 4~9건 또는 벤더 특화기법 존재"),
      ("하","사고·사례 근거가 희소(ATT&CK 사례 ≤3건, 사고 0건)"),
      ("",""),
      ("■ 심각도 (전술·기법 기반 기준값)",""),
      ("상","Impact·Credential Access·Exfiltration·Initial Access·Privilege Escalation 전술, 또는 데이터 파괴·암호화·유출·자격증명 탈취·핵심 권한 기법"),
      ("중","Persistence·Lateral Movement·Collection·Execution·방어무력화·은닉 전술"),
      ("하","Discovery(탐색·열람) 위주 기법"),
      ("",""),
      ("■ 위험도 (발생가능성 × 심각도)",""),
      ("","심각도 상 / 중 / 하"),
      ("발생가능성 상","매우 높음 / 높음 / 보통"),
      ("발생가능성 중","높음 / 보통 / 낮음"),
      ("발생가능성 하","보통 / 낮음 / 낮음"),
      ("",""),
      ("■ 근거 수준 (높은 순)",""),
      ("실제 사고 확인","클라우드 보안사고 DB에 매핑된 실제 사고 존재"),
      ("실사용 기법 포함","사고 매핑은 없으나 ATT&CK 그룹·악성코드·캠페인의 실제 사용 사례(procedure) 존재"),
      ("실증·공개 취약점","ATT&CK 사례는 없으나 AWS/Azure/K8s 벤더 매트릭스가 기법을 문서화"),
      ("이론·시나리오","매트릭스상 가능 기법이나 사례·벤더 문서 근거 없음(연결용·희소 기법)"),
    ]
    for i,(a,c) in enumerate(txt,1):
        ws.cell(i,1,a); ws.cell(i,2,c); ws.cell(i,2).alignment=WRAP
        if a.startswith("■"): ws.cell(i,1).font=Font(bold=True,color="1F3864")
        elif a: ws.cell(i,1).font=Font(bold=True)
    _col_w(ws,[18,100])

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    wb.save(OUT)
    return OUT
