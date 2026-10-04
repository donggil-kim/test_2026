"""통합 보안위협 매트릭스 — 원본 로더·근거 재산정·문안 검증 공통 모듈.

원본
  - AI: sources/ai_v3.2 (통합 AI 보안위협 매트릭스 v3.2, Lv3 124개)
  - 클라우드: output/통합_클라우드보안위협_매트릭스_v5.xlsx (Lv3 154행, 고유 기법 126개)
요약(재구성 Lv3) 문안: integrated/data/ai/D*.yaml, integrated/data/cloud/<전술>.yaml
"""
import collections
import glob
import os
import re

import openpyxl
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AI_DIR = os.path.join(ROOT, "sources", "ai_v3.2")
AI_XLSX = os.path.join(AI_DIR, "output", "통합_AI보안위협_매트릭스_v3.2_LITE.xlsx")
CLOUD_XLSX = os.path.join(ROOT, "output", "통합_클라우드보안위협_매트릭스_v5.xlsx")
DATA_DIR = os.path.join(ROOT, "integrated", "data")

LEVEL = {"상": 3, "중": 2, "하": 1}
LEVEL_INV = {3: "상", 2: "중", 1: "하"}
RISK = {("상", "상"): "매우 높음", ("상", "중"): "높음", ("중", "상"): "높음",
        ("중", "중"): "보통", ("상", "하"): "보통", ("하", "상"): "보통"}
RISK_ORDER = ["매우 높음", "높음", "보통", "낮음"]
EVIDENCE_ORDER = ["실제 사고 확인", "실사용 기법 포함", "실증·공개 취약점", "이론·시나리오"]
CLOUD_REAL_KINDS = {"사고", "캠페인", "사례연구(익명)", "규제공시(8-K)", "위협인텔 보고서"}

AI_DOMAINS = ["D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08", "D09", "D10"]
TACTICS = ["RD", "IA", "EX", "PE", "PV", "ST", "DI", "CA", "DS", "LM", "CO", "C2", "EF", "IM"]
CASE_TAGS = ["실제 사고", "공개 취약점", "실증", "ATT&CK 사례", "시나리오"]
SOURCE_TAG_ALIAS = {"실증·연구": "실증"}


def risk_of(likelihood, severity):
    return RISK.get((likelihood, severity), "낮음")


# ---------------------------------------------------------------- 원본 로더
def load_ai():
    """AI v3.2 원본: Lv3 행(dict), 도메인명, Lv2 통제, 사례(Incident) 매핑."""
    wb = openpyxl.load_workbook(AI_XLSX, read_only=True, data_only=True)
    rows = list(wb["통합매트릭스"].iter_rows(values_only=True))
    header = rows[3]
    lv3 = collections.OrderedDict()
    for r in rows[4:]:
        if r[3] and str(r[3]).startswith("UT-"):
            d = dict(zip(header, r))
            d["위험도"] = risk_of(d["발생가능성"], d["심각도"])  # 원본 셀은 수식 → 값으로 재계산
            d["domain"] = d["도메인 (Lv1)"][:3]
            lv3[r[3]] = d
    base = {b["id"]: b for b in yaml.safe_load(open(os.path.join(AI_DIR, "data", "v3.2", "base.yaml")))}
    lv2 = collections.OrderedDict((x["ut"], x) for x in yaml.safe_load(open(os.path.join(AI_DIR, "data", "v3.2", "lv2.yaml"))))
    cases = yaml.safe_load(open(os.path.join(AI_DIR, "data", "v3.2", "cases.yaml")))
    incidents = collections.defaultdict(set)
    for c in cases:
        if c["type"] == "Incident":
            for l in c["lv3"]:
                incidents[l].add(c["id"])
    for k, d in lv3.items():
        d["atlas_incidents"] = sorted(incidents[k])
        d["owasp_incidents"] = base[k].get("owasp_incidents") or 0
        d["owasp_vulns"] = base[k].get("owasp_vulns") or 0
        if len(d["atlas_incidents"]) + d["owasp_incidents"] != d["실제 사고 수"]:
            raise ValueError(f"AI 실제 사고 수 재현 불일치: {k}")
    domains = collections.OrderedDict()
    for d in lv3.values():
        domains.setdefault(d["domain"], d["도메인 (Lv1)"])
    return {"lv3": lv3, "header": header, "lv2": lv2, "domains": domains, "cases": cases}


def load_cloud():
    """클라우드 v5 원본: 행(154), 기법별 대표 행·전술·실제 사고 ID 집합."""
    wb = openpyxl.load_workbook(CLOUD_XLSX, read_only=True, data_only=True)
    m = list(wb["통합 매트릭스"].iter_rows(values_only=True))
    header = m[3]
    rows = [dict(zip(header, r)) for r in m[4:] if r[1]]
    inc = list(wb["역매핑_사고사례"].iter_rows(values_only=True))
    ih = {k: i for i, k in enumerate(inc[0])}
    real = {x[ih["사건ID"]] for x in inc[1:] if x[ih["사례유형"]] in CLOUD_REAL_KINDS and x[ih["집계 포함"]] == "Y"}
    tech = collections.OrderedDict()
    for r in rows:
        t = str(r["ATT&CK ID"])
        r["tactic"] = r["도메인(Lv1)"][1:3]
        ids = {i.strip() for i in str(r["관련 사례 ID"] or "").replace("\n", ",").split(",") if i.strip()}
        r["real_incidents"] = sorted(ids & real)
        if len(r["real_incidents"]) != r["실제 사고 수"]:
            raise ValueError(f"클라우드 실제 사고 수 재현 불일치: {r['CTC-ID']}")
        if t not in tech:
            tech[t] = {"row": r, "ctc": [], "tactics": []}
        tech[t]["ctc"].append(r["CTC-ID"])
        tech[t]["tactics"].append(r["tactic"])
    tactics = collections.OrderedDict()
    for r in rows:
        tactics.setdefault(r["tactic"], r["도메인(Lv1)"])
    return {"rows": rows, "header": header, "tech": tech, "tactics": tactics, "wb": CLOUD_XLSX}


# ---------------------------------------------------------------- 요약 문안 로더
def load_summary():
    ai, cloud = [], []
    for dom in AI_DOMAINS:
        p = os.path.join(DATA_DIR, "ai", f"{dom}.yaml")
        if os.path.exists(p):
            for e in yaml.safe_load(open(p)) or []:
                e["domain"] = dom
                ai.append(e)
    for tac in TACTICS:
        p = os.path.join(DATA_DIR, "cloud", f"{tac}.yaml")
        if os.path.exists(p):
            for e in yaml.safe_load(open(p)) or []:
                e["domain"] = tac
                cloud.append(e)
    return ai, cloud


# ---------------------------------------------------------------- 근거 재산정
def evaluate_ai(entry, src):
    mem = [src["lv3"][m] for m in entry["members"]]
    atlas = sorted(set().union(*[set(d["atlas_incidents"]) for d in mem]))
    owasp = sum(d["owasp_incidents"] for d in mem)
    n = len(atlas) + owasp
    lik = "상" if n >= 2 else ("중" if n == 1 or any(LEVEL[d["발생가능성"]] >= 2 for d in mem) else "하")
    sev = LEVEL_INV[max(LEVEL[d["심각도"]] for d in mem)]
    if entry.get("severity_override"):
        sev = entry["severity_override"]
    evid = min((d["근거 수준"] for d in mem), key=EVIDENCE_ORDER.index)
    return {"likelihood": lik, "severity": sev, "risk": risk_of(lik, sev), "evidence": evid,
            "incidents": n, "incident_ids": atlas, "owasp_incidents": owasp}


def evaluate_cloud(entry, src):
    mem = [src["tech"][t]["row"] for t in entry["members"]]
    ids = sorted(set().union(*[set(r["real_incidents"]) for r in mem]))
    n = len(ids)
    lik = "상" if n >= 2 else ("중" if n == 1 or any(LEVEL[r["발생가능성"]] >= 2 for r in mem) else "하")
    sev = LEVEL_INV[max(LEVEL[r["심각도"]] for r in mem)]
    if entry.get("severity_override"):
        sev = entry["severity_override"]
    evid = min((r["근거 수준"] for r in mem), key=EVIDENCE_ORDER.index)
    recent = sorted(set().union(*[set(r["real_incidents"]) for r in mem if r["최근 사고(2025~)"]]))  # 참고용
    return {"likelihood": lik, "severity": sev, "risk": risk_of(lik, sev), "evidence": evid,
            "incidents": n, "incident_ids": ids}


# ---------------------------------------------------------------- 문안 검증
CASE_RE = re.compile(r"^- \[(?P<tag>[^\]]+)\] (?P<body>.+)$")
NAMED_RE = re.compile(r"^(?P<name>[^:]+?)(?:\((?P<date>[^()]*(?:\([^()]*\))?[^()]*)\))?: (?P<gist>.+)$")
LIMITS = {"name": 30, "description": 130, "scenario": 175, "cases": 130, "controls": 80}
BANNED = {"인증정보": "자격증명", "크리덴셜": "자격증명", "엑스필": "반출"}


def _lines(text):
    return [l for l in (text or "").split("\n") if l.strip()]


def check_entry(entry, refs, kind):
    """문안 형식·길이·사례 출처 대조. refs: 구성 원본의 참조 문자열 목록."""
    errs, warns = [], []
    eid = entry.get("id", "?")
    for f in ["id", "name", "members", "description", "scenario", "cases", "controls", "basis"]:
        if not entry.get(f):
            errs.append(f"{eid}: '{f}' 누락")
    if errs:
        return errs, warns
    if len(entry["name"]) > LIMITS["name"]:
        warns.append(f"{eid}: 위협명 {len(entry['name'])}자 (>{LIMITS['name']})")
    desc = _lines(entry["description"])
    if len(desc) != 2 or not all(l.startswith("- ") for l in desc):
        errs.append(f"{eid}: 위협 설명은 '- '로 시작하는 2줄이어야 함")
    elif not desc[0].rstrip().endswith("위협"):
        errs.append(f"{eid}: 위협 설명 1줄은 '~위협'으로 끝나야 함")
    scen = _lines(entry["scenario"])
    if not 1 <= len(scen) <= 2 or not all(l.startswith("- ") and "→" in l for l in scen):
        errs.append(f"{eid}: 공격 시나리오는 '→'를 포함한 1~2줄")
    ctrl = _lines(entry["controls"])
    if not 2 <= len(ctrl) <= 3 or not all(l.startswith("- ") for l in ctrl):
        errs.append(f"{eid}: 대응 방안은 '- '로 시작하는 2~3줄")
    for field in ["description", "scenario", "cases", "controls"]:
        for l in _lines(entry[field]):
            if len(l) > LIMITS[field]:
                warns.append(f"{eid}: {field} 한 줄 {len(l)}자 (>{LIMITS[field]})")
    for bad, good in BANNED.items():
        for field in ["name", "description", "scenario", "cases", "controls"]:
            if bad in (entry.get(field) or ""):
                errs.append(f"{eid}: 용어 '{bad}' → '{good}'")
    cases = _lines(entry["cases"])
    if not 1 <= len(cases) <= 2:
        errs.append(f"{eid}: 대표 사례는 1~2줄")
    joined = "\n".join(refs)
    for c in cases:
        if c.startswith("- 공개 사고 미확인"):  # 사례가 없는 기법: 원본의 '공개 사고 미확인' 근거가 있을 때만 허용
            if "공개 사고 미확인" not in joined:
                errs.append(f"{eid}: 원본에 '공개 사고 미확인' 근거 없음")
            continue
        m = CASE_RE.match(c)
        if not m or m.group("tag") not in CASE_TAGS:
            errs.append(f"{eid}: 사례 형식 오류: {c[:40]}")
            continue
        tag, body = m.group("tag"), m.group("body")
        if tag == "시나리오":
            if "[시나리오]" not in joined:
                errs.append(f"{eid}: 원본에 [시나리오] 항목 없음")
            continue
        n = NAMED_RE.match(body)
        if not n:
            errs.append(f"{eid}: 사례는 '사례명(시점): 요지' 형식: {body[:40]}")
            continue
        key = f"{n.group('name')}({n.group('date')})" if n.group("date") else f"] {n.group('name')}:"
        hit = None
        for line in joined.split("\n"):
            if key in line:
                hit = line
                break
        if not hit:
            errs.append(f"{eid}: 사례 '{key}'가 구성 원본 참조에 없음")
            continue
        st = re.match(r"^- \[([^\]]+)\]", hit.strip())
        stag = SOURCE_TAG_ALIAS.get(st.group(1), st.group(1)) if st else None
        if stag != tag:
            errs.append(f"{eid}: 사례 '{key}' 유형 불일치 (원본 [{stag}] / 요약 [{tag}])")
    return errs, warns


def check_all(ai_src, cl_src, ai_sum, cl_sum):
    errs, warns = [], []
    # 1) 원본 전수 배정 (누락·중복 0)
    used = collections.Counter(m for e in ai_sum for m in e["members"])
    missing = [k for k in ai_src["lv3"] if k not in used]
    dup = [k for k, v in used.items() if v > 1]
    unknown = [k for k in used if k not in ai_src["lv3"]]
    used_c = collections.Counter(m for e in cl_sum for m in e["members"])
    missing_c = [k for k in cl_src["tech"] if k not in used_c]
    dup_c = [k for k, v in used_c.items() if v > 1]
    unknown_c = [k for k in used_c if k not in cl_src["tech"]]
    for label, lst in [("AI 미배정", missing), ("AI 중복", dup), ("AI 없는 ID", unknown),
                       ("클라우드 미배정", missing_c), ("클라우드 중복", dup_c), ("클라우드 없는 ID", unknown_c)]:
        if lst:
            (warns if "미배정" in label else errs).append(f"{label}: {lst}")
    ids = [e["id"] for e in ai_sum + cl_sum]
    for k, v in collections.Counter(ids).items():
        if v > 1:
            errs.append(f"위협 ID 중복: {k}")
    # 2) 항목별 문안·사례 검증
    for e in ai_sum:
        if any(m not in ai_src["lv3"] for m in e.get("members", [])):
            continue
        refs = [ai_src["lv3"][m]["참조"] or "" for m in e["members"]]
        a, b = check_entry(e, refs, "ai")
        errs += a
        warns += b
        if not e["id"].startswith(f"AI-{e['domain'][1:]}-"):
            errs.append(f"{e['id']}: ID와 도메인({e['domain']}) 불일치")
    for e in cl_sum:
        if any(m not in cl_src["tech"] for m in e.get("members", [])):
            continue
        refs = [cl_src["tech"][m]["row"]["참조"] or "" for m in e["members"]]
        a, b = check_entry(e, refs, "cloud")
        errs += a
        warns += b
        if not e["id"].startswith(f"CL-{e['domain']}-"):
            errs.append(f"{e['id']}: ID와 전술({e['domain']}) 불일치")
    # 3) 근거 수준과 사례 유형 정합성: '실제 사고 확인'이면 [실제 사고] 1건 이상
    for e, ev in [(e, evaluate_ai(e, ai_src)) for e in ai_sum if all(m in ai_src["lv3"] for m in e["members"])] + \
                 [(e, evaluate_cloud(e, cl_src)) for e in cl_sum if all(m in cl_src["tech"] for m in e["members"])]:
        if ev["evidence"] == "실제 사고 확인" and "[실제 사고]" not in (e.get("cases") or ""):
            warns.append(f"{e['id']}: 근거 수준 '실제 사고 확인'이나 대표 사례에 [실제 사고] 없음")
    return errs, warns


if __name__ == "__main__":
    ai_src, cl_src = load_ai(), load_cloud()
    ai_sum, cl_sum = load_summary()
    errs, warns = check_all(ai_src, cl_src, ai_sum, cl_sum)
    print(f"AI 요약 {len(ai_sum)}개 / 클라우드 요약 {len(cl_sum)}개")
    for w in warns:
        print("  [경고]", w)
    for e in errs:
        print("  [오류]", e)
    print("오류", len(errs), "경고", len(warns))
