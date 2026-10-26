# -*- coding: utf-8 -*-
"""
AI 활용 공격 보안위협 매트릭스 — 데이터·문구 검증기
--------------------------------------------------
빌드 입력(data/·scripts/taxonomy_rules.py)의 정합성을 점검한다(물리·신원·공급망 매트릭스 validate.py와 같은 구성).
  · 원천 데이터 : ID 형식·중복, 분류 체계 필드·어휘(킬체인 단계·AI 역할·고유성·성숙도·주체·대상),
                  ATLAS·ATT&CK·OWASP·NIST·다른 매트릭스 연계·참고 문헌 키가 카탈로그에 있는지, 참고 문헌 카탈로그 필드,
                  사고 DB 필드·어휘, 사고↔세부위협·ATLAS/ATT&CK·origin 형식, 출처 '출처 | URL'
  · 문구/시나리오 : data/text/*.yaml·data/scenarios.yaml가 있으면 형식·참조 ID를 점검(②③단계용; 없으면 건너뜀)

실행 : python3 scripts/validate.py [--strict] [--data-only]
       오류가 있으면 종료 코드 1(--strict는 경고도 실패로 처리)
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import taxonomy_rules as R  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
REF = ROOT / "reference"

ERR, WARN = [], []


def err(where, msg):
    ERR.append(f"[오류] {where}: {msg}")


def warn(where, msg):
    WARN.append(f"[경고] {where}: {msg}")


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _mapping_no_dup(loader, node, deep=False):
    seen = set()
    for k_node, _ in node.value:
        k = loader.construct_object(k_node, deep=deep)
        if k in seen:
            raise yaml.constructor.ConstructorError(None, None, f"중복 키 '{k}'", k_node.start_mark)
        seen.add(k)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_no_dup)


def load(p, default=None):
    if not p.exists():
        return default
    try:
        return yaml.load(p.read_text(encoding="utf-8"), Loader=UniqueKeyLoader)
    except yaml.YAMLError as e:
        err(p.name, f"YAML 파싱 실패 — {e}")
        return default


TAX = load(DATA / "taxonomy.yaml")
FW = load(DATA / "frameworks.yaml")
INCIDENTS = load(DATA / "incidents.yaml", []) or []
SCENARIOS = load(DATA / "scenarios.yaml", {}) or {}
ATLAS = json.loads((REF / "atlas" / "atlas-2026.09-subset.json").read_text(encoding="utf-8"))
ATLAS_INDEX = ATLAS["index"]
ATK = json.loads((REF / "attack" / "enterprise-attack-v19.2-subset.json").read_text(encoding="utf-8"))
ATK_INDEX = ATK["index"]
NIST = json.loads((REF / "nist" / "sp800-53r5-names.json").read_text(encoding="utf-8"))["names"]
LINKS = json.loads((REF / "links" / "other_matrices.json").read_text(encoding="utf-8"))["ids"]
OWASP = FW.get("owasp") or {}
REFS = FW.get("references") or {}
REF_SHORT = {v["short"]: k for k, v in REFS.items() if v.get("short")}

ROWS, LV2 = {}, set()
for d in TAX["domains"]:
    for l2 in d["lv2"]:
        LV2.add(l2["id"])
        for x in l2["lv3"]:
            if x["id"] in ROWS:
                err("taxonomy.yaml", f"세부위협 ID 중복 {x['id']}")
            ROWS[x["id"]] = dict(x, code=d["code"], lv2_id=l2["id"])
AIA_IDS = set(ROWS) | LV2

XM_FIELD = {"AI-": "ai", "CL-": "cl", "OT-": "ot", "SC-": "sc", "ID-": "idn", "PH-": "ph"}
ALLOW_MISSING_TEXT = False


def xm_field(k):
    return next((f for p, f in XM_FIELD.items() if k.startswith(p)), None)


# 문구·시나리오 검사용 정규식·어휘
RE_AIA = re.compile(r"AIA-[A-Z]{2}-\d{2}(?:\.\d)?")
RE_AII = re.compile(r"AII-\d{3}")
RE_ATLAS_TECH = re.compile(r"AML\.T\d{4}(?:\.\d{3})?")
RE_ATLAS_CASE = re.compile(r"AML\.CS\d{4}")
RE_ATK = re.compile(r"(?<![A-Za-z0-9.])(T\d{4}(?:\.\d{3})?|[GSC]\d{4})(?![A-Za-z0-9])")
RE_XM = re.compile(r"(?<![A-Za-z0-9-])(AI-\d{2}-\d{2}|CL-[A-Z]{2}-\d{2}|OT-[A-Z0-9]{2}-\d{2}|SC-[A-Z]{2}-\d{2}|"
                   r"ID-[A-Z]{2}-\d{2}|PH-[A-Z]{2}-\d{2})(?![A-Za-z0-9])")
RE_NIST = re.compile(r"NIST (?:SP 800-53 )?((?:[A-Z]{2}-\d+(?:\(\d+\))?)(?:·[A-Z]{2}-\d+(?:\(\d+\))?)*)")
RE_OWASP = re.compile(r"(?<![A-Za-z0-9-])(LLM\d{2}|ASI\d{2})(?![A-Za-z0-9])")
RE_DATE = re.compile(r"\((\d{4}-\d{2})\)")
RE_NUM = re.compile(r"\d+(?:[.,]\d+)*")
RE_REFNOTE = re.compile(r"참고: (.+)$")
RE_REFSHORT = re.compile(r"[^·〈〉]+?〈[^〉]+〉")

CASE_LABELS = {"[실제 사고]": "실제 사고", "[위협인텔]": "위협인텔", "[실증]": "실증·연구", "[시나리오]": None}
BANNED = {"인증정보": "자격증명", "인증 정보": "자격증명", "크리덴셜": "자격증명", "자격 증명": "자격증명"}
# 가드레일(D11) — 공세 제작법·악용 절차 표현 차단(방어 자료)
BANNED_GUARD = ["탈옥 프롬프트는", "우회 프롬프트는", "다음과 같이 우회", "예시 페이로드", "페이로드 예시",
                "악성코드 예시", "공격 코드는 다음", "제작 방법은", "만드는 방법은"]
REF_SHORT = {v["short"]: k for k, v in REFS.items() if v.get("short")}


def sections(text):
    out, cur = collections.OrderedDict(), None
    for ln in (text or "").splitlines():
        if ln.startswith("■ "):
            cur = ln[2:].strip()
            out[cur] = []
        elif cur is not None:
            out[cur].append(ln)
    return out


# ===========================================================================
# 1) frameworks.yaml — 어휘·카탈로그
# ===========================================================================
def check_frameworks():
    for cat, vocab in (("stages", R.STAGES), ("ai_roles", R.AI_ROLES), ("novelty", R.NOVELTY),
                       ("maturity", R.MATURITY)):
        if list(FW.get(cat) or {}) != vocab:
            err(f"frameworks.yaml {cat}", f"어휘가 taxonomy_rules.py와 다름({list(FW.get(cat) or {})} ≠ {vocab})")
    for k, v in REFS.items():
        where = f"frameworks.yaml references {k}"
        if not re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)+", k):
            err(where, "키 형식(출처-자료) 오류")
        for f in ("title", "short", "publisher", "year", "urls", "use", "domains", "terms", "verify", "checked"):
            if not v.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        if v.get("short") and not re.fullmatch(r".+ 〈[^〉]+〉", v["short"]):
            err(where, f"short는 '출처 〈자료〉' 형식: {v['short']}")
        for u in v.get("urls") or []:
            if not re.fullmatch(r"https?://\S+", u):
                err(where, f"URL 형식 오류: {u}")
        for dm in v.get("domains") or []:
            if dm not in R.DOMAIN_ORDER:
                err(where, f"없는 도메인 코드 {dm}")
        for u in v.get("use") or []:
            if u not in ("분류 근거", "위협 내용", "대응 문구"):
                err(where, f"use 어휘(분류 근거·위협 내용·대응 문구) 아님: {u}")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(v.get("checked", ""))):
            err(where, f"확인일 형식(YYYY-MM-DD) 오류: {v.get('checked')}")
    if len(REF_SHORT) != len(REFS):
        err("frameworks.yaml references", "short 이름 중복")


# ===========================================================================
# 2) taxonomy.yaml
# ===========================================================================
def check_taxonomy():
    codes = [d["code"] for d in TAX["domains"]]
    if codes != R.DOMAIN_ORDER:
        err("taxonomy.yaml", f"도메인 순서·코드가 taxonomy_rules.DOMAIN_ORDER와 다름({codes})")
    for d in TAX["domains"]:
        for f in ("ko", "en", "desc", "excludes"):
            if not d.get(f):
                err(f"taxonomy.yaml {d['code']}", f"도메인 필드 '{f}' 없음")
        for l2 in d["lv2"]:
            if not re.fullmatch(rf"AIA-{d['code']}-\d{{2}}", l2["id"]):
                err(f"taxonomy.yaml {l2['id']}", "위협분류 ID 형식(AIA-<도메인>-NN) 오류")
            for x in l2["lv3"]:
                if not (x["id"] == l2["id"] or re.fullmatch(rf"{re.escape(l2['id'])}\.\d", x["id"])):
                    err(f"taxonomy.yaml {x['id']}", f"세부위협 ID가 위협분류 {l2['id']} 체계와 맞지 않음")
            if len(l2["lv3"]) > 1 and any(x["id"] == l2["id"] for x in l2["lv3"]):
                err(f"taxonomy.yaml {l2['id']}", "하위 세부위협이 여럿이면 Lv2 ID를 Lv3로 쓰지 않음")
    for rid, x in ROWS.items():
        where = f"taxonomy.yaml {rid}"
        for f in ("name", "en", "stage", "ai_role", "novelty", "maturity", "actors", "targets",
                  "severity", "severity_why"):
            if not x.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for f in ("atlas", "attack", "owasp", "nist", "ai", "cl", "ot", "sc", "idn", "ph", "refs"):
            if f not in x:
                err(where, f"필드 '{f}' 없음(해당 없으면 [])")
        for t in x.get("atlas") or []:
            if t not in ATLAS["techniques"]:
                err(where, f"ATLAS 추출본에 없는 기법 {t} — scripts/prepare_atlas.py 재실행 필요")
        if not x.get("atlas") and not x.get("atlas_none"):
            err(where, "ATLAS 연계가 없으면 atlas_none에 미연계 사유를 적음")
        for t in x.get("attack") or []:
            if t not in ATK["techniques"]:
                err(where, f"ATT&CK 추출본에 없는 기법 {t} — scripts/prepare_attack.py 재실행 필요")
        for o in x.get("owasp") or []:
            if o not in OWASP:
                err(where, f"OWASP 카탈로그(frameworks.yaml owasp)에 없는 ID {o}")
        if x.get("ai_role") not in R.AI_ROLES:
            err(where, f"ai_role 값 오류 {x.get('ai_role')}")
        if x.get("novelty") not in R.NOVELTY:
            err(where, f"novelty 값 오류 {x.get('novelty')}")
        if x.get("maturity") not in R.MATURITY:
            err(where, f"maturity 값 오류 {x.get('maturity')}")
        for k in x.get("nist") or []:
            if k not in NIST:
                err(where, f"NIST SP 800-53 Rev.5에 없는 통제 {k}")
        for fld in ("ai", "cl", "ot", "sc", "idn", "ph"):
            for k in x.get(fld) or []:
                if k not in LINKS:
                    err(where, f"다른 매트릭스에 없는 연계 ID {k}({fld}) — scripts/prepare_refs.py 재실행 필요")
                elif xm_field(k) != fld:
                    err(where, f"연계 ID {k}는 '{xm_field(k)}' 필드에 적음(현재 {fld})")
        for k in x.get("refs") or []:
            if k not in REFS:
                err(where, f"참고 문헌 카탈로그(frameworks.yaml references)에 없는 키 {k}")
            elif x["code"] not in (REFS[k].get("domains") or []):
                warn(where, f"참고 문헌 {k}의 주 도메인에 {x['code']}가 없음")
        if len(x.get("refs") or []) > 3:
            err(where, "참고 문헌(refs)은 0~3개")
        if x.get("severity") not in ("상", "중", "하"):
            err(where, f"심각도 값 오류 {x.get('severity')}")
        for v, vocab, name in ((x.get("stage"), R.STAGES, "킬체인 단계"), (x.get("actors"), R.ACTOR_TYPES, "주체 유형"),
                               (x.get("targets"), R.TARGETS, "공격 대상")):
            for s in v or []:
                if s not in vocab:
                    err(where, f"정의되지 않은 {name} {s}")
        # 도메인 코드 = 그 행의 주 킬체인 단계와 정합(stage의 첫 값이 도메인 단계명과 맞는지)
        stage_of_code = dict(zip(R.DOMAIN_ORDER, R.STAGES))
        if x.get("stage") and stage_of_code.get(x["code"]) not in x["stage"]:
            warn(where, f"stage에 도메인 단계 '{stage_of_code.get(x['code'])}'가 없음")
        if x.get("severity") == "상" and len(x.get("severity_why") or "") < 30:
            warn(where, "심각도 '상'은 피해 범위를 severity_why에 적음")
        # 심각도는 영향만으로 판정(검토 6.1) — 속도·규모·탐지 난이도를 '상' 근거로 쓰지 않음
        if x.get("severity") == "상":
            for bad in ("속도", "사람이 대응", "사람 대응", "탐지가 어렵", "탐지하지 못", "레거시"):
                if bad in (x.get("severity_why") or ""):
                    warn(where, f"심각도 '상' 근거에 영향 외 요소('{bad}') — 속도·탐지는 고유 축·우선순위로")
    for k in REFS:
        if not any(k in (x.get("refs") or []) for x in ROWS.values()):
            warn("frameworks.yaml references", f"{k}를 인용한 세부위협이 없음")


# ===========================================================================
# 3) incidents.yaml
# ===========================================================================
INC = {}
ORIGIN_RE = re.compile(r"(IDI-\d{3}|SCI-\d{3}|INC-\d{3,4}|CL/INC-\d{3,4}|OT/INC-\d{3}|AML\.CS\d{4})")


def check_incidents():
    for n, e in enumerate(INCIDENTS):
        i = e.get("id", f"#{n}")
        where = f"incidents.yaml {i}"
        if not re.fullmatch(r"AII-\d{3}", str(i)):
            err(where, "ID 형식(AII-NNN) 오류")
        if i in INC:
            err(where, "ID 중복")
        INC[i] = e
        for f in ("title", "date", "kind", "verification", "region", "sector", "actor", "actor_type",
                  "impact", "ai_use", "maturity", "summary", "aia", "sources"):
            if not e.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        e["date"] = str(e.get("date", ""))
        if not re.fullmatch(r"\d{4}-\d{2}", e["date"]):
            err(where, f"시점 형식(YYYY-MM) 오류: {e['date']}")
        if e.get("kind") not in R.KINDS:
            err(where, f"사례유형 '{e.get('kind')}'이 정의된 어휘에 없음")
        if e.get("verification") not in R.VERIFICATIONS:
            err(where, f"검증 수준 '{e.get('verification')}'이 정의된 어휘에 없음")
        if e.get("legal") and e["legal"] not in R.LEGAL:
            err(where, f"법적 처리 '{e['legal']}'가 정의된 어휘에 없음")
        if e.get("region") and e["region"] not in R.REGIONS:
            err(where, f"지역 '{e['region']}'이 정의된 어휘에 없음")
        if e.get("ai_use") not in R.AI_USE:
            err(where, f"ai_use 값(확인·추정·미확인) 오류: {e.get('ai_use')}")
        if "capability_indicator" in e and not isinstance(e.get("capability_indicator"), bool):
            err(where, "capability_indicator는 true/false")
        if e.get("maturity") not in R.MATURITY:
            err(where, f"maturity 값 오류: {e.get('maturity')}")
        for fld, vocab, name in (("sector", R.SECTORS, "업종"), ("actor_type", R.ACTOR_TYPES, "주체 유형"),
                                 ("impact", R.IMPACTS, "영향")):
            for v in e.get(fld) or []:
                if v not in vocab:
                    err(where, f"{name} '{v}'가 정의된 어휘에 없음")
        for k in e.get("aia") or []:
            if k not in ROWS:
                err(where, f"매핑 세부위협 {k} 없음")
        if len(set(e.get("aia") or [])) != len(e.get("aia") or []):
            err(where, "매핑 세부위협 중복")
        for a in e.get("attack_ref") or []:
            if a not in ATLAS_INDEX and a not in ATK_INDEX:
                err(where, f"ATLAS/ATT&CK 색인에 없는 ID {a}")
        for o in e.get("origin") or []:
            if not ORIGIN_RE.fullmatch(str(o)):
                err(where, f"origin 형식(IDI-·SCI-·INC-·CL/INC-·OT/INC-·AML.CS) 오류: {o}")
        for s in e.get("sources") or []:
            if not re.fullmatch(r".+ \| https?://\S+", str(s)):
                err(where, f"출처 형식('출처 | URL') 오류: {str(s)[:60]}")
        if "TODO" in " ".join(str(s) for s in e.get("sources") or []) or "TODO" in str(e.get("summary", "")):
            err(where, "TODO가 남아 있음 — 1차 출처로 확정")
        e["status"] = R.incident_status(e) if e.get("kind") in R.KINDS and e.get("verification") else "?"


# ===========================================================================
# 4) 행별 근거 요약(빌드 스크립트와 같은 규칙) — 참고용 집계
# ===========================================================================
def row_evidence():
    ev = {k: dict(real=set(), advisory=set(), research=set(), intel=set()) for k in ROWS}
    key = {"실제 사고": "real", "정부 경보": "advisory", "실증·연구": "research", "위협인텔": "intel"}
    for e in INCIDENTS:
        for k in e.get("aia") or []:
            if key.get(e.get("status")) and k in ev:
                ev[k][key[e["status"]]].add(e["id"])
    return ev


# ===========================================================================
# 5) 관점 문구(data/text/*.yaml) — ③단계
# ===========================================================================
def check_refnote(where, rid, ln):
    """'참고: 출처 〈자료〉 · …' 줄 — 카탈로그 short 이름과 일치, 행 refs에 있는지(경고)"""
    m = RE_REFNOTE.search(ln)
    if not m:
        return
    names = [s.strip(" ·") for s in RE_REFSHORT.findall(m.group(1))]
    if not names:
        err(where, f"'참고:' 뒤에는 '출처 〈자료〉' 형식: {ln[:50]}")
    for nm in names:
        if nm not in REF_SHORT:
            err(where, f"참고 문헌 카탈로그 short에 없는 이름 '{nm}'")
        elif REF_SHORT[nm] not in (ROWS[rid].get("refs") or []):
            warn(where, f"참고 문헌 {REF_SHORT[nm]}가 이 행의 refs에 없음")


def check_refs(where, rid, text):
    """문구 전체에 쓰인 참조 ID의 존재·행 매핑 일치"""
    x = ROWS[rid]
    for s in RE_AIA.findall(text):
        if s not in AIA_IDS:
            err(where, f"없는 세부위협 ID {s}")
    for a in RE_ATLAS_TECH.findall(text):
        if a not in ATLAS["techniques"] and a not in ATLAS_INDEX:
            err(where, f"ATLAS에 없는 기법 {a}")
        elif a not in (x.get("atlas") or []):
            warn(where, f"ATLAS 기법 {a}가 이 행의 atlas 매핑에 없음")
    for a in RE_ATK.findall(text):
        if a not in ATK_INDEX:
            err(where, f"ATT&CK v19.2에 없는 ID {a}")
    links = {k for f in ("ai", "cl", "ot", "sc", "idn", "ph") for k in x.get(f) or []}
    for m in RE_XM.findall(text):
        if m not in LINKS:
            err(where, f"다른 매트릭스에 없는 ID {m}")
        elif m not in links:
            err(where, f"다른 매트릭스 ID {m}가 이 행의 연계에 없음")
    for o in RE_OWASP.findall(text):
        if o not in OWASP:
            err(where, f"OWASP 카탈로그에 없는 ID {o}")
        elif o not in (x.get("owasp") or []):
            warn(where, f"OWASP {o}가 이 행의 owasp 매핑에 없음")
    for grp in RE_NIST.findall(text):
        for k in grp.split("·"):
            if k not in NIST:
                err(where, f"NIST SP 800-53에 없는 통제 {k}")
            elif k not in (x.get("nist") or []):
                warn(where, f"NIST {k}가 이 행의 대응 기준 매핑에 없음")
    for bad, good in BANNED.items():
        if bad in text:
            err(where, f"용어 '{bad}' → '{good}'")
    for g in BANNED_GUARD:
        if g in text:
            err(where, f"가드레일(D11): 공세 제작법·악용 절차 표현 '{g}' — 방어 관점(탐지·대응)으로 다시 씀")


def check_case_line(where, rid, ln, stats):
    body = ln[2:].strip()
    if body.startswith("공개 사고 미확인"):
        stats["note"] += 1
        if "—" not in body:
            err(where, "'공개 사고 미확인 — 사유' 형식으로 사유를 적음")
        return None
    if body.startswith("참고:"):
        err(where, "'참고:'는 ■ 실제 사례가 아니라 ■ 관점·■ 대응 끝에 적음")
        return None
    m = re.match(r"(\[[^\]]+\])\s*(.+)$", body)
    if not m or m.group(1) not in CASE_LABELS:
        err(where, "실제 사례 줄은 [실제 사고]·[위협인텔]·[실증]·[시나리오] 또는 '공개 사고 미확인 — 사유'로 시작: "
                   f"{body[:40]}")
        return None
    label, rest = m.group(1), m.group(2)
    stats[label] += 1
    ids = RE_AII.findall(rest)
    cited = [INC[i] for i in ids if i in INC]
    for i in ids:
        if i not in INC:
            err(where, f"사고 DB에 없는 사례 ID {i}")
            continue
        e = INC[i]
        if rid not in (e.get("aia") or []):
            err(where, f"{i}는 이 행에 매핑되지 않은 사고(매핑: {', '.join(e.get('aia') or [])})")
        want = CASE_LABELS[label]
        if want and e["status"] != want:
            err(where, f"{i} 라벨 {label}이 집계 상태 '{e['status']}'와 다름")
    refs = set().union(*[set(e.get("attack_ref") or []) for e in cited]) if cited else set()
    for a in RE_ATLAS_CASE.findall(rest) + RE_ATK.findall(rest):
        if cited and a not in refs:
            err(where, f"{a}가 인용 사고({', '.join(ids)})의 attack_ref에 없음 — 사고 DB와 맞출 것")
    if label in ("[실제 사고]", "[위협인텔]", "[실증]"):
        if not ids:
            err(where, f"{label} 줄에 사고 ID(AII-NNN) 없음: {rest[:40]}")
        md = RE_DATE.search(rest)
        if not md:
            err(where, f"사례명 뒤 '(YYYY-MM)' 시점 표기 없음: {rest[:40]}")
        else:
            for e in cited:
                if e["date"] != md.group(1):
                    err(where, f"{e['id']} 시점 불일치(문구 {md.group(1)}, 사고 DB {e['date']})")
        desc = rest.split(":", 1)[1] if ":" in rest else rest
        desc = re.sub(r"\((?:AII-|AML\.|T\d)[^)]*\)\s*$", "", desc)
        corpus = " ".join(e["title"] + " " + " ".join(e["summary"].split()) for e in cited)
        for num in RE_NUM.findall(desc):
            if len(num.replace(",", "").replace(".", "")) < 2:
                continue
            if num not in corpus and num.replace(",", "") not in corpus.replace(",", ""):
                warn(where, f"수치 '{num}'이 인용 사고({', '.join(ids)})의 제목·요약에 없음 — 출처 확인")
    return label


def check_texts(ev):
    files = sorted((DATA / "text").glob("*.yaml")) if (DATA / "text").exists() else []
    seen, onelines = {}, collections.defaultdict(list)
    stats = collections.Counter()
    for f in files:
        d = load(f, {}) or {}
        for rid, t in d.items():
            where = f"text/{f.name} {rid}"
            if rid not in ROWS:
                err(where, "분류 체계에 없는 세부위협 ID")
                continue
            if rid in seen:
                err(where, f"문구 중복(이미 {seen[rid]}에 있음)")
            seen[rid] = f.name
            if not rid.startswith(f"AIA-{f.stem}-"):
                warn(where, f"도메인 파일({f.name})과 ID 도메인이 다름")
            t = t or {}
            for k in ("oneline", "summary", "reference", "detect"):
                if not t.get(k):
                    err(where, f"'{k}' 없음")
            ol = t.get("oneline") or ""
            if len(ol) > 50:
                err(where, f"oneline {len(ol)}자(50자 이내)")
            if ol.endswith((".", "다")):
                warn(where, "oneline은 명사형으로 끝냄")
            onelines[ol].append(rid)
            sm = (t.get("summary") or "").splitlines()
            if len(sm) != 2 or not all(s.startswith("- ") for s in sm):
                err(where, "summary는 '- '로 시작하는 2줄")
            elif not sm[0].rstrip().endswith("수 있음"):
                warn(where, "summary 1줄은 '공격자는 … 할 수 있음' 형식")
            for s in sm:
                if len(s) > 180:
                    warn(where, f"summary 줄이 김({len(s)}자)")
            ref = sections(t.get("reference"))
            if list(ref) != ["관점", "실제 사례"]:
                err(where, f"reference 구성은 ■ 관점 → ■ 실제 사례(현재: {list(ref)})")
            for sec, lines in ref.items():
                for ln in lines:
                    if ln and not ln.startswith("- "):
                        err(where, f"reference '{sec}' 줄은 '- '로 시작: {ln[:30]}")
            labels = collections.Counter()
            for ln in ref.get("실제 사례", []):
                if ln.startswith("- "):
                    labels[check_case_line(where, rid, ln, stats)] += 1
            if len([ln for ln in ref.get("관점", []) if ln.startswith("- ")]) < 2:
                warn(where, "■ 관점 항목이 2개 미만")
            for ln in ref.get("관점", []):
                check_refnote(where, rid, ln)
            n_cases = sum(v for k, v in labels.items() if k)
            if ev[rid]["real"] and not labels["[실제 사고]"]:
                err(where, f"실제 사고 {len(ev[rid]['real'])}건이 매핑된 행인데 [실제 사고] 사례 인용 없음")
            if not n_cases and not any(ln[2:].startswith("공개 사고 미확인") for ln in ref.get("실제 사례", [])):
                err(where, "인용 사례가 없으면 '공개 사고 미확인 — 사유'를 적음")
            det = sections(t.get("detect"))
            if list(det) != ["탐지", "대응"]:
                err(where, f"detect 구성은 ■ 탐지 → ■ 대응(현재: {list(det)})")
            for sec, lines in det.items():
                if not [ln for ln in lines if ln.startswith("- ")]:
                    err(where, f"detect '{sec}' 항목 없음")
                for ln in lines:
                    if ln and not ln.startswith("- "):
                        err(where, f"detect '{sec}' 줄은 '- '로 시작: {ln[:30]}")
                    if "참고:" in ln and sec != "대응":
                        err(where, "'참고:'는 ■ 대응 끝에만 적음")
                    if "참고:" in ln:
                        check_refnote(where, rid, ln)
            check_refs(where, rid, "\n".join(str(t.get(k) or "") for k in ("oneline", "summary", "reference", "detect")))
    missing = [rid for rid in ROWS if rid not in seen]
    if missing and ALLOW_MISSING_TEXT:
        print(f"참고 data/text: 문구 미작성 {len(missing)}개 — " + ", ".join(missing))
    else:
        for rid in missing:
            err("data/text", f"{rid} 문구 없음")
    for ol, rids in onelines.items():
        if ol and len(rids) > 1:
            err("data/text", f"oneline 중복 {rids}: {ol}")
    return len(seen), stats


# ===========================================================================
# 6) 공격 체인 시나리오(data/scenarios.yaml) — ③단계
# ===========================================================================
def check_scenarios():
    n = 0
    for s in SCENARIOS.get("scenarios") or []:
        where = f"scenarios.yaml {s.get('id')}"
        n += 1
        if not re.fullmatch(r"ASN-\d{2}", str(s.get("id"))):
            err(where, "ID 형식(ASN-NN) 오류")
        for f in ("id", "title", "incidents", "summary", "steps", "chokepoints"):
            if not s.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for i in s.get("incidents") or []:
            if i not in INC:
                err(where, f"사고 DB에 없는 사례 ID {i}")
        rows_in_steps = set()
        for j, st in enumerate(s.get("steps") or [], 1):
            for k in st.get("aia") or []:
                if k not in ROWS:
                    err(f"{where} 단계 {j}", f"없는 세부위협 ID {k}")
                rows_in_steps.add(k)
            for f in ("aia", "단계", "행위", "탐지"):
                if not st.get(f):
                    err(f"{where} 단계 {j}", f"필드 '{f}' 없음")
            if st.get("단계") and st["단계"] not in R.STAGES:
                err(f"{where} 단계 {j}", f"킬체인 단계 어휘가 아닌 단계 {st['단계']}")
            joined = " ".join(str(v) for v in st.values())
            for a in RE_ATK.findall(joined) + RE_ATLAS_CASE.findall(joined):
                if a not in ATK_INDEX and a not in ATLAS_INDEX:
                    err(f"{where} 단계 {j}", f"ATLAS/ATT&CK 색인에 없는 ID {a}")
            for i in RE_AII.findall(joined):
                if i not in (s.get("incidents") or []):
                    err(f"{where} 단계 {j}", f"단계에 쓴 사고 ID {i}가 시나리오 근거 사고(incidents)에 없음")
        for i in s.get("incidents") or []:
            if i in INC and not (set(INC[i].get("aia") or []) & rows_in_steps):
                warn(where, f"{i}의 매핑 세부위협이 시나리오 단계에 하나도 없음")
        for c in s.get("chokepoints") or []:
            for k in RE_AIA.findall(str(c)):
                if k not in rows_in_steps:
                    warn(where, f"초크 포인트의 {k}가 시나리오 단계에 없음")
    return n


def main():
    global ALLOW_MISSING_TEXT
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="경고도 실패로 처리")
    ap.add_argument("--data-only", action="store_true", help="문구 검사 없이 원천 데이터·시나리오만 점검(v1 단계)")
    ap.add_argument("--allow-missing-text", action="store_true",
                    help="문구가 없는 세부위협은 오류 대신 미작성 목록으로만 표시")
    a = ap.parse_args()
    ALLOW_MISSING_TEXT = a.allow_missing_text

    check_frameworks()
    check_taxonomy()
    check_incidents()
    ev = row_evidence()
    n_text, stats = (0, collections.Counter()) if a.data_only else check_texts(ev)
    n_scn = check_scenarios()

    for m in ERR:
        print(m)
    for m in WARN:
        print(m)
    real_rows = sum(1 for k in ROWS if ev[k]["real"])
    cases = sum(v for k, v in stats.items() if k and k != "note")
    print(f"세부위협 {len(ROWS)}개(문구 {n_text}) · 사고 {len(INCIDENTS)}건 · 시나리오 {n_scn}개 · "
          f"실제 사고가 매핑된 행 {real_rows}개 · 인용 사례 {cases}건")
    print(f"— 오류 {len(ERR)} · 경고 {len(WARN)}")
    if ERR or (a.strict and WARN):
        sys.exit(1)


if __name__ == "__main__":
    main()
