# -*- coding: utf-8 -*-
"""
물리·인적 보안위협 매트릭스 — 데이터·문구 검증기
--------------------------------------------
빌드 입력(data/·scripts/taxonomy_rules.py)의 정합성과 물리 관점 문구(data/text/*.yaml)의 작성 규칙을 점검한다
(아이덴티티·공급망 매트릭스 scripts/validate.py와 같은 구성).

  · 원천 데이터 : ID 형식·중복, 분류 체계 필드·어휘(공격 단계·주체 유형·적용 프로파일), ATT&CK 미연계 사유,
                  교차 매핑·대응 기준·다른 매트릭스·참고 문헌 키가 카탈로그에 있는지, 참고 문헌 카탈로그 필드,
                  사고 DB 필드·어휘, 사고↔세부위협·ATT&CK·다른 매트릭스 사고 ID 형식, 출처 '출처 | URL'
  · 문구 형식   : oneline 50자 이내, summary 2줄, reference(■ 물리 관점 / ■ 실제 사례)·detect(■ 탐지 / ■ 대응) 구성
  · 사례 대조   : 인용한 사고 ID가 그 행에 매핑됐는지, 라벨([실제 사고]·[정부 경보]·[위협인텔]·[실증])이 집계 상태와 맞는지,
                  사례명 뒤 (YYYY-MM)이 사고 DB 시점과 같은지, 설명 속 수치가 인용 사고 요약에 있는지(경고)
  · 참조 ID     : PHT·ATT&CK·다른 매트릭스·NIST·ISO 27001·ISMS-P·CERT ID 존재와 행 매핑 일치
  · 참고 문헌   : '참고: 출처 〈자료〉'는 ■ 물리 관점·■ 대응에만, 카탈로그 short 이름과 일치, 사례 라벨로 쓰지 않음(작업방향 6.5.4)
  · 근거 수준   : 실제 사고가 매핑된 행은 [실제 사고] 사례를 하나 이상 인용, 사례가 없으면 '공개 사고 미확인 — 사유'
  · 용어        : 인증정보·크리덴셜 대신 자격증명
  · 시나리오    : data/scenarios.yaml의 단계별 PHT·사고 ID·공격 단계 어휘·초크 포인트

실행 : python3 scripts/validate.py [--strict] [--data-only] [--allow-missing-text]
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
ALLOW_MISSING_TEXT = False


def err(where, msg):
    ERR.append(f"[오류] {where}: {msg}")


def warn(where, msg):
    WARN.append(f"[경고] {where}: {msg}")


# ---------------------------------------------------------------------------
# YAML — 같은 키가 두 번 나오면 PyYAML은 조용히 덮어쓰므로 중복 키를 오류로 잡는다
# ---------------------------------------------------------------------------
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
        err(p.relative_to(ROOT), f"YAML 파싱 실패 — {e}")
        return default


TAX = load(DATA / "taxonomy.yaml")
FW = load(DATA / "frameworks.yaml")
INCIDENTS = load(DATA / "incidents.yaml", []) or []
SCENARIOS = load(DATA / "scenarios.yaml", {}) or {}
ATK = json.loads((REF / "attack" / "enterprise-attack-v19.2-subset.json").read_text(encoding="utf-8"))
ATK_INDEX = ATK["index"]
ITKB = json.loads((REF / "itkb" / "insider-threat-ttp-kb.json").read_text(encoding="utf-8"))
NIST = json.loads((REF / "nist" / "sp800-53r5-names.json").read_text(encoding="utf-8"))["names"]
LINKS = json.loads((REF / "links" / "other_matrices.json").read_text(encoding="utf-8"))["ids"]
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
PHT_IDS = set(ROWS) | LV2

RE_PHT = re.compile(r"PHT-[A-Z]{2}-\d{2}(?:\.\d)?")
RE_PHI = re.compile(r"PHI-\d{3}")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
RE_ATK = re.compile(r"(?<![A-Za-z0-9-])(T\d{4}(?:\.\d{3})?|[GSC]\d{4})(?![A-Za-z0-9])")
RE_XM = re.compile(r"(?<![A-Za-z0-9-])(IDT-[A-Z]{2}-\d{2}(?:\.\d)?|SCT-[A-Z]{2}-\d{2}(?:\.\d)?|OTC-[A-Z0-9]{2}-\d{2}(?:\.\d)?|"
                   r"OT-[A-Z0-9]{2}-\d{2}|CL-[A-Z]{2}-\d{2}|AI-\d{2}-\d{2})(?![A-Za-z0-9])")
RE_ISO = re.compile(r"ISO 27001 (\d\.\d+(?:·\d\.\d+)*)")
RE_ISMS = re.compile(r"ISMS-P (\d\.\d+\.\d+(?:·\d\.\d+\.\d+)*)")
RE_CERT = re.compile(r"CERT (\d+(?:·\d+)*)")
RE_NIST = re.compile(r"NIST (?:SP 800-53 )?((?:[A-Z]{2}-\d+(?:\(\d+\))?)(?:·[A-Z]{2}-\d+(?:\(\d+\))?)*)")
RE_DATE = re.compile(r"\((\d{4}-\d{2})\):")
RE_NUM = re.compile(r"\d+(?:[.,]\d+)*")
RE_REFNOTE = re.compile(r"참고: (.+)$")
RE_REFSHORT = re.compile(r"[^·〈〉]+?〈[^〉]+〉")

CASE_LABELS = {"[실제 사고]": "실제 사고", "[정부 경보]": "정부 경보", "[위협인텔]": "위협인텔", "[실증]": "실증·연구",
               "[공개 취약점]": None, "[시나리오]": None}
BANNED = {"인증정보": "자격증명", "인증 정보": "자격증명", "크리덴셜": "자격증명", "자격 증명": "자격증명"}
XM_FIELD = {"IDT-": "idt", "SCT-": "sct", "OTC-": "ot", "OT-": "ot", "CL-": "cloud", "AI-": "ai"}
CTL = {"iso": "iso27001", "ismsp": "ismsp", "cert": "cert"}


def xm_field(k):
    return next(f for p, f in XM_FIELD.items() if k.startswith(p))


# ===========================================================================
# 1) 원천 데이터 — 분류 체계·카탈로그
# ===========================================================================
def check_frameworks():
    for cat, vocab in (("stages", R.STAGES), ("actor_types", R.ACTOR_TYPES), ("profiles", R.PROFILES)):
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


def check_taxonomy():
    codes = [d["code"] for d in TAX["domains"]]
    if codes != R.DOMAIN_ORDER:
        err("taxonomy.yaml", f"도메인 순서·코드가 taxonomy_rules.DOMAIN_ORDER와 다름({codes})")
    for d in TAX["domains"]:
        for f in ("ko", "en", "desc", "excludes"):
            if not d.get(f):
                err(f"taxonomy.yaml {d['code']}", f"도메인 필드 '{f}' 없음")
        for l2 in d["lv2"]:
            if not re.fullmatch(rf"PHT-{d['code']}-\d{{2}}", l2["id"]):
                err(f"taxonomy.yaml {l2['id']}", "위협분류 ID 형식(PHT-<도메인>-NN) 오류")
            for x in l2["lv3"]:
                if not (x["id"] == l2["id"] or re.fullmatch(rf"{re.escape(l2['id'])}\.\d", x["id"])):
                    err(f"taxonomy.yaml {x['id']}", f"세부위협 ID가 위협분류 {l2['id']} 체계와 맞지 않음")
            if len(l2["lv3"]) > 1 and any(x["id"] == l2["id"] for x in l2["lv3"]):
                err(f"taxonomy.yaml {l2['id']}", "하위 세부위협이 여럿이면 Lv2 ID를 Lv3로 쓰지 않음")
    for rid, x in ROWS.items():
        where = f"taxonomy.yaml {rid}"
        for f in ("name", "en", "stage", "actors", "profiles", "assets", "severity", "severity_why"):
            if not x.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for f in ("attack", "nist", "iso", "ismsp", "cert", "idt", "sct", "ot", "cloud", "ai", "refs"):
            if f not in x:
                err(where, f"필드 '{f}' 없음(해당 없으면 [])")
        for t in x.get("attack") or []:
            if t not in ATK["techniques"]:
                err(where, f"ATT&CK 추출본에 없는 기법 {t} — scripts/prepare_attack.py 재실행 필요")
        if not x.get("attack") and not x.get("attack_none"):
            err(where, "ATT&CK 연계가 없으면 attack_none에 미연계 사유를 적음")
        if x.get("attack") and x.get("attack_none"):
            warn(where, "ATT&CK 연계가 있는데 attack_none도 있음")
        for k in x.get("nist") or []:
            if k not in NIST:
                err(where, f"NIST SP 800-53 Rev.5에 없는 통제 {k}")
        for fld, cat in CTL.items():
            keys = {str(k) for k in FW[cat]}
            for k in x.get(fld) or []:
                if str(k) not in keys:
                    err(where, f"{fld} 카탈로그(frameworks.yaml {cat})에 없는 ID {k}")
        for fld in ("idt", "sct", "ot", "cloud", "ai"):
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
        for v, vocab, name in ((x.get("stage"), R.STAGES, "공격 단계"), (x.get("actors"), R.ACTOR_TYPES, "주체 유형"),
                               (x.get("profiles"), R.PROFILES, "적용 프로파일")):
            for s in v or []:
                if s not in vocab:
                    err(where, f"정의되지 않은 {name} {s}")
        if x.get("severity") == "상" and len(x.get("severity_why") or "") < 30:
            warn(where, "심각도 '상'은 피해 범위를 severity_why에 적음")
    for (c, k) in R.FRAMEWORK_NOT_MAPPED:
        cat = CTL.get(c)
        if not cat or str(k) not in {str(v) for v in FW[cat]}:
            err("taxonomy_rules.FRAMEWORK_NOT_MAPPED", f"{c} 카탈로그에 없는 ID {k}")
        elif any(str(k) in [str(v) for v in x.get(c) or []] for x in ROWS.values()):
            warn("taxonomy_rules.FRAMEWORK_NOT_MAPPED", f"{c} {k}는 이미 세부위협에 매핑됨 — 미연계 사유 삭제")
    for c, cat in CTL.items():
        used = {str(v) for x in ROWS.values() for v in x.get(c) or []}
        for k in FW[cat]:
            if str(k) not in used and (c, k) not in R.FRAMEWORK_NOT_MAPPED and (c, str(k)) not in R.FRAMEWORK_NOT_MAPPED:
                warn(f"frameworks.yaml {cat}", f"{k}가 어느 세부위협에도 매핑되지 않음 — 매핑하거나 FRAMEWORK_NOT_MAPPED에 사유 기록")
    for t in R.ATTACK_COUNT_ALL | R.ATTACK_COUNT_KEYWORD:
        if t not in ATK_INDEX:
            err("taxonomy_rules.ATTACK_COUNT", f"ATT&CK v19.2에 없는 기법 {t}")
    for k in REFS:
        if not any(k in (x.get("refs") or []) for x in ROWS.values()):
            warn("frameworks.yaml references", f"{k}를 인용한 세부위협이 없음")


# ===========================================================================
# 2) 사고 DB
# ===========================================================================
INC = {}


def check_incidents():
    for n, e in enumerate(INCIDENTS):
        i = e.get("id", f"#{n}")
        where = f"incidents.yaml {i}"
        if not re.fullmatch(r"PHI-\d{3}", str(i)):
            err(where, "ID 형식(PHI-NNN) 오류")
        if i in INC:
            err(where, "ID 중복")
        INC[i] = e
        for f in ("title", "date", "kind", "verification", "region", "sector", "actor", "actor_type", "impact", "summary",
                  "pht", "sources"):
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
        for fld, vocab, name in (("sector", R.SECTORS, "업종"), ("actor_type", R.ACTOR_TYPES, "주체 유형"),
                                 ("impact", R.IMPACTS, "영향")):
            for v in e.get(fld) or []:
                if v not in vocab:
                    err(where, f"{name} '{v}'가 정의된 어휘에 없음")
        for k in e.get("pht") or []:
            if k not in ROWS:
                err(where, f"매핑 세부위협 {k} 없음")
        if len(set(e.get("pht") or [])) != len(e.get("pht") or []):
            err(where, "매핑 세부위협 중복")
        for a in e.get("attack_ref") or []:
            if a not in ATK_INDEX:
                err(where, f"ATT&CK v19.2에 없는 ID {a}")
        for o in e.get("origin") or []:
            if not re.fullmatch(r"(IDI-\d{3}|SCI-\d{3}|INC-\d{3,4})", str(o)):
                err(where, f"origin 형식(IDI-·SCI-·INC-) 오류: {o}")
        for s in e.get("sources") or []:
            if not re.fullmatch(r".+ \| https?://\S+", str(s)):
                err(where, f"출처 형식('출처 | URL') 오류: {str(s)[:60]}")
        if "TODO" in " ".join(str(s) for s in e.get("sources") or []) or "TODO" in str(e.get("summary", "")):
            err(where, "TODO가 남아 있음 — 1차 출처로 확정")
        e["status"] = R.incident_status(e) if e.get("kind") in R.KINDS and e.get("verification") else "?"


def check_context():
    for d in TAX["domains"]:
        for c in d.get("context") or []:
            where = f"taxonomy.yaml {d['code']} context"
            for f in ("text", "source"):
                if not c.get(f):
                    err(where, f"필드 '{f}' 없음")
            if c.get("source") and not re.fullmatch(r".+ \| https?://\S+", c["source"]):
                err(where, f"출처 형식('출처 | URL') 오류: {c['source'][:60]}")


# ===========================================================================
# 3) 행별 근거(빌드 스크립트와 같은 규칙)
# ===========================================================================
def row_evidence():
    ev = {k: dict(real=set(), advisory=set(), research=set(), intel=set()) for k in ROWS}
    key = {"실제 사고": "real", "정부 경보": "advisory", "실증·연구": "research", "위협인텔": "intel"}
    for e in INCIDENTS:
        for k in e.get("pht") or []:
            if key.get(e.get("status")) and k in ev:
                ev[k][key[e["status"]]].add(e["id"])
    return ev


# ===========================================================================
# 4) 물리 관점 문구
# ===========================================================================
def sections(text):
    out, cur = collections.OrderedDict(), None
    for ln in (text or "").splitlines():
        if ln.startswith("■ "):
            cur = ln[2:].strip()
            out[cur] = []
        else:
            out.setdefault(cur, []).append(ln)
    return out


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
    for s in RE_PHT.findall(text):
        if s not in PHT_IDS:
            err(where, f"없는 세부위협 ID {s}")
    for a in RE_ATK.findall(text):
        if a not in ATK_INDEX:
            err(where, f"ATT&CK v19.2에 없는 ID {a}")
    links = {k for f in ("idt", "sct", "ot", "cloud", "ai") for k in x.get(f) or []}
    for m in RE_XM.findall(text):
        if m not in LINKS:
            err(where, f"다른 매트릭스에 없는 ID {m}")
        elif m not in links:
            err(where, f"다른 매트릭스 ID {m}가 이 행의 연계(idt·sct·ot·cloud·ai)에 없음")
    for grp in RE_NIST.findall(text):
        for k in grp.split("·"):
            if k not in NIST:
                err(where, f"NIST SP 800-53에 없는 통제 {k}")
            elif k not in (x.get("nist") or []):
                warn(where, f"NIST {k}가 이 행의 대응 기준 매핑에 없음")
    for rx, fld, cat, label in ((RE_ISO, "iso", "iso27001", "ISO 27001"), (RE_ISMS, "ismsp", "ismsp", "ISMS-P"),
                                (RE_CERT, "cert", "cert", "CERT")):
        keys = {str(k) for k in FW[cat]}
        for grp in rx.findall(text):
            for k in grp.split("·"):
                if k not in keys:
                    err(where, f"{label} 카탈로그에 없는 항목 {k}")
                elif k not in [str(v) for v in x.get(fld) or []]:
                    warn(where, f"{label} {k}가 이 행의 대응 기준 매핑에 없음")
    for bad, good in BANNED.items():
        if bad in text:
            err(where, f"용어 '{bad}' → '{good}'")


def check_case_line(where, rid, ln, stats):
    body = ln[2:].strip()
    if body.startswith("공개 사고 미확인"):
        stats["note"] += 1
        if "—" not in body:
            err(where, "'공개 사고 미확인 — 사유' 형식으로 사유를 적음")
        return None
    if body.startswith("참고:"):
        err(where, "'참고:'는 ■ 실제 사례가 아니라 ■ 물리 관점·■ 대응 끝에 적음(작업방향 6.5.4)")
        return None
    m = re.match(r"(\[[^\]]+\])\s*(.+)$", body)
    if not m or m.group(1) not in CASE_LABELS:
        err(where, "실제 사례 줄은 [실제 사고]·[정부 경보]·[위협인텔]·[실증]·[공개 취약점]·[시나리오] 또는 '공개 사고 미확인 — 사유'로 시작: "
                   f"{body[:40]}")
        return None
    label, rest = m.group(1), m.group(2)
    stats[label] += 1
    ids = RE_PHI.findall(rest)
    cited = [INC[i] for i in ids if i in INC]
    for i in ids:
        if i not in INC:
            err(where, f"사고 DB에 없는 사례 ID {i}")
            continue
        e = INC[i]
        if rid not in e["pht"]:
            err(where, f"{i}는 이 행에 매핑되지 않은 사고(매핑: {', '.join(e['pht'])})")
        want = CASE_LABELS[label]
        if want and e["status"] != want:
            err(where, f"{i} 라벨 {label}이 집계 상태 '{e['status']}'와 다름")
        if label in ("[공개 취약점]", "[시나리오]"):
            err(where, f"{label} 줄에 사고 ID {i} 인용 — 사고면 [실제 사고]/[정부 경보]/[위협인텔]/[실증] 라벨 사용")
    refs = set().union(*[set(e.get("attack_ref") or []) for e in cited]) if cited else set()
    for a in RE_ATK.findall(rest):
        if cited and a not in refs:
            err(where, f"ATT&CK {a}가 인용 사고({', '.join(ids)})의 attack_ref에 없음 — 사고 DB와 맞출 것")
    if label in ("[실제 사고]", "[정부 경보]", "[위협인텔]", "[실증]"):
        if not ids:
            err(where, f"{label} 줄에 사고 ID(PHI-NNN) 없음: {rest[:40]}")
        md = RE_DATE.search(rest)
        if not md:
            err(where, f"사례명 뒤 '(YYYY-MM):' 시점 표기 없음: {rest[:40]}")
        else:
            for e in cited:
                if e["date"] != md.group(1):
                    err(where, f"{e['id']} 시점 불일치(문구 {md.group(1)}, 사고 DB {e['date']})")
        desc = rest.split(":", 1)[1] if ":" in rest else rest
        desc = re.sub(r"\((?:PHI|ATT&CK)[^)]*\)\s*$", "", desc)
        corpus = " ".join(e["title"] + " " + " ".join(e["summary"].split()) for e in cited)
        for num in RE_NUM.findall(desc):
            if len(num.replace(",", "").replace(".", "")) < 2:
                continue
            if num not in corpus and num.replace(",", "") not in corpus.replace(",", ""):
                warn(where, f"수치 '{num}'이 인용 사고({', '.join(ids)})의 제목·요약에 없음 — 출처 확인")
    if label == "[공개 취약점]" and not RE_CVE.findall(rest):
        err(where, f"[공개 취약점] 줄에 CVE 없음: {rest[:40]}")
    return label


def check_texts(ev):
    files = sorted((DATA / "text").glob("*.yaml"))
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
            if not rid.startswith(f"PHT-{f.stem}-"):
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
                warn(where, "summary 1줄은 '공격자는 … 할 수 있음' 형식(행위 주체가 내부자 등이면 주어만 바꿈)")
            for s in sm:
                if len(s) > 170:
                    warn(where, f"summary 줄이 김({len(s)}자)")
            ref = sections(t.get("reference"))
            if list(ref) != ["물리 관점", "실제 사례"]:
                err(where, f"reference 구성은 ■ 물리 관점 → ■ 실제 사례(현재: {list(ref)})")
            for sec, lines in ref.items():
                for ln in lines:
                    if not ln.startswith("- "):
                        err(where, f"reference '{sec}' 줄은 '- '로 시작: {ln[:30]}")
            labels = collections.Counter()
            for ln in ref.get("실제 사례", []):
                if ln.startswith("- "):
                    labels[check_case_line(where, rid, ln, stats)] += 1
            if len(ref.get("물리 관점", [])) < 2:
                warn(where, "■ 물리 관점 항목이 2개 미만")
            for ln in ref.get("물리 관점", []):
                check_refnote(where, rid, ln)
                for a in RE_ATK.findall(ln):
                    if a.startswith("T") and a not in ROWS[rid]["attack"]:
                        warn(where, f"물리 관점의 기법 {a}가 이 행의 ATT&CK 매핑에 없음")
            n_cases = sum(v for k, v in labels.items() if k)
            if ev[rid]["real"] and not labels["[실제 사고]"]:
                err(where, f"실제 사고 {len(ev[rid]['real'])}건이 매핑된 행인데 [실제 사고] 사례 인용 없음")
            if not n_cases and not any(ln[2:].startswith("공개 사고 미확인") for ln in ref.get("실제 사례", [])):
                err(where, "인용 사례가 없으면 '공개 사고 미확인 — 사유'를 적음")
            det = sections(t.get("detect"))
            if list(det) != ["탐지", "대응"]:
                err(where, f"detect 구성은 ■ 탐지 → ■ 대응(현재: {list(det)})")
            for sec, lines in det.items():
                if not lines:
                    err(where, f"detect '{sec}' 항목 없음")
                for ln in lines:
                    if not ln.startswith("- "):
                        err(where, f"detect '{sec}' 줄은 '- '로 시작: {ln[:30]}")
                    if "참고:" in ln:
                        if sec != "대응":
                            err(where, "'참고:'는 ■ 대응 끝에만 적음")
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
# 5) 공격 체인 시나리오
# ===========================================================================
def check_scenarios():
    n = 0
    for s in SCENARIOS.get("scenarios") or []:
        where = f"scenarios.yaml {s.get('id')}"
        n += 1
        if not re.fullmatch(r"PSN-\d{2}", str(s.get("id"))):
            err(where, "ID 형식(PSN-NN) 오류")
        for f in ("id", "title", "incidents", "summary", "steps", "chokepoints"):
            if not s.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for i in s.get("incidents") or []:
            if i not in INC:
                err(where, f"사고 DB에 없는 사례 ID {i}")
        rows_in_steps = set()
        for j, st in enumerate(s.get("steps") or [], 1):
            for k in st.get("pht") or []:
                if k not in ROWS:
                    err(f"{where} 단계 {j}", f"없는 세부위협 ID {k}")
                rows_in_steps.add(k)
            for f in ("pht", "단계", "행위", "탐지"):
                if not st.get(f):
                    err(f"{where} 단계 {j}", f"필드 '{f}' 없음")
            if st.get("단계") and st["단계"] not in R.STAGES:
                err(f"{where} 단계 {j}", f"공격 단계 어휘가 아닌 단계 {st['단계']}")
            for a in RE_ATK.findall(" ".join(str(v) for v in st.values())):
                if a not in ATK_INDEX:
                    err(f"{where} 단계 {j}", f"ATT&CK v19.2에 없는 ID {a}")
            for i in RE_PHI.findall(" ".join(str(v) for v in st.values())):
                if i not in (s.get("incidents") or []):
                    err(f"{where} 단계 {j}", f"단계에 쓴 사고 ID {i}가 시나리오 근거 사고(incidents)에 없음")
        for i in s.get("incidents") or []:
            if i in INC and not (set(INC[i]["pht"]) & rows_in_steps):
                warn(where, f"{i}의 매핑 세부위협이 시나리오 단계에 하나도 없음")
        for c in s.get("chokepoints") or []:
            for k in RE_PHT.findall(str(c)):
                if k not in rows_in_steps:
                    warn(where, f"초크 포인트의 {k}가 시나리오 단계에 없음")
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="경고도 실패로 처리")
    ap.add_argument("--data-only", action="store_true", help="문구 검사 없이 원천 데이터·시나리오만 점검(v1 단계)")
    ap.add_argument("--allow-missing-text", action="store_true",
                    help="문구가 없는 세부위협은 오류 대신 미작성 목록으로만 표시(작성된 문구는 그대로 검사)")
    args = ap.parse_args()
    global ALLOW_MISSING_TEXT
    ALLOW_MISSING_TEXT = args.allow_missing_text
    check_frameworks()
    check_taxonomy()
    check_incidents()
    check_context()
    ev = row_evidence()
    n_text, stats = (0, collections.Counter()) if args.data_only else check_texts(ev)
    n_scn = check_scenarios()
    for m in ERR + WARN:
        print(m)
    cases = sum(v for k, v in stats.items() if k != "note")
    st = collections.Counter(e.get("status") for e in INCIDENTS)
    print(f"\n검증 대상: 세부위협 {len(ROWS)}개(위협분류 {len(LV2)}개, 문구 {n_text}개) · 사고 {len(INCIDENTS)}건("
          + " · ".join(f"{k} {v}" for k, v in st.items()) + f") · 참고 문헌 {len(REFS)}개 · 시나리오 {n_scn}개 · 인용 사례 {cases}건"
          + ("(" + " · ".join(f"{k} {v}" for k, v in stats.items() if k != "note") + ")" if cases else ""))
    print(f"검증 결과: 오류 {len(ERR)}건 · 경고 {len(WARN)}건")
    sys.exit(1 if ERR or (args.strict and WARN) else 0)


if __name__ == "__main__":
    main()
