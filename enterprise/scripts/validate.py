# -*- coding: utf-8 -*-
"""
고도화 엔터프라이즈 침해 매트릭스 — 데이터·문구·시나리오 검증기
(aiattack·물리·신원 매트릭스 validate.py와 같은 구성)

실행 : python3 scripts/validate.py [--strict] [--data-only] [--allow-missing-text]
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


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _nodup(loader, node, deep=False):
    seen = set()
    for k_node, _ in node.value:
        k = loader.construct_object(k_node, deep=deep)
        if k in seen:
            raise yaml.constructor.ConstructorError(None, None, f"중복 키 '{k}'", k_node.start_mark)
        seen.add(k)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _nodup)


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
ATK = json.loads((REF / "attack" / "enterprise-attack-v19.2-subset.json").read_text(encoding="utf-8"))
ATK_INDEX = ATK["index"]
KEV = json.loads((REF / "kev" / "kev-subset.json").read_text(encoding="utf-8"))["index"]
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
ENT_IDS = set(ROWS) | LV2

XM_FIELD = {"AI-": "ai", "CL-": "cl", "OT-": "ot", "SC-": "sc", "ID-": "idn", "PH-": "ph"}
RE_ENT = re.compile(r"ENT-[A-Z0-9]{2}-\d{2}(?:\.\d)?")
RE_ENI = re.compile(r"ENI-\d{3}")
RE_ATK = re.compile(r"(?<![A-Za-z0-9.])(T\d{4}(?:\.\d{3})?|[GSC]\d{4})(?![A-Za-z0-9])")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
RE_XM = re.compile(r"(?<![A-Za-z0-9-])(AI-\d{2}-\d{2}|CL-[A-Z]{2}-\d{2}|OT-[A-Z0-9]{2}-\d{2}|SC-[A-Z]{2}-\d{2}|"
                   r"ID-[A-Z]{2}-\d{2}|PH-[A-Z]{2}-\d{2})(?![A-Za-z0-9])")
RE_NIST = re.compile(r"NIST (?:SP 800-53 )?((?:[A-Z]{2}-\d+(?:\(\d+\))?)(?:·[A-Z]{2}-\d+(?:\(\d+\))?)*)")
RE_DATE = re.compile(r"\((\d{4}-\d{2})\)")
RE_NUM = re.compile(r"\d+(?:[.,]\d+)*")
RE_REFNOTE = re.compile(r"참고: (.+)$")
RE_REFSHORT = re.compile(r"[^·〈〉]+?〈[^〉]+〉")
CASE_LABELS = {"[실제 사고]": "실제 사고", "[정부 경보]": "정부 경보", "[위협인텔]": "위협인텔", "[실증]": "실증·연구", "[시나리오]": None}
BANNED = {"인증정보": "자격증명", "인증 정보": "자격증명", "크리덴셜": "자격증명", "자격 증명": "자격증명"}
BANNED_GUARD = ["예시 페이로드", "페이로드 예시", "악성코드 예시", "공격 코드는 다음", "제작 방법은", "만드는 방법은", "다음과 같이 우회"]


def xm_field(k):
    return next((f for p, f in XM_FIELD.items() if k.startswith(p)), None)


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
def check_frameworks():
    for cat, vocab in (("tactics", R.TACTICS), ("legacy_gaps", R.LEGACY_GAPS), ("defense_levels", R.DEFENSE_LEVELS),
                       ("platforms", R.PLATFORMS)):
        if list(FW.get(cat) or {}) != vocab:
            err(f"frameworks.yaml {cat}", f"어휘가 taxonomy_rules.py와 다름({list(FW.get(cat) or {})} ≠ {vocab})")
    for k, v in REFS.items():
        where = f"frameworks.yaml references {k}"
        if not re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", k):
            err(where, "키 형식 오류")
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
                err(where, f"없는 전술 코드 {dm}")
        for u in v.get("use") or []:
            if u not in ("분류 근거", "위협 내용", "대응 문구"):
                err(where, f"use 어휘 아님: {u}")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(v.get("checked", ""))):
            err(where, f"확인일 형식(YYYY-MM-DD) 오류: {v.get('checked')}")
    if len(REF_SHORT) != len(REFS):
        err("frameworks.yaml references", "short 이름 중복")


def check_taxonomy():
    codes = [d["code"] for d in TAX["domains"]]
    if codes != R.DOMAIN_ORDER:
        err("taxonomy.yaml", f"도메인 순서·코드가 DOMAIN_ORDER와 다름({codes})")
    tactic_of = dict(zip(R.DOMAIN_ORDER, R.TACTICS))
    for d in TAX["domains"]:
        for f in ("ko", "en", "desc", "excludes"):
            if not d.get(f):
                err(f"taxonomy.yaml {d['code']}", f"도메인 필드 '{f}' 없음")
        for l2 in d["lv2"]:
            if not re.fullmatch(rf"ENT-{d['code']}-\d{{2}}", l2["id"]):
                err(f"taxonomy.yaml {l2['id']}", "위협분류 ID 형식(ENT-<전술>-NN) 오류")
            for x in l2["lv3"]:
                if not (x["id"] == l2["id"] or re.fullmatch(rf"{re.escape(l2['id'])}\.\d", x["id"])):
                    err(f"taxonomy.yaml {x['id']}", f"세부위협 ID가 위협분류 {l2['id']} 체계와 맞지 않음")
            if len(l2["lv3"]) > 1 and any(x["id"] == l2["id"] for x in l2["lv3"]):
                err(f"taxonomy.yaml {l2['id']}", "하위 세부위협이 여럿이면 Lv2 ID를 Lv3로 쓰지 않음")
    for rid, x in ROWS.items():
        where = f"taxonomy.yaml {rid}"
        for f in ("name", "en", "tactic", "legacy_gap", "defense_level", "actors", "platforms", "severity", "severity_why"):
            if not x.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for f in ("attack", "nist", "ai", "cl", "ot", "sc", "idn", "ph", "refs"):
            if f not in x:
                err(where, f"필드 '{f}' 없음(해당 없으면 [])")
        if not x.get("attack"):
            err(where, "attack(ATT&CK 기법) 1개 이상 필요")
        for t in x.get("attack") or []:
            if t not in ATK["techniques"]:
                err(where, f"ATT&CK 추출본에 없는 기법 {t} — prepare_attack.py 재실행")
        if x.get("tactic") != tactic_of.get(x["code"]):
            err(where, f"tactic '{x.get('tactic')}'가 도메인 전술 '{tactic_of.get(x['code'])}'와 다름")
        if x.get("defense_level") not in R.DEFENSE_LEVELS:
            err(where, f"defense_level 값 오류 {x.get('defense_level')}")
        for g in x.get("legacy_gap") or []:
            if g not in R.LEGACY_GAPS:
                err(where, f"정의되지 않은 레거시 공백 유형 {g}")
        for a in x.get("actors") or []:
            if a not in R.ACTOR_TYPES:
                err(where, f"정의되지 않은 주체 유형 {a}")
        for p in x.get("platforms") or []:
            if p not in R.PLATFORMS:
                err(where, f"정의되지 않은 플랫폼 {p}")
        for f in ("kev", "lolbas", "loldriver"):
            if f in x and not isinstance(x[f], bool):
                err(where, f"{f}는 true/false")
        for k in x.get("nist") or []:
            if k not in NIST:
                err(where, f"NIST SP 800-53 Rev.5에 없는 통제 {k}")
        for fld in ("ai", "cl", "ot", "sc", "idn", "ph"):
            for k in x.get(fld) or []:
                if k not in LINKS:
                    err(where, f"다른 매트릭스에 없는 연계 ID {k}({fld}) — prepare_refs.py 재실행")
                elif xm_field(k) != fld:
                    err(where, f"연계 ID {k}는 '{xm_field(k)}' 필드에 적음(현재 {fld})")
        for k in x.get("refs") or []:
            if k not in REFS:
                err(where, f"참고 문헌 카탈로그에 없는 키 {k}")
            elif x["code"] not in (REFS[k].get("domains") or []):
                warn(where, f"참고 문헌 {k}의 주 전술에 {x['code']}가 없음")
        if len(x.get("refs") or []) > 3:
            err(where, "참고 문헌(refs)은 0~3개")
        if x.get("severity") not in ("상", "중", "하"):
            err(where, f"심각도 값 오류 {x.get('severity')}")
        if x.get("severity") == "상" and len(x.get("severity_why") or "") < 30:
            warn(where, "심각도 '상'은 피해 범위를 severity_why에 적음")
    for k in REFS:
        if not any(k in (x.get("refs") or []) for x in ROWS.values()):
            warn("frameworks.yaml references", f"{k}를 인용한 세부위협이 없음")


INC = {}
ORIGIN_RE = re.compile(r"(IDI-\d{3}|SCI-\d{3}|INC-\d{3,4}|CL/INC-\d{3,4}|OT/INC-\d{3}|AML\.CS\d{4})")


def check_incidents():
    for n, e in enumerate(INCIDENTS):
        i = e.get("id", f"#{n}")
        where = f"incidents.yaml {i}"
        if not re.fullmatch(r"ENI-\d{3}", str(i)):
            err(where, "ID 형식(ENI-NNN) 오류")
        if i in INC:
            err(where, "ID 중복")
        INC[i] = e
        for f in ("title", "date", "kind", "verification", "region", "sector", "actor", "actor_type",
                  "impact", "summary", "ent", "sources"):
            if not e.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        e["date"] = str(e.get("date", ""))
        if not re.fullmatch(r"\d{4}-\d{2}", e["date"]):
            err(where, f"시점 형식(YYYY-MM) 오류: {e['date']}")
        if e.get("kind") not in R.KINDS:
            err(where, f"사례유형 '{e.get('kind')}' 어휘에 없음")
        if e.get("verification") not in R.VERIFICATIONS:
            err(where, f"검증 수준 '{e.get('verification')}' 어휘에 없음")
        if e.get("legal") and e["legal"] not in R.LEGAL:
            err(where, f"법적 처리 '{e['legal']}' 어휘에 없음")
        if e.get("region") and e["region"] not in R.REGIONS:
            err(where, f"지역 '{e['region']}' 어휘에 없음")
        for fld, vocab, name in (("sector", R.SECTORS, "업종"), ("actor_type", R.ACTOR_TYPES, "주체 유형"),
                                 ("impact", R.IMPACTS, "영향")):
            for v in e.get(fld) or []:
                if v not in vocab:
                    err(where, f"{name} '{v}' 어휘에 없음")
        for k in e.get("ent") or []:
            if k not in ROWS:
                err(where, f"매핑 세부위협 {k} 없음")
        if len(set(e.get("ent") or [])) != len(e.get("ent") or []):
            err(where, "매핑 세부위협 중복")
        for a in e.get("attack_ref") or []:
            if a not in ATK_INDEX:
                err(where, f"ATT&CK 색인에 없는 ID {a}")
        for c in e.get("cve") or []:
            if not RE_CVE.fullmatch(str(c)):
                err(where, f"CVE 형식 오류 {c}")
            elif c not in KEV:
                warn(where, f"{c}가 KEV 목록에 없음(KEV 외 취약점이면 비고에 근거)")
        for o in e.get("origin") or []:
            if not ORIGIN_RE.fullmatch(str(o)):
                err(where, f"origin 형식 오류: {o}")
        for s in e.get("sources") or []:
            if not re.fullmatch(r".+ \| https?://\S+", str(s)):
                err(where, f"출처 형식('출처 | URL') 오류: {str(s)[:60]}")
        if "TODO" in " ".join(str(s) for s in e.get("sources") or []) or "TODO" in str(e.get("summary", "")):
            err(where, "TODO가 남아 있음")
        e["status"] = R.incident_status(e) if e.get("kind") in R.KINDS and e.get("verification") else "?"


def row_evidence():
    ev = {k: dict(real=set(), advisory=set(), intel=set(), research=set()) for k in ROWS}
    key = {"실제 사고": "real", "정부 경보": "advisory", "위협인텔": "intel", "실증·연구": "research"}
    for e in INCIDENTS:
        for k in e.get("ent") or []:
            if key.get(e.get("status")) and k in ev:
                ev[k][key[e["status"]]].add(e["id"])
    return ev


# ---- 문구·시나리오 ----
def check_refnote(where, rid, ln):
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
    x = ROWS[rid]
    for s in RE_ENT.findall(text):
        if s not in ENT_IDS:
            err(where, f"없는 세부위협 ID {s}")
    for a in RE_ATK.findall(text):
        if a not in ATK_INDEX:
            err(where, f"ATT&CK v19.2에 없는 ID {a}")
        elif a.startswith("T") and a not in (x.get("attack") or []):
            warn(where, f"ATT&CK {a}가 이 행의 attack 매핑에 없음")
    for c in RE_CVE.findall(text):
        if c not in KEV:
            warn(where, f"CVE {c}가 KEV 목록에 없음")
    for m in RE_XM.findall(text):
        links = {k for f in ("ai", "cl", "ot", "sc", "idn", "ph") for k in x.get(f) or []}
        if m not in LINKS:
            err(where, f"다른 매트릭스에 없는 ID {m}")
        elif m not in links:
            err(where, f"다른 매트릭스 ID {m}가 이 행의 연계에 없음")
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
            err(where, f"가드레일(D11): 공세 제작법 표현 '{g}' — 방어 관점으로 다시 씀")


def check_case_line(where, rid, ln, stats):
    body = ln[2:].strip()
    if body.startswith("공개 사고 미확인"):
        stats["note"] += 1
        if "—" not in body:
            err(where, "'공개 사고 미확인 — 사유' 형식")
        return None
    if body.startswith("참고:"):
        err(where, "'참고:'는 ■ 관점·■ 대응 끝에 적음")
        return None
    m = re.match(r"(\[[^\]]+\])\s*(.+)$", body)
    if not m or m.group(1) not in CASE_LABELS:
        err(where, "실제 사례 줄은 [실제 사고]·[정부 경보]·[위협인텔]·[실증]·[시나리오] 또는 '공개 사고 미확인 — 사유'로 시작: "
                   f"{body[:40]}")
        return None
    label, rest = m.group(1), m.group(2)
    stats[label] += 1
    ids = RE_ENI.findall(rest)
    cited = [INC[i] for i in ids if i in INC]
    for i in ids:
        if i not in INC:
            err(where, f"사고 DB에 없는 사례 ID {i}")
            continue
        e = INC[i]
        if rid not in (e.get("ent") or []):
            err(where, f"{i}는 이 행에 매핑되지 않은 사고(매핑: {', '.join(e.get('ent') or [])})")
        want = CASE_LABELS[label]
        if want and e["status"] != want:
            err(where, f"{i} 라벨 {label}이 집계 상태 '{e['status']}'와 다름")
    refs = set().union(*[set(e.get("attack_ref") or []) | set(e.get("cve") or []) for e in cited]) if cited else set()
    for a in RE_ATK.findall(rest) + RE_CVE.findall(rest):
        if cited and a not in refs:
            err(where, f"{a}가 인용 사고({', '.join(ids)})의 attack_ref·cve에 없음")
    if label in ("[실제 사고]", "[정부 경보]", "[위협인텔]", "[실증]"):
        if not ids:
            err(where, f"{label} 줄에 사고 ID(ENI-NNN) 없음: {rest[:40]}")
        md = RE_DATE.search(rest)
        if not md:
            err(where, f"사례명 뒤 '(YYYY-MM)' 시점 표기 없음: {rest[:40]}")
        else:
            for e in cited:
                if e["date"] != md.group(1):
                    err(where, f"{e['id']} 시점 불일치(문구 {md.group(1)}, DB {e['date']})")
        desc = rest.split(":", 1)[1] if ":" in rest else rest
        desc = RE_CVE.sub("", desc)              # CVE 번호는 인용 사고 cve 필드로 이미 검증 — 수치 대조에서 제외
        desc = RE_ATK.sub("", desc)
        desc = re.sub(r"\((?:ENI-)[^)]*\)\s*$", "", desc)
        corpus = " ".join(e["title"] + " " + " ".join(e["summary"].split()) for e in cited)
        for num in RE_NUM.findall(desc):
            if len(num.replace(",", "").replace(".", "")) < 2:
                continue
            if num not in corpus and num.replace(",", "") not in corpus.replace(",", ""):
                warn(where, f"수치 '{num}'이 인용 사고({', '.join(ids)}) 제목·요약에 없음 — 출처 확인")
    return label


def check_texts(ev):
    files = sorted((DATA / "text").glob("*.yaml")) if (DATA / "text").exists() else []
    seen, onelines, stats = {}, collections.defaultdict(list), collections.Counter()
    for f in files:
        d = load(f, {}) or {}
        for rid, t in d.items():
            where = f"text/{f.name} {rid}"
            if rid not in ROWS:
                err(where, "분류 체계에 없는 세부위협 ID")
                continue
            if rid in seen:
                err(where, f"문구 중복(이미 {seen[rid]})")
            seen[rid] = f.name
            if not rid.startswith(f"ENT-{f.stem}-"):
                warn(where, f"도메인 파일({f.name})과 ID 전술이 다름")
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
                if len(s) > 185:
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


def check_scenarios():
    n = 0
    for s in SCENARIOS.get("scenarios") or []:
        where = f"scenarios.yaml {s.get('id')}"
        n += 1
        if not re.fullmatch(r"ESN-\d{2}", str(s.get("id"))):
            err(where, "ID 형식(ESN-NN) 오류")
        for f in ("id", "title", "incidents", "summary", "steps", "chokepoints"):
            if not s.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for i in s.get("incidents") or []:
            if i not in INC:
                err(where, f"사고 DB에 없는 사례 ID {i}")
        rows_in_steps = set()
        for j, st in enumerate(s.get("steps") or [], 1):
            for k in st.get("ent") or []:
                if k not in ROWS:
                    err(f"{where} 단계 {j}", f"없는 세부위협 ID {k}")
                rows_in_steps.add(k)
            for f in ("ent", "전술", "행위", "탐지"):
                if not st.get(f):
                    err(f"{where} 단계 {j}", f"필드 '{f}' 없음")
            if st.get("전술") and st["전술"] not in R.TACTICS:
                err(f"{where} 단계 {j}", f"전술 어휘가 아닌 {st['전술']}")
            joined = " ".join(str(v) for v in st.values())
            for a in RE_ATK.findall(joined):
                if a not in ATK_INDEX:
                    err(f"{where} 단계 {j}", f"ATT&CK 색인에 없는 ID {a}")
            for i in RE_ENI.findall(joined):
                if i not in (s.get("incidents") or []):
                    err(f"{where} 단계 {j}", f"단계에 쓴 사고 ID {i}가 근거 사고(incidents)에 없음")
        for i in s.get("incidents") or []:
            if i in INC and not (set(INC[i].get("ent") or []) & rows_in_steps):
                warn(where, f"{i}의 매핑 세부위협이 단계에 하나도 없음")
        for c in s.get("chokepoints") or []:
            for k in RE_ENT.findall(str(c)):
                if k not in rows_in_steps:
                    warn(where, f"초크 포인트의 {k}가 단계에 없음")
    return n


def main():
    global ALLOW_MISSING_TEXT
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--data-only", action="store_true")
    ap.add_argument("--allow-missing-text", action="store_true")
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
          f"실제 사고 매핑 행 {real_rows}개 · 인용 사례 {cases}건")
    print(f"— 오류 {len(ERR)} · 경고 {len(WARN)}")
    if ERR or (a.strict and WARN):
        sys.exit(1)


if __name__ == "__main__":
    main()
