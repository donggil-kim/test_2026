# -*- coding: utf-8 -*-
"""
통합 신원(아이덴티티)·계정 보안위협 매트릭스 — 데이터·문구 검증기
---------------------------------------------------------------
빌드 입력(data/·scripts/taxonomy_rules.py)의 정합성과 신원 관점 문구(data/text/*.yaml)의 작성 규칙을 점검한다
(공급망 매트릭스 scripts/validate.py와 같은 구성).

  · 원천 데이터 : ID 형식·중복, 사고 DB 필드·어휘, 사고↔세부위협·KEV·ATT&CK 참조, 분류 체계의 교차 매핑·대응 기준 ID
  · 문구 형식   : oneline 50자 이내, summary 2줄, reference(■ 신원 관점 / ■ 실제 사례)·detect(■ 탐지 / ■ 대응) 구성
  · 사례 대조   : 인용한 사고 ID가 그 행에 매핑됐는지, 라벨([실제 사고]·[실증]·[위협인텔])이 집계 상태와 맞는지,
                  사례명 뒤 (YYYY-MM)이 사고 DB 시점과 같은지, CVE가 행의 KEV 판정이나 인용 사고에 있는지,
                  [시연] 줄의 SAT-ID가 행 매핑에 있는지, 설명 속 수치가 인용 사고의 요약에 있는지(경고)
  · 참조 ID     : IDT·ATT&CK·SAT·NHI·CCM·CIS·NIST·ISMS-P·다른 매트릭스 ID 존재와 행 매핑 일치,
                  사례 줄의 ATT&CK ID는 인용 사고의 attack_ref에, 신원 관점의 ATT&CK ID는 행 기법·절차 주체에 있는지
  · 근거 수준   : '실제 사고 확인' 행은 [실제 사고] 사례를 하나 이상 인용, 사례가 없으면 '공개 사고 미확인 — 사유'
  · 용어        : 인증정보·크리덴셜 대신 자격증명
  · 시나리오    : data/scenarios.yaml의 단계별 IDT·사고 ID

실행 : python3 scripts/validate.py [--strict] [--allow-missing-text]
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
INCIDENTS = load(DATA / "incidents.yaml", [])
SCENARIOS = load(DATA / "scenarios.yaml", {}) or {}
ATK = json.loads((REF / "attack" / "enterprise-attack-v19.2-subset.json").read_text(encoding="utf-8"))
ATK_INDEX = ATK["index"]
KEV = {v["cveID"]: v for v in json.loads((REF / "advisories" / "known_exploited_vulnerabilities.json")
                                          .read_text(encoding="utf-8"))["vulnerabilities"]}
SAT = json.loads((REF / "push-bia" / "techniques.json").read_text(encoding="utf-8"))["techniques"]
NIST = json.loads((REF / "nist" / "sp800-53r5-names.json").read_text(encoding="utf-8"))["names"]
LINKS = json.loads((REF / "links" / "other_matrices.json").read_text(encoding="utf-8"))["ids"]

ROWS, LV2 = {}, set()
for d in TAX["domains"]:
    for l2 in d["lv2"]:
        LV2.add(l2["id"])
        for x in l2["lv3"]:
            if x["id"] in ROWS:
                err("taxonomy.yaml", f"세부위협 ID 중복 {x['id']}")
            ROWS[x["id"]] = dict(x, code=d["code"])
IDT_IDS = set(ROWS) | LV2

RE_IDT = re.compile(r"IDT-[A-Z]{2}-\d{2}(?:\.\d)?")
RE_IDI = re.compile(r"IDI-\d{3}")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
RE_ATK = re.compile(r"(?<![A-Za-z0-9-])(T\d{4}(?:\.\d{3})?|[GSC]\d{4})(?![A-Za-z0-9])")
RE_XM = re.compile(r"(?<![A-Za-z0-9-])(CL-[A-Z]{2}-\d{2}|AI-\d{2}-\d{2}|OT-[A-Z]{2}-\d{2}|SCT-[A-Z]{2}-\d{2}(?:\.\d)?)(?![A-Za-z0-9.])")
RE_SAT = re.compile(r"SAT\d{4}")
RE_NHI = re.compile(r"(?<![A-Za-z0-9])(NHI\d{1,2})(?![0-9])")
RE_CCM = re.compile(r"(?<![A-Za-z0-9-])((?:IAM|HRS|CEK|LOG|STA)-\d{2})(?![0-9])")
RE_CIS = re.compile(r"CIS (\d+\.\d+(?:·\d+\.\d+)*)")
RE_ISMS = re.compile(r"ISMS-P (\d\.\d+\.\d+(?:·\d\.\d+\.\d+)*)")
RE_NIST = re.compile(r"NIST (?:SP 800-53 )?((?:[A-Z]{2}-\d+(?:\(\d+\))?)(?:·[A-Z]{2}-\d+(?:\(\d+\))?)*)")
RE_DATE = re.compile(r"\((\d{4}-\d{2})\):")
RE_NUM = re.compile(r"\d+(?:[.,]\d+)*")
RE_KEVN = re.compile(r"KEV[^\n]*?(?:등재|판정) (\d+)건")

CASE_LABELS = {"[실제 사고]": "실제 사고", "[실증]": "실증·연구", "[위협인텔]": "위협인텔", "[공개 취약점]": None,
               "[시연]": None, "[시나리오]": None}
CASE_NOTES = ("공개 사고 미확인", "참고:")
BANNED = {"인증정보": "자격증명", "인증 정보": "자격증명", "크리덴셜": "자격증명", "자격 증명": "자격증명"}
BANNED_OK = ("크리덴셜 스터핑",)   # 업계 고유명사(OWASP OAT-008 국문 통칭)는 허용

# ===========================================================================
# 1) 원천 데이터
# ===========================================================================
CATS = {"nhi": "owasp_nhi", "sp80063": "sp80063", "asvs": "asvs", "oat": "oat", "ccm": "ccm", "cis": "cis", "ismsp": "ismsp"}


def check_taxonomy():
    for rid, x in ROWS.items():
        where = f"taxonomy.yaml {rid}"
        for f in ("name", "en", "stage", "id_types", "id_envs", "attack", "severity", "severity_why"):
            if not x.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for t in x["attack"]:
            if t not in ATK["techniques"]:
                err(where, f"ATT&CK 추출본에 없는 기법 {t} — scripts/prepare_attack.py 재실행 필요")
        for fld, cat in CATS.items():
            keys = {str(k) for k in FW[cat]}
            for k in x.get(fld) or []:
                if str(k) not in keys:
                    err(where, f"{fld} 카탈로그(frameworks.yaml {cat})에 없는 ID {k}")
        for k in x.get("sat") or []:
            if k not in SAT:
                err(where, f"Browser & Identity Attacks Matrix에 없는 ID {k}")
        for k in x.get("nist") or []:
            if k not in NIST:
                err(where, f"NIST SP 800-53 Rev.5에 없는 통제 {k}")
        for fld in ("cloud", "ai", "ot", "sct"):
            for k in x.get(fld) or []:
                if k not in LINKS:
                    err(where, f"다른 매트릭스에 없는 연계 ID {k}({fld})")
        if x.get("severity") not in ("상", "중", "하"):
            err(where, f"심각도 값 오류 {x.get('severity')}")
        for p in x.get("id_types") or []:
            if p not in R.ID_TYPES:
                err(where, f"정의되지 않은 신원 유형 {p}")
        for p in x.get("id_envs") or []:
            if p not in R.ID_ENVS:
                err(where, f"정의되지 않은 ID 환경 {p}")
        tac = set(FW["attack_tactics_ko"].values())
        for s in x.get("stage") or []:
            if s not in tac:
                err(where, f"ATT&CK 전술 국문명이 아닌 공격 단계 {s}")
    for (c, k) in R.FRAMEWORK_NOT_MAPPED:
        cat = CATS.get(c)
        if not cat or str(k) not in {str(v) for v in FW[cat]}:
            err("taxonomy_rules.FRAMEWORK_NOT_MAPPED", f"{c} 카탈로그에 없는 ID {k}")
        elif any(str(k) in [str(v) for v in x.get(c) or []] for x in ROWS.values()):
            warn("taxonomy_rules.FRAMEWORK_NOT_MAPPED", f"{c} {k}는 이미 세부위협에 매핑됨 — 미연계 사유 삭제")


def check_kev():
    for cve, (cat, rows, note) in R.KEV_IDENTITY.items():
        if cve not in KEV:
            err("taxonomy_rules.KEV_IDENTITY", f"KEV 카탈로그에 없는 CVE {cve}")
        if cat not in R.KEV_CATEGORIES:
            err("taxonomy_rules.KEV_IDENTITY", f"{cve} 구분 '{cat}'이 KEV_CATEGORIES에 없음")
        for r in rows:
            if r not in ROWS:
                err("taxonomy_rules.KEV_IDENTITY", f"{cve} 매핑 세부위협 {r} 없음")
        for i in RE_IDI.findall(note):
            if i not in INC:
                err("taxonomy_rules.KEV_IDENTITY", f"{cve} 비고의 사고 ID {i} 없음")
            elif cve not in (INC[i].get("kev") or []):
                warn("taxonomy_rules.KEV_IDENTITY", f"{cve} 비고가 {i}를 가리키지만 사고 DB의 kev에 없음")


INC = {}


def check_incidents():
    kinds = set(R.KINDS)
    for n, e in enumerate(INCIDENTS):
        i = e.get("id", f"#{n}")
        where = f"incidents.yaml {i}"
        if not re.fullmatch(r"IDI-\d{3}", str(i)):
            err(where, "ID 형식(IDI-NNN) 오류")
        if i in INC:
            err(where, "ID 중복")
        INC[i] = e
        for f in ("title", "date", "kind", "verification", "id_env", "id_type", "impact", "summary", "idt", "sources"):
            if not e.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        e["date"] = str(e.get("date", ""))
        if not re.fullmatch(r"\d{4}-\d{2}", e["date"]):
            err(where, f"시점 형식(YYYY-MM) 오류: {e['date']}")
        if e.get("kind") not in kinds:
            err(where, f"사례유형 '{e.get('kind')}'이 정의된 어휘에 없음")
        if e.get("verification") not in R.VERIFICATIONS:
            err(where, f"검증 수준 '{e.get('verification')}'이 정의된 어휘에 없음")
        for v in e.get("id_env") or []:
            if v not in R.ID_ENVS:
                err(where, f"ID 환경 '{v}'가 정의된 어휘에 없음")
        for v in e.get("id_type") or []:
            if v not in R.ID_TYPES:
                err(where, f"신원 유형 '{v}'가 정의된 어휘에 없음")
        for imp in e.get("impact") or []:
            if imp not in R.IMPACTS:
                err(where, f"영향 '{imp}'이 정의된 어휘에 없음")
        for k in e.get("idt") or []:
            if k not in ROWS:
                err(where, f"매핑 세부위협 {k} 없음")
        if len(set(e.get("idt") or [])) != len(e.get("idt") or []):
            err(where, "매핑 세부위협 중복")
        for c in e.get("kev") or []:
            if c not in KEV:
                err(where, f"KEV 카탈로그에 없는 CVE {c}")
        for a in e.get("attack_ref") or []:
            if a not in ATK_INDEX:
                err(where, f"ATT&CK v19.2에 없는 ID {a}")
        for o in e.get("origin") or []:
            if not re.fullmatch(r"(SCI-\d{3}|INC-\d{4})", str(o)):
                err(where, f"origin 형식(SCI-NNN·INC-NNNN) 오류: {o}")
        for s in e.get("sources") or []:
            if not re.fullmatch(r".+ \| https?://\S+", s):
                err(where, f"출처 형식('출처 | URL') 오류: {s[:60]}")
        e["status"] = R.incident_status(e) if e.get("kind") else "?"


# ===========================================================================
# 2) 행별 근거(빌드 스크립트와 같은 규칙)
# ===========================================================================
def row_evidence():
    ev = {k: dict(real=set(), research=set(), intel=set(), kev=set()) for k in ROWS}
    for e in INCIDENTS:
        key = {"실제 사고": "real", "실증·연구": "research", "위협인텔": "intel"}.get(e["status"])
        for k in e.get("idt") or []:
            if key and k in ev:
                ev[k][key].add(e["id"])
    for cve, (cat, rows, note) in R.KEV_IDENTITY.items():
        for k in rows:
            if k in ev:
                ev[k]["kev"].add(cve)
    return ev


# ===========================================================================
# 3) 신원 관점 문구
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


def check_refs(where, rid, text):
    """문구 전체에 쓰인 참조 ID의 존재·행 매핑 일치"""
    x = ROWS[rid]
    for s in RE_IDT.findall(text):
        if s not in IDT_IDS:
            err(where, f"없는 세부위협 ID {s}")
    for a in RE_ATK.findall(text):
        if a not in ATK_INDEX:
            err(where, f"ATT&CK v19.2에 없는 ID {a}")
    links = set(x.get("cloud") or []) | set(x.get("ai") or []) | set(x.get("ot") or []) | set(x.get("sct") or [])
    for m in RE_XM.findall(text):
        if m not in LINKS:
            err(where, f"다른 매트릭스에 없는 ID {m}")
        elif m not in links:
            err(where, f"다른 매트릭스 ID {m}가 이 행의 연계(cloud·ai·ot·sct)에 없음")
    for k in RE_SAT.findall(text):
        if k not in SAT:
            err(where, f"Browser & Identity Attacks Matrix에 없는 ID {k}")
        elif k not in (x.get("sat") or []):
            warn(where, f"SAT {k}가 이 행의 매핑에 없음")
    for k in RE_NHI.findall(text):
        if k not in FW["owasp_nhi"]:
            err(where, f"OWASP NHI Top 10에 없는 ID {k}")
        elif k not in (x.get("nhi") or []):
            warn(where, f"NHI {k}가 이 행의 매핑에 없음")
    for k in RE_CCM.findall(text):
        if k not in FW["ccm"]:
            err(where, f"CSA CCM 카탈로그에 없는 통제 {k}")
        elif k not in (x.get("ccm") or []):
            warn(where, f"CCM {k}가 이 행의 대응 기준 매핑에 없음")
    cis = {str(c) for c in FW["cis"]}
    for grp in RE_CIS.findall(text):
        for k in grp.split("·"):
            if k not in cis:
                err(where, f"CIS Controls 카탈로그에 없는 세이프가드 {k}")
            elif k not in [str(v) for v in x.get("cis") or []]:
                warn(where, f"CIS {k}가 이 행의 대응 기준 매핑에 없음")
    isms = {str(c) for c in FW["ismsp"]}
    for grp in RE_ISMS.findall(text):
        for k in grp.split("·"):
            if k not in isms:
                err(where, f"ISMS-P 카탈로그에 없는 항목 {k}")
            elif k not in [str(v) for v in x.get("ismsp") or []]:
                warn(where, f"ISMS-P {k}가 이 행의 대응 기준 매핑에 없음")
    for grp in RE_NIST.findall(text):
        for k in grp.split("·"):
            if k not in NIST:
                err(where, f"NIST SP 800-53에 없는 통제 {k}")
            elif k not in (x.get("nist") or []):
                warn(where, f"NIST {k}가 이 행의 대응 기준 매핑에 없음")
    t2 = text
    for ok in BANNED_OK:
        t2 = t2.replace(ok, "")
    for bad, good in BANNED.items():
        if bad in t2:
            err(where, f"용어 '{bad}' → '{good}'")


def check_case_line(where, rid, ln, ev, stats):
    body = ln[2:].strip()
    if body.startswith(CASE_NOTES):
        stats["note"] += 1
        return None
    m = re.match(r"(\[[^\]]+\])\s*(.+)$", body)
    if not m or m.group(1) not in CASE_LABELS:
        err(where, "실제 사례 줄은 [실제 사고]·[실증]·[위협인텔]·[공개 취약점]·[시연]·[시나리오] 또는 '공개 사고 미확인'·'참고:'로 시작: "
                   f"{body[:40]}")
        return None
    label, rest = m.group(1), m.group(2)
    stats[label] += 1
    ids = RE_IDI.findall(rest)
    cves = RE_CVE.findall(rest)
    cited = [INC[i] for i in ids if i in INC]
    for i in ids:
        if i not in INC:
            err(where, f"사고 DB에 없는 사례 ID {i}")
            continue
        e = INC[i]
        if rid not in e["idt"]:
            err(where, f"{i}는 이 행에 매핑되지 않은 사고(매핑: {', '.join(e['idt'])})")
        want = CASE_LABELS[label]
        if want and e["status"] != want:
            err(where, f"{i} 라벨 {label}이 집계 상태 '{e['status']}'와 다름")
        if label in ("[공개 취약점]", "[시연]", "[시나리오]"):
            err(where, f"{label} 줄에 사고 ID {i} 인용 — 사고면 [실제 사고]/[실증]/[위협인텔] 라벨 사용")
    refs = set().union(*[set(e.get("attack_ref") or []) for e in cited]) if cited else set()
    for a in RE_ATK.findall(rest):
        if cited and a not in refs:
            err(where, f"ATT&CK {a}가 인용 사고({', '.join(ids)})의 attack_ref에 없음 — 사고 DB와 맞출 것")
    if label in ("[실제 사고]", "[실증]", "[위협인텔]"):
        if not ids:
            err(where, f"{label} 줄에 사고 ID(IDI-NNN) 없음: {rest[:40]}")
        md = RE_DATE.search(rest)
        if not md:
            err(where, f"사례명 뒤 '(YYYY-MM):' 시점 표기 없음: {rest[:40]}")
        else:
            for e in cited:
                if e["date"] != md.group(1):
                    err(where, f"{e['id']} 시점 불일치(문구 {md.group(1)}, 사고 DB {e['date']})")
        desc = rest.split(":", 1)[1] if ":" in rest else rest
        desc = re.sub(r"\((?:IDI|CVE|ATT&CK)[^)]*\)\s*$", "", desc)
        desc = RE_CVE.sub("", desc)
        corpus = " ".join(e["title"] + " " + " ".join(e["summary"].split()) for e in cited)
        for num in RE_NUM.findall(desc):
            if len(num.replace(",", "").replace(".", "")) < 2:
                continue
            if num not in corpus and num.replace(",", "") not in corpus.replace(",", ""):
                warn(where, f"수치 '{num}'이 인용 사고({', '.join(ids)})의 제목·요약에 없음 — 출처 확인")
    if label == "[시연]":
        sats = RE_SAT.findall(rest)
        if not sats:
            err(where, f"[시연] 줄에 SAT-ID 없음: {rest[:40]}")
        for s in sats:
            if s not in (ROWS[rid].get("sat") or []):
                err(where, f"[시연] {s}가 이 행의 SAT 매핑에 없음")
    if label == "[공개 취약점]":
        if not cves:
            err(where, f"[공개 취약점] 줄에 CVE 없음: {rest[:40]}")
        mk = RE_KEVN.search(rest)
        if mk and int(mk.group(1)) != len(ev["kev"]):
            warn(where, f"'KEV 판정 {mk.group(1)}건' 표기가 이 행의 KEV 판정 {len(ev['kev'])}건과 다름")
    for c in cves:
        ok = c in ev["kev"] or any(c in (e.get("kev") or []) or c in e["title"] or c in e["summary"] for e in cited)
        if not ok:
            err(where, f"{c}가 이 행의 KEV 판정이나 인용 사고에 없음")
        if label == "[공개 취약점]" and c not in KEV:
            err(where, f"{c}는 KEV 카탈로그에 없음")
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
            if not rid.startswith(f"IDT-{f.stem}-"):
                warn(where, f"도메인 파일({f.name})과 ID 도메인이 다름")
            for k in ("oneline", "summary", "reference", "detect"):
                if not (t or {}).get(k):
                    err(where, f"'{k}' 없음")
            t = t or {}
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
            if list(ref) != ["신원 관점", "실제 사례"]:
                err(where, f"reference 구성은 ■ 신원 관점 → ■ 실제 사례(현재: {list(ref)})")
            for sec, lines in ref.items():
                for ln in lines:
                    if not ln.startswith("- "):
                        err(where, f"reference '{sec}' 줄은 '- '로 시작: {ln[:30]}")
            labels = collections.Counter()
            for ln in ref.get("실제 사례", []):
                if ln.startswith("- "):
                    labels[check_case_line(where, rid, ln, ev[rid], stats)] += 1
            if len(ref.get("신원 관점", [])) < 2:
                warn(where, "■ 신원 관점 항목이 2개 미만")
            row_subj = {p["subject"] for tq in ROWS[rid]["attack"] for p in ATK["procedures"].get(tq, [])}
            for ln in ref.get("신원 관점", []):
                for a in RE_ATK.findall(ln):
                    if a.startswith("T") and a not in ROWS[rid]["attack"]:
                        warn(where, f"신원 관점의 기법 {a}가 이 행의 ATT&CK 매핑에 없음")
                    elif not a.startswith("T") and a not in row_subj:
                        warn(where, f"신원 관점의 {a}가 이 행 기법들의 ATT&CK 절차 주체가 아님")
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
# 4) 공격 체인 시나리오
# ===========================================================================
def check_scenarios():
    n = 0
    for s in SCENARIOS.get("scenarios", []):
        where = f"scenarios.yaml {s.get('id')}"
        n += 1
        for f in ("id", "title", "incidents", "summary", "steps", "chokepoints"):
            if not s.get(f):
                err(where, f"필수 필드 '{f}' 없음")
        for i in s.get("incidents") or []:
            if i not in INC:
                err(where, f"사고 DB에 없는 사례 ID {i}")
        rows_in_steps = set()
        for j, st in enumerate(s.get("steps") or [], 1):
            for k in st.get("idt") or []:
                if k not in ROWS:
                    err(f"{where} 단계 {j}", f"없는 세부위협 ID {k}")
                rows_in_steps.add(k)
            for f in ("idt", "단계", "행위", "탐지"):
                if not st.get(f):
                    err(f"{where} 단계 {j}", f"필드 '{f}' 없음")
            if st.get("단계") and st["단계"] not in set(FW["attack_tactics_ko"].values()):
                err(f"{where} 단계 {j}", f"ATT&CK 전술 국문명이 아닌 단계 {st['단계']}")
            for a in RE_ATK.findall(" ".join(str(v) for v in st.values())):
                if a not in ATK_INDEX:
                    err(f"{where} 단계 {j}", f"ATT&CK v19.2에 없는 ID {a}")
        for a in RE_ATK.findall(str(s.get("ref") or "")):
            if a not in ATK_INDEX:
                err(where, f"ATT&CK v19.2에 없는 ID {a}")
        for c in RE_CVE.findall(str(s.get("ref") or "")):
            if c not in KEV:
                err(where, f"KEV 카탈로그에 없는 CVE {c}")
        for i in s.get("incidents") or []:
            if i in INC and not (set(INC[i]["idt"]) & rows_in_steps):
                warn(where, f"{i}의 매핑 세부위협이 시나리오 단계에 하나도 없음")
        for c in s.get("chokepoints") or []:
            for k in RE_IDT.findall(str(c)):
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
    check_incidents()
    check_taxonomy()
    check_kev()
    ev = row_evidence()
    n_text, stats = (0, collections.Counter()) if args.data_only else check_texts(ev)
    n_scn = check_scenarios()
    for m in ERR + WARN:
        print(m)
    cases = sum(v for k, v in stats.items() if k != "note")
    print(f"\n검증 대상: 세부위협 {len(ROWS)}개(문구 {n_text}개) · 사고 {len(INCIDENTS)}건 · KEV 판정 {len(R.KEV_IDENTITY)}건 · "
          f"시나리오 {n_scn}개 · 인용 사례 {cases}건(" + " · ".join(f"{k} {v}" for k, v in stats.items() if k != "note") + ")")
    print(f"검증 결과: 오류 {len(ERR)}건 · 경고 {len(WARN)}건")
    sys.exit(1 if ERR or (args.strict and WARN) else 0)


if __name__ == "__main__":
    main()
