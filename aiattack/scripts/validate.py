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


def xm_field(k):
    return next((f for p, f in XM_FIELD.items() if k.startswith(p)), None)


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
        if e.get("ai_use") not in ("확인", "추정"):
            err(where, f"ai_use 값(확인·추정) 오류: {e.get('ai_use')}")
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
# 5) 문구·시나리오(②③단계) — 파일이 있을 때만
# ===========================================================================
def check_text_and_scenarios():
    text_files = sorted((DATA / "text").glob("*.yaml")) if (DATA / "text").exists() else []
    if text_files:
        for p in text_files:
            t = load(p, {}) or {}
            for rid in t:
                if rid not in ROWS:
                    err(f"text/{p.name}", f"없는 세부위협 ID {rid}")
    if SCENARIOS.get("scenarios"):
        for sc in SCENARIOS["scenarios"]:
            where = f"scenarios {sc.get('id')}"
            for step in sc.get("steps") or []:
                for k in step.get("aia") or []:
                    if k not in ROWS:
                        err(where, f"없는 세부위협 ID {k}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--data-only", action="store_true")
    a = ap.parse_args()

    check_frameworks()
    check_taxonomy()
    check_incidents()
    if not a.data_only:
        check_text_and_scenarios()

    ev = row_evidence()
    real_rows = sum(1 for k in ROWS if ev[k]["real"])
    print(f"세부위협 {len(ROWS)}개 · 사고 {len(INCIDENTS)}건 · 실제 사고가 매핑된 행 {real_rows}개")
    for m in ERR:
        print(m)
    for m in WARN:
        print(m)
    print(f"— 오류 {len(ERR)} · 경고 {len(WARN)}")
    if ERR or (a.strict and WARN):
        sys.exit(1)


if __name__ == "__main__":
    main()
