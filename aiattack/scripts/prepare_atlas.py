# -*- coding: utf-8 -*-
"""
MITRE ATLAS 2026.09 → AI 활용 공격 매트릭스용 최소 추출본
--------------------------------------------------------
data/taxonomy.yaml이 쓰는 ATLAS 기법(명칭·전술·성숙도·ATT&CK 대응)과 전체 기법·전술·사례의 ID→명칭 색인만 뽑아
reference/atlas/atlas-2026.09-subset.json으로 저장한다(공급망·물리 매트릭스의 prepare_attack.py와 같은 구성).
  · techniques : taxonomy.yaml atlas 필드에 쓰인 기법만(명칭·전술·maturity·attack 대응)
  · index      : 전체 기법·사례(AML.CSxxxx) ID→명칭 — 사고 DB·문구의 ATLAS ID 검증(scripts/validate.py)에 씀
  · maturity   : ATLAS 2026.09 성숙도(Realized·Demonstrated·Feasible) — 발생가능성의 'AI 역량 성숙도' 신호(D4)
원본(reference/atlas/ATLAS-2026.09.yaml, MITRE ATLAS 공개 배포본)을 그대로 복제하지 않고 빌드를 재현하기 위한 것.

실행 : python3 scripts/prepare_atlas.py [--src <ATLAS yaml 경로>]
       기본 경로는 reference/atlas/ATLAS-2026.09.yaml (최신 갱신은 MITRE atlas-data dist/v6/ATLAS-latest.yaml)
"""
import argparse
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "reference" / "atlas" / "ATLAS-2026.09.yaml"
OUT = ROOT / "reference" / "atlas" / "atlas-2026.09-subset.json"
TAXONOMY = ROOT / "data" / "taxonomy.yaml"
NOTICE = ("© The MITRE Corporation. ATLAS® is a trademark of The MITRE Corporation. "
          "MITRE ATLAS 공개 배포본(https://github.com/mitre-atlas/atlas-data) — ID·명칭만 인용")


def clean(text):
    text = re.sub(r"\[([^\]]+)\]\((https?://)[^)]+\)", r"\1", text or "")
    return re.sub(r"\s+", " ", text).strip()


def attack_ref(t):
    a = t.get("attack-reference")
    if isinstance(a, dict):
        return a.get("id") or ""
    return a or ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    args = ap.parse_args()

    d = yaml.safe_load(Path(args.src).read_text(encoding="utf-8"))
    version = d["collection"]["version"]
    tactics = {tid: t["name"] for tid, t in d["tactics"].items()}
    techniques = d["techniques"]
    cases = d.get("case-studies") or {}

    tax = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8")) if TAXONOMY.exists() else {"domains": []}
    used = sorted({a for dm in tax["domains"] for l2 in dm["lv2"] for x in l2["lv3"] for a in (x.get("atlas") or [])})
    missing = [a for a in used if a not in techniques]
    if missing:
        raise SystemExit(f"ATLAS {version}에 없는 기법: {missing}")

    def tac_names(t):
        # 기법이 걸리는 전술 — relationships의 'subtechnique-of'/tactic 정보 대신 상위 전술은 기법 설명에 없어
        # 간단히 attack-reference 유무와 maturity만 싣고, 전술 매핑은 사례(case-study) 쪽 step의 tactic에서 본다
        return None

    tech_out = {t: dict(name=techniques[t]["name"], maturity=techniques[t].get("maturity"),
                        attack=attack_ref(techniques[t]),
                        parent=(t.rsplit(".", 1)[0] if re.search(r"\.\d{3}$", t) else ""))
                for t in used}

    index = {tid: v["name"] for tid, v in sorted(techniques.items())}
    index.update({cid: c["name"] for cid, c in sorted(cases.items())})

    out = dict(
        notice=NOTICE,
        source=f"MITRE ATLAS {version} (reference/atlas/ATLAS-2026.09.yaml)",
        version=version,
        tactics=tactics,
        techniques=tech_out,
        case_studies={cid: dict(name=c["name"], type=c.get("type"), date=str(c.get("date", "")))
                      for cid, c in sorted(cases.items())},
        index=index,
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"ATLAS {version} — 전술 {len(tactics)} · 기법(사용) {len(tech_out)} · 사례 {len(cases)} · "
          f"ID 색인 {len(index)} → {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
