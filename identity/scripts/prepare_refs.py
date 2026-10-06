# -*- coding: utf-8 -*-
"""
신원 매트릭스 참조 자료 추출 — NIST SP 800-53 통제명 · 다른 매트릭스 연계 ID
------------------------------------------------------------------------
1) NIST SP 800-53 Rev.5 OSCAL 카탈로그 → reference/nist/sp800-53r5-names.json (통제 ID→영문 명칭, 공공 영역)
2) 통합 AI·클라우드·OT 매트릭스 v2 요약 ID(AI-·CL-·OT-)와 공급망 매트릭스 v2 세부위협 ID(SCT-)
   → reference/links/other_matrices.json (ID→명칭·위험도) — 연계 열·문구의 ID 검증용

실행 : curl -o /tmp/nist.json https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json
       python3 scripts/prepare_refs.py --nist /tmp/nist.json
       (--nist 생략 시 연계 ID만 갱신. 연계 ID 원천은 저장소의 integrated/·supplychain/ 폴더)
"""
import argparse
import csv
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
NIST_OUT = ROOT / "reference" / "nist" / "sp800-53r5-names.json"
LINK_OUT = ROOT / "reference" / "links" / "other_matrices.json"
INTEGRATED = REPO / "integrated" / "output" / "통합_요약매트릭스_v2.csv"
SUPPLY = REPO / "supplychain" / "data" / "taxonomy.yaml"
SUPPLY_CSV = REPO / "supplychain" / "output" / "통합_공급망보안위협_매트릭스_v2.csv"


def nist(path):
    cat = json.loads(Path(path).read_text(encoding="utf-8"))["catalog"]
    names = {}

    def walk(c):
        lab = [p["value"] for p in c.get("props", []) if p["name"] == "label" and p.get("class") != "zero-padded"]
        if lab:
            names[lab[0]] = c["title"]
        for s in c.get("controls", []):
            walk(s)

    for g in cat["groups"]:
        for c in g.get("controls", []):
            walk(c)
    doc = dict(source="NIST SP 800-53 Rev.5 OSCAL catalog (usnistgov/oscal-content)",
               version=cat["metadata"]["version"], last_modified=cat["metadata"].get("last-modified"),
               license="미국 정부 저작물(공공 영역)", names=names)
    NIST_OUT.parent.mkdir(parents=True, exist_ok=True)
    NIST_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"NIST SP 800-53 통제 {len(names)}개(v{doc['version']}) → {NIST_OUT}")


def links():
    ids = {}
    with open(INTEGRATED, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            ids[r["위협 ID"]] = dict(name=r["세부 위협(Lv3)"], matrix=r["구분(Lv0)"], risk=r.get("위험도", ""))
    risk = {}
    if SUPPLY_CSV.exists():
        with open(SUPPLY_CSV, encoding="utf-8-sig") as f:
            risk = {r["SCT-ID"]: r["위험도"] for r in csv.DictReader(f)}
    tax = yaml.safe_load(SUPPLY.read_text(encoding="utf-8"))
    for d in tax["domains"]:
        for l2 in d["lv2"]:
            for x in l2["lv3"]:
                ids[x["id"]] = dict(name=x["name"], matrix="공급망 보안위협", risk=risk.get(x["id"], ""))
    doc = dict(source={"integrated": str(INTEGRATED.relative_to(REPO)), "supplychain": str(SUPPLY.relative_to(REPO))},
               note="통합 AI·클라우드·OT 매트릭스 v2 요약 ID(AI-·CL-·OT-)와 공급망 매트릭스 v2 세부위협 ID(SCT-)",
               ids=dict(sorted(ids.items())))
    LINK_OUT.parent.mkdir(parents=True, exist_ok=True)
    LINK_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    by = {}
    for v in ids.values():
        by[v["matrix"]] = by.get(v["matrix"], 0) + 1
    print(f"연계 ID {len(ids)}개 {by} → {LINK_OUT}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--nist", help="NIST SP 800-53 Rev.5 OSCAL 카탈로그 JSON")
    a = ap.parse_args()
    if a.nist:
        nist(a.nist)
    links()
