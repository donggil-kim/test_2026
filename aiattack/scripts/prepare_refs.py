# -*- coding: utf-8 -*-
"""
AI 활용 공격 매트릭스 참조 자료 추출 — NIST SP 800-53 통제명 · 다른 매트릭스 연계 ID
-----------------------------------------------------------------------------
1) NIST SP 800-53 Rev.5 통제명 → reference/nist/sp800-53r5-names.json (통제 ID→영문 명칭, 공공 영역)
   --nist 로 OSCAL 카탈로그를 주면 새로 추출하고, 없으면 같은 저장소 identity/ 추출본(OSCAL 5.2.0)을 복사한다.
2) 다른 매트릭스 연계 ID → reference/links/other_matrices.json (ID→명칭·Lv0·위험도)
   AI 활용 공격은 '렌즈 매트릭스'라 기존 6개 매트릭스와 대량 겹친다(작업방향 5장). 겹침은 재수록이 아니라
   통합 v4.1 요약 ID로 연계만 한다 → 통합 v4.1 요약 매트릭스의 237개 Lv0 ID(AI-·CL-·OT-·SC-·ID-·PH-)를 그대로 읽는다.
   integrated/output/통합_요약매트릭스_v4.1.csv

실행 : python3 scripts/prepare_refs.py [--nist <NIST_SP-800-53_rev5_catalog.json>]
"""
import argparse
import collections
import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
NIST_OUT = ROOT / "reference" / "nist" / "sp800-53r5-names.json"
NIST_IDENTITY = REPO / "identity" / "reference" / "nist" / "sp800-53r5-names.json"
LINK_OUT = ROOT / "reference" / "links" / "other_matrices.json"
INTEGRATED = REPO / "integrated" / "output" / "통합_요약매트릭스_v4.1.csv"


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
    print(f"NIST SP 800-53 통제 {len(names)}개(v{doc['version']}) → {NIST_OUT.relative_to(ROOT)}")


def links():
    ids = {}
    with open(INTEGRATED, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            ids[r["위협 ID"]] = dict(name=r["세부 위협(Lv3)"], matrix=f"통합 v4.1 {r['구분(Lv0)']}",
                                    risk=r.get("위험도", ""))
    doc = dict(source={"integrated": str(INTEGRATED.relative_to(REPO))},
               note="통합 v4.1 요약 매트릭스의 Lv0 요약 ID(AI-·CL-·OT-·SC-·ID-·PH-) — 겹치는 위협은 재수록 대신 이 ID로 연계(작업방향 5장)",
               ids=dict(sorted(ids.items())))
    LINK_OUT.parent.mkdir(parents=True, exist_ok=True)
    LINK_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    by = collections.Counter(v["matrix"] for v in ids.values())
    print(f"연계 ID {len(ids)}개 {dict(by)} → {LINK_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--nist", help="NIST SP 800-53 Rev.5 OSCAL 카탈로그 JSON(없으면 identity/ 추출본 복사)")
    a = ap.parse_args()
    if a.nist:
        nist(a.nist)
    else:
        NIST_OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(NIST_IDENTITY, NIST_OUT)
        print(f"NIST SP 800-53 통제명 — {NIST_IDENTITY.relative_to(REPO)} 복사 → {NIST_OUT.relative_to(ROOT)}")
    links()
