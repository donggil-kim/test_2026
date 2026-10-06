# -*- coding: utf-8 -*-
"""
물리·인적 매트릭스 참조 자료 추출 — NIST SP 800-53 통제명 · 다른 매트릭스 연계 ID
--------------------------------------------------------------------------
1) NIST SP 800-53 Rev.5 통제명 → reference/nist/sp800-53r5-names.json (통제 ID→영문 명칭, 공공 영역)
   --nist 로 OSCAL 카탈로그를 주면 새로 추출하고, 없으면 같은 저장소 identity/ 추출본(OSCAL 5.2.0)을 복사한다.
2) 다른 매트릭스 연계 ID → reference/links/other_matrices.json (ID→명칭·매트릭스·위험도)
   · 아이덴티티 매트릭스 v2 세부위협(IDT-)      identity/data/taxonomy.yaml + output CSV(위험도)
   · 공급망 매트릭스 v2 세부위협(SCT-)          supplychain/data/taxonomy.yaml + output CSV(위험도)
   · OT 매트릭스 v5 세부위협(OTC-)              ot/output/통합_OT보안위협_매트릭스_v5.xlsx '통합매트릭스_LITE'
   · 통합 AI·클라우드·OT 매트릭스 v2 요약 ID(AI-·CL-·OT-)  integrated/output/통합_요약매트릭스_v2.csv

실행 : python3 scripts/prepare_refs.py [--nist <NIST_SP-800-53_rev5_catalog.json>]
"""
import argparse
import collections
import csv
import json
import shutil
from pathlib import Path

import openpyxl
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
NIST_OUT = ROOT / "reference" / "nist" / "sp800-53r5-names.json"
NIST_IDENTITY = REPO / "identity" / "reference" / "nist" / "sp800-53r5-names.json"
LINK_OUT = ROOT / "reference" / "links" / "other_matrices.json"
SRC = {
    "identity": (REPO / "identity" / "data" / "taxonomy.yaml", REPO / "identity" / "output" / "통합_신원보안위협_매트릭스_v2.csv",
                 "IDT-ID", "아이덴티티 보안위협 v2"),
    "supplychain": (REPO / "supplychain" / "data" / "taxonomy.yaml",
                    REPO / "supplychain" / "output" / "통합_공급망보안위협_매트릭스_v2.csv", "SCT-ID", "공급망 보안위협 v2"),
}
OT_XLSX = REPO / "ot" / "output" / "통합_OT보안위협_매트릭스_v5.xlsx"
INTEGRATED = REPO / "integrated" / "output" / "통합_요약매트릭스_v2.csv"


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


def taxonomy_ids(tax_path, csv_path, id_col, matrix):
    risk = {}
    if csv_path.exists():
        with open(csv_path, encoding="utf-8-sig") as f:
            risk = {r[id_col]: r["위험도"] for r in csv.DictReader(f)}
    tax = yaml.safe_load(tax_path.read_text(encoding="utf-8"))
    out = {}
    for d in tax["domains"]:
        for l2 in d["lv2"]:
            for x in l2["lv3"]:
                out[x["id"]] = dict(name=x["name"], matrix=matrix, risk=risk.get(x["id"], ""))
    return out


def ot_ids():
    wb = openpyxl.load_workbook(OT_XLSX, read_only=True)
    rows = list(wb["통합매트릭스_LITE"].iter_rows(values_only=True))
    i = next(n for n, r in enumerate(rows) if r and "OTC-ID" in r)
    ci = {c: j for j, c in enumerate(rows[i])}
    out = {}
    for r in rows[i + 1:]:
        if r and r[ci["OTC-ID"]]:
            out[r[ci["OTC-ID"]]] = dict(name=r[ci["세부위협(Lv3)"]], matrix="OT 보안위협 v5", risk=r[ci["위험도"]] or "")
    return out


def links():
    ids = {}
    for key, (tax, out_csv, col, matrix) in SRC.items():
        ids.update(taxonomy_ids(tax, out_csv, col, matrix))
    ids.update(ot_ids())
    with open(INTEGRATED, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            ids[r["위협 ID"]] = dict(name=r["세부 위협(Lv3)"], matrix=f"통합 v2 {r['구분(Lv0)']}", risk=r.get("위험도", ""))
    doc = dict(source={"identity": "identity/data/taxonomy.yaml", "supplychain": "supplychain/data/taxonomy.yaml",
                       "ot": str(OT_XLSX.relative_to(REPO)), "integrated": str(INTEGRATED.relative_to(REPO))},
               note="아이덴티티 v2(IDT-)·공급망 v2(SCT-)·OT v5(OTC-) 세부위협 ID와 통합 AI·클라우드·OT 매트릭스 v2 요약 ID(AI-·CL-·OT-)",
               ids=dict(sorted(ids.items())))
    LINK_OUT.parent.mkdir(parents=True, exist_ok=True)
    LINK_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    by = collections.Counter(v["matrix"] for v in ids.values())
    print(f"연계 ID {len(ids)}개 {dict(by)} → {LINK_OUT}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--nist", help="NIST SP 800-53 Rev.5 OSCAL 카탈로그 JSON(없으면 identity/ 추출본 복사)")
    a = ap.parse_args()
    if a.nist:
        nist(a.nist)
    else:
        NIST_OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(NIST_IDENTITY, NIST_OUT)
        print(f"NIST SP 800-53 통제명 — {NIST_IDENTITY.relative_to(REPO)} 복사 → {NIST_OUT}")
    links()
