# -*- coding: utf-8 -*-
"""
MITRE ATT&CK Enterprise v19.2 → 공급망 매트릭스용 최소 추출본
--------------------------------------------------------------
data/taxonomy.yaml이 쓰는 기법의 정보(명칭·전술·URL)와 그 기법을 쓰는 주체(그룹·소프트웨어·캠페인)의
절차(mapping description)만 뽑아 reference/attack/enterprise-attack-v19.2-subset.json으로 저장한다.
원본 xlsx(약 5MB)를 폴더에 복제하지 않고도 빌드를 재현하기 위한 것.

실행 : python3 scripts/prepare_attack.py [--xlsx <enterprise-attack-v19.2.xlsx 경로>]
       기본 경로는 저장소 루트의 enterprise-attack-v19.2.xlsx
"""
import argparse
import json
import re
from pathlib import Path

import openpyxl
import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reference" / "attack" / "enterprise-attack-v19.2-subset.json"
TAXONOMY = ROOT / "data" / "taxonomy.yaml"
NOTICE = ("© The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation. "
          "Terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/")


def rows_of(ws):
    it = ws.iter_rows(values_only=True)
    hdr = next(it)
    for r in it:
        yield dict(zip(hdr, r))


def clean(text):
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https://attack\.mitre\.org/[^)]+\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xlsx", default=str(ROOT.parent / "enterprise-attack-v19.2.xlsx"))
    args = ap.parse_args()

    tax = yaml.safe_load(TAXONOMY.read_text(encoding="utf-8"))
    used = sorted({t for d in tax["domains"] for l2 in d["lv2"] for x in l2["lv3"] for t in x["attack"]})
    wb = openpyxl.load_workbook(args.xlsx, read_only=True)

    tech = {}
    for r in rows_of(wb["techniques"]):
        tech[r["ID"]] = dict(name=r["name"], tactics=r["tactics"], url=r["url"],
                             platforms=r["platforms"], parent=r["sub-technique of"] or "")
    missing = [t for t in used if t not in tech]
    if missing:
        raise SystemExit(f"ATT&CK v19.2에 없는 기법: {missing}")

    subjects = {}
    for sheet, kind in (("groups", "그룹"), ("software", "소프트웨어"), ("campaigns", "캠페인")):
        for r in rows_of(wb[sheet]):
            subjects[r["ID"]] = dict(name=r["name"], kind=kind, url=r["url"])

    procs = {t: [] for t in used}
    for r in rows_of(wb["relationships"]):
        if r["mapping type"] != "uses" or r["target ID"] not in procs:
            continue
        sid = r["source ID"]
        if sid not in subjects:
            continue
        procs[r["target ID"]].append(dict(subject=sid, text=clean(r["mapping description"])[:600]))

    out = dict(
        notice=NOTICE, source="MITRE ATT&CK Enterprise v19.2 (enterprise-attack-v19.2.xlsx)",
        techniques={t: tech[t] for t in used},
        subjects={s: subjects[s] for s in sorted({p["subject"] for v in procs.values() for p in v})},
        procedures={t: sorted(v, key=lambda p: p["subject"]) for t, v in procs.items()},
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"기법 {len(used)}개 · 주체 {len(out['subjects'])}개 · 절차 {sum(len(v) for v in procs.values())}건 → {OUT}")


if __name__ == "__main__":
    main()
