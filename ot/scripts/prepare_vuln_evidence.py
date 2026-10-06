# -*- coding: utf-8 -*-
"""CISA ICS 권고(CSAF 2.0) + KEV → 취약점 근거 표 (data/ics_advisory_cves.csv)

입력
  --csaf DIR : cisagov/CSAF 저장소의 csaf_files/OT/white (연도별 *.json)
               예) git clone --depth 1 --filter=blob:none --no-checkout https://github.com/cisagov/CSAF
                   git sparse-checkout init --no-cone
                   echo '/csaf_files/OT/white/*/*.json' > .git/info/sparse-checkout && git checkout develop
  reference/advisories/known_exploited_vulnerabilities.json (cisagov/kev-data)
출력
  data/ics_advisory_cves.csv : 권고-CVE 단위 1행 (권고 ID·공개일·벤더·제품·업종·CVE·CWE·CVSS·KEV 여부)

원문 CSAF는 용량(약 100MB)이 커서 저장소에 넣지 않고, 이 스크립트로 만든 추출본만 둔다.
"""
import argparse
import csv
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEV = ROOT / "reference/advisories/known_exploited_vulnerabilities.json"
OUT = ROOT / "data/ics_advisory_cves.csv"

COLS = ["권고 ID", "공개일", "권고명", "벤더", "제품", "업종", "CVE", "CWE", "CWE명",
        "CVSS v3", "CVSS v4", "공격 경로(AV)", "사용자 상호작용(UI)",
        "KEV", "KEV 벤더", "KEV 제품", "KEV 등재일", "KEV 랜섬웨어 사용"]


def release_date(doc):
    """ICSA-YY-DDD-NN의 연도·일차에서 CISA 공개일 산출(벤더 CSAF 재게시본은 initial_release_date가 벤더 날짜)."""
    m = re.match(r"ICSA-(\d{2})-(\d{3})-", doc["tracking"]["id"])
    if m:
        import datetime
        y, d = 2000 + int(m.group(1)), int(m.group(2))
        try:
            return (datetime.date(y, 1, 1) + datetime.timedelta(days=d - 1)).isoformat()
        except ValueError:
            pass
    return (doc["tracking"].get("initial_release_date") or "")[:10]


def vendors_products(tree):
    vendors, products = [], []
    for b in tree.get("branches", []):
        if b.get("category") == "vendor":
            vendors.append(b.get("name", "").strip())
            for c in b.get("branches", []):
                if c.get("category") in ("product_family", "product_name"):
                    products.append(c.get("name", "").strip())
    return sorted(set(v for v in vendors if v)), sorted(set(p for p in products if p))


def note(doc, title):
    for n in doc.get("notes", []):
        if (n.get("title") or "").strip().lower() == title:
            return (n.get("text") or "").strip()
    return ""


def score(v, key):
    best = None
    for s in v.get("scores", []):
        x = (s.get(key) or {}).get("baseScore")
        if x is not None:
            best = x if best is None else max(best, x)
    return best


AV_CODE = {"N": "NETWORK", "A": "ADJACENT_NETWORK", "L": "LOCAL", "P": "PHYSICAL"}
UI_CODE = {"N": "NONE", "R": "REQUIRED", "P": "PASSIVE", "A": "ACTIVE"}


def vector(v):
    """CVSS v3(없으면 v4)의 공격 경로·사용자 상호작용 — 필드가 없으면 vectorString에서 파싱."""
    for key in ("cvss_v3", "cvss_v4"):
        for sc in v.get("scores", []):
            c = sc.get(key) or {}
            av, ui = c.get("attackVector"), c.get("userInteraction")
            vs = c.get("vectorString") or ""
            if not av:
                m = re.search(r"/AV:([NALP])", vs)
                av = AV_CODE.get(m.group(1)) if m else None
            if not ui:
                m = re.search(r"/UI:([NRPA])", vs)
                ui = UI_CODE.get(m.group(1)) if m else None
            if av:
                return av, ui or ""
    return "", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csaf", required=True, help="csaf_files/OT/white 경로")
    a = ap.parse_args()

    kev = {v["cveID"]: v for v in json.loads(KEV.read_text(encoding="utf-8"))["vulnerabilities"]}
    rows, seen = [], set()
    files = sorted(Path(a.csaf).glob("*/*.json"))
    for f in files:
        d = json.loads(f.read_text(encoding="utf-8"))
        doc = d["document"]
        adv = doc["tracking"]["id"].strip().upper()
        vend, prod = vendors_products(d.get("product_tree", {}))
        sectors = note(doc, "critical infrastructure sectors")
        for v in d.get("vulnerabilities", []):
            cve = (v.get("cve") or "").strip().upper()
            key = (adv, cve or v.get("title", ""))
            if key in seen:
                continue
            seen.add(key)
            cwe = v.get("cwe") or {}
            k = kev.get(cve)
            av, ui = vector(v)
            rows.append({
                "권고 ID": adv, "공개일": release_date(doc), "권고명": doc.get("title", "").strip(),
                "벤더": "; ".join(vend), "제품": "; ".join(prod[:8]), "업종": sectors,
                "CVE": cve, "CWE": (cwe.get("id") or "").strip(), "CWE명": (cwe.get("name") or "").strip(),
                "CVSS v3": score(v, "cvss_v3"), "CVSS v4": score(v, "cvss_v4"),
                "공격 경로(AV)": av, "사용자 상호작용(UI)": ui,
                "KEV": "Y" if k else "", "KEV 벤더": k["vendorProject"] if k else "",
                "KEV 제품": k["product"] if k else "", "KEV 등재일": k["dateAdded"] if k else "",
                "KEV 랜섬웨어 사용": (k.get("knownRansomwareCampaignUse") if k else "") or "",
            })
    rows.sort(key=lambda r: (r["공개일"], r["권고 ID"], r["CVE"]))
    OUT.parent.mkdir(exist_ok=True)
    with open(OUT, "w", encoding="utf-8-sig", newline="") as fp:
        w = csv.DictWriter(fp, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    advs = {r["권고 ID"] for r in rows}
    cves = {r["CVE"] for r in rows if r["CVE"]}
    kevs = {r["CVE"] for r in rows if r["KEV"]}
    print(f"권고 {len(advs)}건 · CVE {len(cves)}개 · KEV 교차 {len(kevs)}개 → {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
