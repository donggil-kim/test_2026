# -*- coding: utf-8 -*-
"""
CISA KEV(알려진 악용 취약점) → 고도화 엔터프라이즈 침해 매트릭스용 최소 추출본
----------------------------------------------------------------------------
'KEV 악용·빠른 익스플로잇·엣지 0-day'(선정 신호·사고 근거)의 근거. 같은 저장소 KEV 사본(2026.10.02판 1,733건)을
읽어 CVE→벤더·제품·등재일·설명 색인과 요약 통계(연도별 등재·경계/엣지 장비 비중·같은 해 악용 비중)를 만든다.
  · reference/kev/kev-subset.json : CVE 색인(사고 DB가 인용한 CVE 검증용) + 요약 통계

실행 : python3 scripts/prepare_kev.py [--src <known_exploited_vulnerabilities.json>]
       기본 경로는 같은 저장소 supplychain/reference/advisories/ 사본
"""
import argparse
import collections
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
SRC = REPO / "supplychain" / "reference" / "advisories" / "known_exploited_vulnerabilities.json"
OUT = ROOT / "reference" / "kev" / "kev-subset.json"
NOTICE = "CISA Known Exploited Vulnerabilities Catalog (공공 영역) — CVE·벤더·제품·등재일만 인용"

# 경계·엣지 장비(VPN·방화벽·게이트웨이·파일전송 등) 판정 키워드(벤더·제품명 기준, 작업방향 7.2)
EDGE_RE = re.compile(
    r"VPN|firewall|gateway|Fortinet|FortiOS|FortiGate|Ivanti|Pulse|Citrix|NetScaler|Palo Alto|PAN-OS|GlobalProtect|"
    r"SonicWall|Zyxel|Cisco (?:ASA|IOS|Adaptive|Firepower)|Array Networks|Barracuda|MOVEit|GoAnywhere|Accellion|"
    r"Edge|appliance|router|NAS|load balancer|ADC|Secure (?:Gateway|Mobile)|Connect Secure|Policy Secure", re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=str(SRC))
    a = ap.parse_args()
    d = json.loads(Path(a.src).read_text(encoding="utf-8"))
    vulns = d["vulnerabilities"]
    index, by_year, edge_by_year, sameyear_by_year = {}, collections.Counter(), collections.Counter(), collections.Counter()
    for v in vulns:
        cve = v["cveID"]
        added = v.get("dateAdded", "")
        yr = added[:4]
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        name = v.get("vulnerabilityName", "")
        edge = bool(EDGE_RE.search(f"{vendor} {product} {name}"))
        index[cve] = dict(vendor=vendor, product=product, added=added, edge=edge)
        if yr:
            by_year[yr] += 1
            if edge:
                edge_by_year[yr] += 1
            m = re.match(r"CVE-(\d{4})-", cve)
            if m and m.group(1) == yr:
                sameyear_by_year[yr] += 1
    doc = dict(
        notice=NOTICE, source=f"CISA KEV {d.get('catalogVersion')} ({d.get('dateReleased','')[:10]})",
        count=len(index),
        by_year=dict(sorted(by_year.items())),
        edge_share={y: f"{round(100*edge_by_year[y]/by_year[y])}%" for y in sorted(by_year)},
        sameyear_share={y: f"{round(100*sameyear_by_year[y]/by_year[y])}%" for y in sorted(by_year)},
        edge_total=sum(edge_by_year.values()),
        index=index,
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"KEV {len(index)}건 · 연도별 {doc['by_year']} · 엣지 비중 {doc['edge_share']} → {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
