# -*- coding: utf-8 -*-
"""
LOLBAS · LOLDrivers → 고도화 엔터프라이즈 침해 매트릭스용 최소 추출본
-------------------------------------------------------------------
'서명된 정상 도구·취약 드라이버 악용'(레거시 공백 유형) 교차 열의 근거.
원문(LOLBAS 245개·LOLDrivers 706개)을 그대로 복제하지 않고 ID·명칭·분류·ATT&CK 매핑만 추출한다.
  · reference/lolbas/lolbas-subset.json     : LOLBin 이름·명령 분류(Execute·AWL Bypass·Dump 등)·URL
  · reference/lolbas/loldrivers-subset.json : 취약/악성 드라이버 분류·ATT&CK ID·대표 샘플명(요약 통계 포함)

원문 출처(공개): LOLBAS https://lolbas-project.github.io/api/lolbas.json (MIT),
               LOLDrivers https://www.loldrivers.io/api/drivers.json (MIT)
실행 : python3 scripts/prepare_lolbas.py [--lolbas <lolbas.json>] [--loldrivers <drivers.json>]
       (기본 경로는 세션 스크래치패드 dl/ — 없으면 위 URL에서 내려받아 지정)
"""
import argparse
import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DL = Path("/tmp/claude-0/-home-user-test-2026/549f135b-62f4-51ef-9cd4-9fb6de7f6d60/scratchpad/dl")
LOLBAS_OUT = ROOT / "reference" / "lolbas" / "lolbas-subset.json"
LOLDRV_OUT = ROOT / "reference" / "lolbas" / "loldrivers-subset.json"
NOTICE = "LOLBAS·LOLDrivers (© 각 프로젝트 기여자, MIT) — ID·명칭·분류·ATT&CK 매핑만 인용"


def lolbas(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    entries, catc = {}, collections.Counter()
    for e in d:
        cats = sorted({c.get("Category") for c in (e.get("Commands") or []) if c.get("Category")})
        catc.update(cats)
        entries[e["Name"]] = dict(categories=cats, url=e.get("url", ""))
    doc = dict(notice=NOTICE, source="LOLBAS (lolbas-project.github.io)", count=len(entries),
               category_counts=dict(catc.most_common()), entries=dict(sorted(entries.items())))
    LOLBAS_OUT.parent.mkdir(parents=True, exist_ok=True)
    LOLBAS_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"LOLBAS {len(entries)}개(명령 분류 {len(catc)}종) → {LOLBAS_OUT.relative_to(ROOT)}")


def loldrivers(path):
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    catc, mitrec, by = collections.Counter(), collections.Counter(), {}
    for e in d:
        cat = e.get("Category") or ""
        catc.update([cat])
        mids = e.get("MitreID")
        mids = [mids] if isinstance(mids, str) else (mids or [])
        mitrec.update(mids)
        samples = [s for s in (e.get("Tags") or []) if isinstance(s, str)][:2]
        by[e["Id"]] = dict(category=cat, mitre=mids, samples=samples)
    doc = dict(notice=NOTICE, source="LOLDrivers (loldrivers.io)", count=len(by),
               category_counts=dict(catc), mitre_counts=dict(mitrec.most_common()),
               note="Category: vulnerable driver(취약 드라이버 BYOVD) / malicious(악성 드라이버). MitreID는 ATT&CK 기법")
    LOLDRV_OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"LOLDrivers {len(by)}개(분류 {dict(catc)}) → {LOLDRV_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--lolbas", default=str(DL / "lolbas.json"))
    ap.add_argument("--loldrivers", default=str(DL / "loldrivers.json"))
    a = ap.parse_args()
    lolbas(a.lolbas)
    loldrivers(a.loldrivers)
