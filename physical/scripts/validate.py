# -*- coding: utf-8 -*-
"""물리·인적 매트릭스 검증기(최소 스텁).
현재: taxonomy/incidents 의 ID 형식·중복·필수 필드·매핑 존재·어휘·출처 형식만 점검.
TODO(새 세션): ../supplychain/scripts/validate.py 를 참고해 문구 형식·사례 라벨↔집계 상태·
      시점(YYYY-MM)·금지 용어(인증정보·크리덴셜)·프레임워크 ID 존재/행 매핑 일치·시나리오 검증을 이식.
실행: python3 scripts/validate.py   (오류가 있으면 종료 코드 1)
"""
import re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import taxonomy_rules as R

ERR = []
def err(where, msg): ERR.append(f"[오류] {where}: {msg}")

def load(p, d=None):
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else d

TAX = load(ROOT / "data/taxonomy.yaml", {})
INC = load(ROOT / "data/incidents.yaml", []) or []

ROWS = {}
for dmn in TAX.get("domains", []):
    for l2 in dmn.get("lv2", []):
        for x in l2.get("lv3", []):
            if x["id"] in ROWS:
                err("taxonomy.yaml", f"세부위협 ID 중복 {x['id']}")
            ROWS[x["id"]] = x
            if x.get("severity") not in ("상", "중", "하"):
                err(f"taxonomy.yaml {x['id']}", f"severity 값 오류 {x.get('severity')}")

for e in INC:
    i = e.get("id", "?")
    where = f"incidents.yaml {i}"
    if not re.fullmatch(r"PHI-\d{3}", str(i)):
        err(where, "ID 형식(PHI-NNN) 오류")
    for f in ("title", "date", "kind", "verification", "summary", "pht", "sources"):
        if not e.get(f):
            err(where, f"필수 필드 '{f}' 없음")
    if e.get("kind") and e["kind"] not in R.KINDS:
        err(where, f"kind 어휘 아님: {e.get('kind')}")
    if e.get("date") and not re.fullmatch(r"\d{4}-\d{2}", str(e["date"])):
        err(where, f"date 형식(YYYY-MM) 오류: {e.get('date')}")
    for k in e.get("pht", []) or []:
        if k not in ROWS:
            err(where, f"매핑 세부위협 {k} 없음")

for m in ERR:
    print(m)
print(f"\n검증: 세부위협 {len(ROWS)}개 · 사고 {len(INC)}건 | 오류 {len(ERR)}건")
print("NOTE: 최소 스텁입니다. ../supplychain/scripts/validate.py 기준으로 문구·사례·프레임워크 검증을 이식하세요.")
sys.exit(1 if ERR else 0)
