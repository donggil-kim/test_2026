# -*- coding: utf-8 -*-
"""키워드 사고 매핑 점검 (v4) — 분석 매핑 누락 후보를 사람이 검토하도록 보고

scripts/taxonomy_rules.py의 KEYWORD_RULES로, 사고 제목·요약에 키워드가 있는데 그 기법이
해당 사고에 매핑(직접 ics/ent · 상위기법 · ATT&CK 공식 절차)돼 있지 않으면 후보로 출력한다.
자동 집계·발생가능성에는 전혀 영향을 주지 않는 '검토 보조' 도구다.

실행: python3 scripts/check_keyword_mapping.py
"""
import contextlib
import io
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.argv = [sys.argv[0]]
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(str(HERE / "build_ot_threat_matrix.py"), run_name="keyword-check")

incidents, R, name_ko = g["incidents"], g["R"], g["name_ko"]
ics, ent, norm = g["ics"], g["ent"], g["norm"]


def mapped_keys(e):
    """사고에 이미 매핑된 행 키 — 직접(ics/ent) + ATT&CK 공식 절차 + 각 상위기법."""
    keys = set(e.get("links") or {})
    for ref in e.get("attack_ref") or []:
        rid = ref.partition("@")[0]
        for t in ics.subject_uses.get(rid, []) + ent.subject_uses.get(rid, []):
            k = norm(t)
            if k:
                keys.add(k)
    return keys | {k.split(".")[0] for k in keys}


candidates = []
for e in incidents:
    text = (e.get("title", "") + " " + e.get("summary", "")).lower()
    mk = mapped_keys(e)
    for key, words in R.KEYWORD_RULES.items():
        if key in mk or key.split(".")[0] in mk:
            continue
        hit = [w for w in words if w.lower() in text]
        if hit:
            candidates.append((e["id"], e.get("status", ""), key, name_ko(key), hit))

print(f"키워드 매핑 점검 — 후보 {len(candidates)}건 (검토용, 자동 집계 아님)\n")
cur = None
for inc_id, status, key, nm, hit in sorted(candidates):
    if inc_id != cur:
        cur = inc_id
        e = next(x for x in incidents if x["id"] == inc_id)
        print(f"● {inc_id} [{status}] {e['title']}")
    print(f"    + {key} {nm}  ← {', '.join(hit)}")
print("\n검토 후: 맞으면 data/incidents.yaml의 ics/ent에 추가, 아니면 무시(오탐 — 규칙은 보수적으로 유지)")
