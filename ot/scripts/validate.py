# -*- coding: utf-8 -*-
"""OT 관점 문구(data/text/*.yaml) 검증 — AI 매트릭스 v3.2 validate를 OT용으로 확장

검사 항목
  · 형식: 요약설명 2줄 개조식, 참조의 '■ OT 관점'·'■ 실제 사례' 단락, 탐지·대응의 '■ 탐지'·'■ 대응' 단락
  · 참조 ID: OTC-ID·INC-ID·ATT&CK 캠페인/소프트웨어/그룹 ID가 실제로 존재하는지
  · 사례 라벨: '실제 사례' 줄의 라벨이 인용한 사고의 집계 상태와 일치하는지
      [실제 사고] ↔ 실제 사고 / [실증] ↔ 연구·시연 / [위협인텔] ↔ 위협인텔(능력 발견)
  · 근거 정합: '실제 사례'에 인용한 사고가 해당 기법에 매핑돼 있는지(문구와 근거 집계가 어긋나지 않게)
  · 절차 정합: '실제 사례'에 인용한 ATT&CK 캠페인·소프트웨어가 해당 기법(통합된 Enterprise 기법 포함)의 절차를 갖는지
실행: python3 scripts/validate.py  (문제가 있으면 종료 코드 1)
"""
import contextlib
import io
import re
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.argv = [sys.argv[0]]
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(str(HERE / "build_ot_threat_matrix.py"), run_name="validate")

rows, ev, incidents, TEXT, ics = g["rows"], g["ev"], g["incidents"], g["TEXT"], g["ics"]
ent, merged = g["ent"], g["merged_into"]
inc_by = {e["id"]: e for e in incidents}
keys = {o["key"] for o in rows}
codes = {o["code"] for o in rows}
otc_ids = {o["otc"] for o in rows}
LABEL_STATUS = {"실제 사고": "실제 사고", "실증": "실증·연구", "위협인텔": "위협인텔"}
LABELS = {"실제 사고", "위협인텔", "공개 취약점", "실증", "시나리오"}

problems, warnings = [], []


def bullets(block):
    return [ln for ln in block.split("\n") if ln.startswith("- ")]


def proc_subjects(key):
    """기법(통합된 Enterprise 기법·상위기법으로 모인 Enterprise 하위기법 포함)의 절차를 가진 ATT&CK 주체"""
    techs = {key, *merged.get(key, [])} | {t for t in ent.procs if t.split(".")[0] == key}
    return {s for t in techs for s, _ in ics.procs.get(t, []) + ent.procs.get(t, [])}


def split_sections(text, heads):
    out = {}
    pattern = "|".join(re.escape(h) for h in heads)
    parts = re.split(f"({pattern})", text)
    for i in range(1, len(parts) - 1, 2):
        out[parts[i]] = parts[i + 1].strip()
    return out


for tkey, t in TEXT.items():
    base, _, code = tkey.partition("@")
    if base not in keys or (code and code not in codes):
        problems.append((tkey, "매트릭스에 없는 키"))
        continue
    summary, ref, det = t.get("summary") or "", t.get("reference") or "", t.get("detect") or ""
    if len(bullets(summary)) != 2 or len(summary.strip().split("\n")) != 2:
        problems.append((tkey, "요약설명 2줄 개조식 아님"))
    sec = split_sections(ref, ["■ OT 관점", "■ 실제 사례"])
    if set(sec) != {"■ OT 관점", "■ 실제 사례"}:
        problems.append((tkey, "참조 단락 누락"))
        continue
    if not 2 <= len(bullets(sec["■ OT 관점"])) <= 5:
        problems.append((tkey, f"OT 관점 {len(bullets(sec['■ OT 관점']))}줄(2~5줄)"))
    cases = bullets(sec["■ 실제 사례"])
    if not 1 <= len(cases) <= 3:
        problems.append((tkey, f"실제 사례 {len(cases)}줄(1~3줄)"))
    dsec = split_sections(det, ["■ 탐지", "■ 대응"])
    if set(dsec) != {"■ 탐지", "■ 대응"} or not bullets(dsec.get("■ 탐지", "")) or not bullets(dsec.get("■ 대응", "")):
        problems.append((tkey, "탐지·대응 단락 누락"))

    text = summary + "\n" + ref + "\n" + det
    for x in set(re.findall(r"OTC-[A-Z0-9]{2}-\d{2}(?:\.\d)?", text)) - otc_ids:
        problems.append((tkey, "없는 OTC-ID", x))
    for x in set(re.findall(r"INC-\d{3}", text)) - set(inc_by):
        problems.append((tkey, "없는 사고 ID", x))
    for x in set(re.findall(r"ATT&CK ([CSG]\d{4})", text)) - set(ics.subjects):
        problems.append((tkey, "없는 ATT&CK 주체", x))

    for line in cases:
        m = re.match(r"- \[([^\]]+)\]", line)
        if not m:
            if not line.startswith("- 공개 사고 미확인"):
                problems.append((tkey, "사례 라벨 없음", line[:40]))
            continue
        label = m.group(1)
        if label not in LABELS:
            problems.append((tkey, "알 수 없는 라벨", label))
            continue
        for sid in set(re.findall(r"ATT&CK ([CSG]\d{4})", line)) - proc_subjects(base):
            problems.append((tkey, "인용한 ATT&CK 주체에 이 기법 절차 없음", sid))
        cited = re.findall(r"INC-\d{3}", line)
        if label in LABEL_STATUS and not cited:
            problems.append((tkey, f"[{label}] 줄에 사고 ID 없음", line[:40]))
        for i in cited:
            e = inc_by.get(i)
            if not e:
                continue
            if label in LABEL_STATUS and e["status"] != LABEL_STATUS[label]:
                problems.append((tkey, "라벨-유형 불일치", i, f"[{label}] vs {e['status']}"))
            mapped = base in e["links"] or (base.split(".")[0] in e["links"])
            if not mapped:
                problems.append((tkey, "사례가 해당 기법에 매핑되지 않음", i))
        if label == "실제 사고":
            n_real = len(ev[base]["real"])
            if not n_real:
                problems.append((tkey, "[실제 사고] 라벨이지만 집계된 실제 사고 0건"))

written = {k.partition("@")[0] for k in TEXT}
pending = sorted(keys - written)
print(f"OT 관점 문구 {len(written & keys)}/{len(keys)}개 작성", "· 미작성:", ", ".join(pending) if pending else "없음")
for p in problems:
    print("  !", *p)
sys.exit(1 if problems else 0)
