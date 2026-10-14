"""통합 요약 매트릭스 버전 간 위험 값 변화표 (검증 결정 F8) — v4 → v4.1.

사용: python3 integrated/scripts/compare_versions.py [이전 버전] [새 버전]   (기본 v4 v4.1)
출력: integrated/output/통합_위험값변화_<이전>_<새>.csv · .md
사고 정정(시점·사례 구분·중복 정리)과 신규 사고 추가로 실제 사고 수·최근 사고·근거 수준·발생가능성·위험도·우선순위가 바뀐 위협만 싣는다.
"""
import csv
import os
import sys

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output")
FIELDS = ["실제 사고 수", "최근 사고(2025~)", "근거 수준", "발생가능성", "심각도", "위험도", "우선순위"]
KEY_FIELDS = ["근거 수준", "발생가능성", "위험도", "우선순위"]  # 이 값이 바뀌면 '평가 변동'


def load(ver):
    with open(os.path.join(OUT_DIR, f"통합_요약매트릭스_{ver}.csv"), encoding="utf-8-sig") as f:
        return {r["위협 ID"]: r for r in csv.DictReader(f)}


def main():
    old_v, new_v = (sys.argv[1:3] + ["v4", "v4.1"][len(sys.argv[1:3]):])[:2]
    old, new = load(old_v), load(new_v)
    rows = []
    for tid in list(new) + [t for t in old if t not in new]:
        a, b = old.get(tid), new.get(tid)
        if not a or not b:
            rows.append({"위협 ID": tid, "구분(Lv0)": (a or b)["구분(Lv0)"], "세부 위협(Lv3)": (a or b)["세부 위협(Lv3)"],
                         "변동": "삭제" if not b else "신설", **{f"{k}({old_v})": (a or {}).get(k, "") for k in FIELDS},
                         **{f"{k}({new_v})": (b or {}).get(k, "") for k in FIELDS}})
            continue
        changed = [k for k in FIELDS if a[k] != b[k]]
        if not changed:
            continue
        rows.append({"위협 ID": tid, "구분(Lv0)": b["구분(Lv0)"], "세부 위협(Lv3)": b["세부 위협(Lv3)"],
                     "변동": "평가 변동" if any(k in changed for k in KEY_FIELDS) else "근거 수만 변동",
                     **{f"{k}({old_v})": a[k] for k in FIELDS}, **{f"{k}({new_v})": b[k] for k in FIELDS}})
    cols = ["위협 ID", "구분(Lv0)", "세부 위협(Lv3)", "변동"] + [f"{k}({v})" for k in FIELDS for v in (old_v, new_v)]
    base = os.path.join(OUT_DIR, f"통합_위험값변화_{old_v}_{new_v}")
    with open(base + ".csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    ev = [r for r in rows if r["변동"] != "근거 수만 변동"]
    md = [f"# 통합 요약 매트릭스 위험 값 변화 {old_v} → {new_v}", "",
          f"요약 위협 {len(new)}개 중 값이 바뀐 위협 {len(rows)}개 — 평가 변동(근거 수준·발생가능성·위험도·우선순위) {len(ev)}개, "
          f"근거 수만 변동(실제 사고 수·최근 사고) {len(rows) - len(ev)}개. 원인: 사고사례 검증 정정(시점 → 최초 공개월, 사례 구분 재분류, "
          "같은 DB 중복 정리)과 신규 사고(W2) 추가.", ""]
    if ev:
        md += ["## 평가 변동", "", "| 위협 ID | 세부 위협 | 근거 수준 | 발생가능성 | 위험도 | 우선순위 | 실제 사고 수 |", "|---|---|---|---|---|---|---|"]
        for r in ev:
            def d(k):
                x, y = r[f"{k}({old_v})"], r[f"{k}({new_v})"]
                return f"{x} → **{y}**" if x != y else y
            md.append(f"| {r['위협 ID']} | {r['세부 위협(Lv3)']} | {d('근거 수준')} | {d('발생가능성')} | {d('위험도')} | "
                      f"{d('우선순위')} | {d('실제 사고 수')} |")
        md.append("")
    md += ["## 근거 수만 변동", "", "| 위협 ID | 실제 사고 수 | 최근 사고(2025~) |", "|---|---|---|"]
    for r in rows:
        if r["변동"] == "근거 수만 변동":
            md.append(f"| {r['위협 ID']} | {r[f'실제 사고 수({old_v})']} → {r[f'실제 사고 수({new_v})']} | "
                      f"{r[f'최근 사고(2025~)({old_v})']} → {r[f'최근 사고(2025~)({new_v})']} |")
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print(f"변화 {len(rows)}개(평가 변동 {len(ev)}) → {base}.csv · .md")


if __name__ == "__main__":
    main()
