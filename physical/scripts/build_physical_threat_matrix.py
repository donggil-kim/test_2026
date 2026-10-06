# -*- coding: utf-8 -*-
"""물리·인적 매트릭스 빌드(최소 스텁).
현재: taxonomy 를 읽어 세부위협 목록 CSV 만 output/ 에 생성(동작 확인용).
TODO(새 세션): ../supplychain/scripts/build_supplychain_threat_matrix.py 를 참고해
      근거 집계(사고/프레임워크)·위험평가·우선순위·관점 문구·워크북(xlsx) 시트 구성을 이식.
      빌드 전 scripts/validate.py 를 자동 실행(오류 시 중단)하도록 확장.
실행: python3 scripts/build_physical_threat_matrix.py
"""
import csv, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import taxonomy_rules as R  # noqa: F401  (확장 시 사용)

TAX = yaml.safe_load((ROOT / "data/taxonomy.yaml").read_text(encoding="utf-8"))
rows = []
for dmn in TAX.get("domains", []):
    for l2 in dmn.get("lv2", []):
        for x in l2.get("lv3", []):
            rows.append([f"[{dmn['code']}] {dmn['ko']}", l2["id"], l2["name"], x["id"], x["name"],
                         x.get("en", ""), ", ".join(x.get("stage", [])), x.get("severity", "")])

out = ROOT / "output"
out.mkdir(exist_ok=True)
csv_path = out / "물리인적_보안위협_매트릭스_v0.csv"
with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.writer(f)
    w.writerow(["도메인", "위협분류 ID", "위협분류", "세부위협 ID", "세부위협", "영문명", "공격 단계", "심각도"])
    w.writerows(rows)
print(f"세부위협 {len(rows)}개 → {csv_path}")
print("NOTE: 최소 스텁입니다. ../supplychain/scripts/build_supplychain_threat_matrix.py 기준으로 확장하세요.")
