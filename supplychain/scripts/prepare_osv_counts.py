# -*- coding: utf-8 -*-
"""
OpenSSF Malicious Packages(OSV 형식) → 생태계·연도별 악성 패키지 보고 건수
--------------------------------------------------------------------------
ossf/malicious-packages 저장소의 파일 경로만 세므로 본문(blob)을 내려받을 필요가 없다.
  git clone --depth 1 --filter=blob:none --no-checkout https://github.com/ossf/malicious-packages.git
연도는 보고 ID(MAL-YYYY-NNNN)의 연도 — 패키지가 게시된 연도와 다를 수 있음.

실행 : python3 scripts/prepare_osv_counts.py --repo <malicious-packages 클론 경로>
출력 : data/osv_malicious_counts.csv (머리말에 원본 커밋·기준일)
"""
import argparse
import collections
import csv
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "osv_malicious_counts.csv"
PAT = re.compile(r"^osv/(malicious|withdrawn)/([^/]+)/.*?MAL-(\d{4})-\d+\.json$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    args = ap.parse_args()
    git = ["git", "-C", args.repo, "-c", "core.quotepath=off"]
    head = subprocess.run(git + ["log", "-1", "--format=%H %cs"], capture_output=True, text=True, check=True).stdout.split()
    paths = subprocess.run(git + ["ls-tree", "-r", "--name-only", "HEAD", "osv/"],
                           capture_output=True, text=True, check=True).stdout.splitlines()
    mal, wd = collections.Counter(), collections.Counter()
    for p in paths:
        m = PAT.match(p)
        if not m:
            continue
        kind, eco, year = m.groups()
        (mal if kind == "malicious" else wd)[(eco, year)] += 1
    years = sorted({y for _, y in mal})
    ecos = sorted({e for e, _ in mal}, key=lambda e: -sum(v for (x, _), v in mal.items() if x == e))
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        f.write(f"# OpenSSF Malicious Packages {head[0][:12]} ({head[1]}) — 보고 ID 연도 기준, withdrawn 제외\n")
        w = csv.writer(f)
        w.writerow(["생태계"] + years + ["합계", "철회(withdrawn)"])
        for e in ecos:
            row = [mal[(e, y)] for y in years]
            w.writerow([e] + row + [sum(row), sum(v for (x, _), v in wd.items() if x == e)])
    print(f"악성 보고 {sum(mal.values())}건 · 생태계 {len(ecos)}개 → {OUT}")


if __name__ == "__main__":
    main()
