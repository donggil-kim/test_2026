# -*- coding: utf-8 -*-
"""
MITRE CTID Insider Threat TTP Knowledge Base(ITKB) → 물리·인적 매트릭스용 추출본
---------------------------------------------------------------------------
참여 기관의 실제 내부자 사례에서 관측된 ATT&CK 기법 목록(기법·하위 기법과 전술 조합), 기법별 완화책(M-ID)·
데이터 소스(DS-ID), 관측 가능한 인적 지표(OHI) 목록만 뽑아 reference/itkb/insider-threat-ttp-kb.json으로 저장한다.
ITKB는 ATT&CK v14 기준이므로 저장소 루트의 ATT&CK v19.2 xlsx와 대조해 v19.2에 없는 ID는 후속 ID를 기록한다.
라이선스: Apache-2.0(원본 LICENSE.txt를 reference/itkb/LICENSE-Apache-2.0.txt로 함께 보관)

실행 : git clone https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb.git <폴더>
       python3 scripts/prepare_itkb.py --repo <폴더> [--xlsx <enterprise-attack-v19.2.xlsx>]
"""
import argparse
import csv
import json
import re
import shutil
import subprocess
from pathlib import Path

import openpyxl

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reference" / "itkb" / "insider-threat-ttp-kb.json"
LICENSE_OUT = ROOT / "reference" / "itkb" / "LICENSE-Apache-2.0.txt"
NOTICE = ("Insider Threat TTP Knowledge Base © 2024 MITRE Center for Threat-Informed Defense (Approved for public release, "
          "CT0041·CT0102). Licensed under the Apache License, Version 2.0. Uses MITRE ATT&CK® "
          "(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).")

# ATT&CK v14 → v19.2에서 구조가 바뀐 ID(방어 무력화 전술 신설로 Impair Defenses 계열 이동)
V14_TO_V19 = {
    "T1562": "T1685",        # Impair Defenses → Disable or Modify Tools(방어 무력화 전술로 분할)
    "T1562.001": "T1685",    # Impair Defenses: Disable or Modify Tools → Disable or Modify Tools
    "T1070.001": "T1685.005",  # Indicator Removal: Clear Windows Event Logs → Disable or Modify Tools: Clear Windows Event Logs
}
RST_LINK = re.compile(r"`(T\d{4}(?:\.\d{3})?) <[^>]+>`_")


def git_meta(repo):
    try:
        h, d = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%H %cs"], capture_output=True, text=True,
                              check=True).stdout.split()
        return h[:7], d
    except (subprocess.CalledProcessError, ValueError):
        return "", ""


def id_map(path):
    out = {}
    with open(path, encoding="utf-8-sig") as f:
        for r in csv.reader(f):
            m = RST_LINK.match(r[0]) if r else None
            if m:
                out[m.group(1)] = [v.strip() for v in (r[1] if len(r) > 1 else "").split(",") if v.strip()]
    return out


def ohi(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip()[2:].strip() for ln in lines if ln.strip().startswith("* ")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="insider-threat-ttp-kb 저장소 클론 경로")
    ap.add_argument("--xlsx", default=str(ROOT.parent / "enterprise-attack-v19.2.xlsx"))
    args = ap.parse_args()
    repo = Path(args.repo)

    wb = openpyxl.load_workbook(args.xlsx, read_only=True)
    it = wb["techniques"].iter_rows(values_only=True)
    hdr = next(it)
    v19 = {d["ID"]: d["name"] for d in (dict(zip(hdr, r)) for r in it)}

    rows = []
    with open(repo / "docs" / "insider-threat-ttp-kb.csv", encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            rows.append(dict(technique=r["Technique ID"], name=r["Technique Title"], tactic=r["Tactic ID"],
                             tactic_name=r["Tactic Title"]))
    mit = id_map(repo / "docs" / "extra" / "mitigations.csv")
    ds = id_map(repo / "docs" / "extra" / "datasources.csv")

    techniques = {}
    for r in rows:
        t = r["technique"]
        x = techniques.setdefault(t, dict(name=r["name"], tactics=[], mitigations=mit.get(t, []), datasources=ds.get(t, [])))
        x["tactics"].append(r["tactic_name"])
    for t, x in techniques.items():
        if t in v19:
            x["v19"] = t
            x["v19_name"] = v19[t]
        else:
            x["v19"] = V14_TO_V19.get(t, "")
            x["v19_name"] = v19.get(x["v19"], "")
            x["note"] = "ATT&CK v19.2에 없는 ID — 후속 ID 기록" if x["v19"] else "ATT&CK v19.2에 없는 ID — 후속 ID 미확인"
    commit, date = git_meta(repo)
    n_sub = sum(1 for t in techniques if "." in t)
    doc = dict(
        notice=NOTICE,
        source="https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb",
        version=f"v2(ATT&CK v14 기준) · 커밋 {commit}({date})",
        license="Apache-2.0",
        counts=dict(rows=len(rows), techniques=len(techniques), parent=len(techniques) - n_sub, sub=n_sub),
        techniques=dict(sorted(techniques.items())),
        ohi=ohi(repo / "docs" / "ohi.rst"),
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    shutil.copyfile(repo / "LICENSE.txt", LICENSE_OUT)
    moved = {t: x["v19"] for t, x in techniques.items() if x["v19"] != t}
    print(f"ITKB 기법 {len(techniques)}개(기법 {len(techniques) - n_sub} · 하위 {n_sub}) · 전술 조합 {len(rows)}행 · "
          f"OHI {len(doc['ohi'])}종 · v19.2 변경 {moved} → {OUT}")


if __name__ == "__main__":
    main()
