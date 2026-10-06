# -*- coding: utf-8 -*-
"""MITRE EMB3D STIX 2.1 → data/emb3d.yaml (빌드용 최소 추출본)

EMB3D 원본(STIX)은 라이선스상 사본마다 저작권 표시·라이선스 문구를 붙여야 하므로 저장소에 두지 않고,
위협·완화책의 ID·명칭·분류·성숙도·연계 ID만 추출한다(설명문·근거 문헌 본문은 싣지 않음).

원본 받기: git clone --depth 1 https://github.com/mitre/emb3d.git  →  assets/emb3d-stix-2.0.1.json
실행    : python3 scripts/prepare_emb3d.py --stix <경로>/emb3d-stix-2.0.1.json
"""
import argparse
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "emb3d.yaml"

NOTICE = """\
# MITRE EMB3D™ 최소 추출본 — scripts/prepare_emb3d.py로 생성(직접 수정하지 말 것)
#
# ©2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
#
# LICENSE (EMB3D Terms of Use, https://emb3d.mitre.org/subtabs/terms-of-use.html)
# The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use, copy, and create
# derivative works of EMB3D™ for internal business purposes or commercial use. Any copy you make for such purposes is
# authorized provided that you reproduce MITRE's copyright designation and this license in any such copy and provide
# MITRE notice of such use at EMB3D@mitre.org. For all other uses of EMB3D™, contact MITRE at techtransfer@mitre.org.
# All rights not expressly granted are hereby reserved.
#
"""

MATURITY = {"observed adversarial technique": "관찰", "observed adversarial behavior": "관찰",
            "known exploitable weakness": "알려진 취약점", "proof of concept": "개념 증명"}


def iec_ids(text):
    """'- EDR / HDR / NDR 3.14 – Integrity of the boot process' → [('EDR/HDR/NDR 3.14', 'Integrity of the boot process')]"""
    out = []
    for ln in text.split("\n"):
        ln = ln.strip().lstrip("-").strip()
        if not ln or ln.lower() == "none":
            continue
        ln = re.sub(r"^CR\s*[–-]\s*(\d+\.\d+)\s+", r"CR \1 – ", ln)          # 'CR – 3.5 Input Validation' 표기 정리
        m = re.match(r"((?:CR|SAR|EDR|HDR|NDR)(?:\s*/\s*(?:CR|SAR|EDR|HDR|NDR))*)\s+(\d+\.\d+)\s*[–-]\s*(.+)", ln)
        if not m:
            continue
        kinds = re.sub(r"\s*/\s*", "/", m.group(1))
        title, re_part = m.group(3).strip(), ""
        r = re.search(r":\s*RE\s*\((\d+)\)\s*(.*)$", title)
        if r:
            re_part, title = f" RE({r.group(1)})", title[:r.start()].strip()
        out.append([f"{kinds} {m.group(2)}{re_part}", title])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", required=True, help="emb3d-stix-2.x.json 경로")
    a = ap.parse_args()
    src = Path(a.stix)
    objs = json.loads(src.read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}
    mids_of = {}
    for r in objs:
        if r["type"] == "relationship" and r["relationship_type"] == "mitigates":
            mids_of.setdefault(r["target_ref"], []).append(by_id[r["source_ref"]]["x_mitre_emb3d_mitigation_id"])
    threats = []
    for o in sorted((o for o in objs if o["type"] == "vulnerability"), key=lambda o: o["x_mitre_emb3d_threat_id"]):
        ev = o["x_mitre_emb3d_threat_evidence"]
        threats.append(dict(
            id=o["x_mitre_emb3d_threat_id"], name=o["name"], category=o["x_mitre_emb3d_threat_category"],
            maturity=MATURITY[o["x_mitre_emb3d_threat_maturity"].strip().lower()],
            cwes=sorted(set(re.findall(r"CWE-\d+", o["x_mitre_emb3d_threat_CWEs"])), key=lambda c: int(c[4:])),
            cves=sorted(set(re.findall(r"CVE-\d{4}-\d+", o["x_mitre_emb3d_threat_CVEs"] + ev))),
            atk_cited=sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", ev))),
            mids=sorted(set(mids_of.get(o["id"], []))),
        ))
    mitigations = []
    for o in sorted((o for o in objs if o["type"] == "course-of-action"), key=lambda o: o["x_mitre_emb3d_mitigation_id"]):
        mitigations.append(dict(id=o["x_mitre_emb3d_mitigation_id"], name=o["name"],
                                maturity=o["x_mitre_emb3d_mitigation_maturity"],
                                iec62443_4_2=iec_ids(o["x_mitre_emb3d_mitigation_IEC_62443_mappings"])))
    data = dict(source=dict(file=src.name, repo="https://github.com/mitre/emb3d", site="https://emb3d.mitre.org/"),
                threats=threats, mitigations=mitigations)
    OUT.write_text(NOTICE + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)} — 위협 {len(threats)}개 · 완화책 {len(mitigations)}개")


if __name__ == "__main__":
    main()
