# -*- coding: utf-8 -*-
"""
Browser & Identity Attacks Matrix(Push Security, 구 SaaS Attacks Matrix) → 신원 매트릭스용 최소 추출본
---------------------------------------------------------------------------------------------
기법별 ID(SAT10NN)·명칭·전술·요약 첫 문장·예시 이름·참고 링크·ATT&CK 링크만 뽑아
reference/push-bia/techniques.json으로 저장한다. 예시 파일의 화면 캡처(제3자 앱)는 옮기지 않는다.

  원본 : https://github.com/pushsecurity/saas-attacks (CC BY 4.0)
  사용 : 세부위협의 'SAT-ID' 교차 매핑·분류 누락 점검·실증 근거(사고 수에 넣지 않음)

실행 : git clone https://github.com/pushsecurity/saas-attacks.git /tmp/bia
       python3 scripts/prepare_push.py --repo /tmp/bia
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "reference" / "push-bia" / "techniques.json"
NOTICE = ("Browser & Identity Attacks Matrix (formerly SaaS Attacks Matrix) © Push Security and contributors, "
          "licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). "
          "이 파일은 원본에서 ID·명칭·전술·요약 첫 문장·링크만 추출한 것이며 내용을 변경하지 않았다.")


def section(md, title):
    m = re.search(rf"^## {title}\s*\n(.*?)(?=^## |\Z)", md, re.S | re.M)
    return m.group(1).strip() if m else ""


def links(block):
    return [dict(title=t.strip(), url=u.strip()) for t, u in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", block)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="pushsecurity/saas-attacks 로컬 클론 경로")
    args = ap.parse_args()
    repo = Path(args.repo)
    commit = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%H %cs"], capture_output=True,
                            text=True).stdout.split()
    out = {}
    for d in sorted((repo / "techniques").iterdir()):
        f = d / "description.md"
        if not f.exists():
            continue
        md = f.read_text(encoding="utf-8")
        name = re.search(r"^# (.+)$", md, re.M).group(1).strip()
        mid = re.search(r"^ID:\s*(SAT\d{4})", md, re.M)
        if not mid:
            raise SystemExit(f"ID 없음: {d.name}")
        tactics = [t.strip("* ").strip() for t in section(md, "Tactics").splitlines() if t.strip().startswith("*")]
        summ = " ".join(section(md, "Summary").split())
        first = re.split(r"(?<=[.!?])\s", summ, maxsplit=1)[0] if summ else ""
        exs = links(section(md, "Examples"))
        refs = links(section(md, "References"))
        atk = sorted({re.sub(r"/(\d{3})", r".\1", m).strip("/") for m in
                      re.findall(r"attack\.mitre\.org/techniques/(T\d{4}(?:/\d{3})?)", md)})
        out[mid.group(1)] = dict(
            name=name, slug=d.name, tactics=tactics, summary_first=first,
            examples=[e["title"] for e in exs],
            n_examples=len(exs), n_refs=len(refs),
            references=[r for r in refs if "attack.mitre.org" not in r["url"]][:8],
            attack=atk,
            url=f"https://github.com/pushsecurity/saas-attacks/blob/main/techniques/{d.name}/description.md")
    doc = dict(notice=NOTICE, source="https://github.com/pushsecurity/saas-attacks",
               commit=commit[0] if commit else "", commit_date=commit[1] if len(commit) > 1 else "",
               techniques=dict(sorted(out.items())))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
    lic = repo / "LICENSE"
    if lic.exists():
        (OUT.parent / "LICENSE-CC-BY-4.0.txt").write_text(lic.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"기법 {len(out)}개(예시 {sum(v['n_examples'] for v in out.values())}건 · ATT&CK 링크 보유 "
          f"{sum(1 for v in out.values() if v['attack'])}개) · 커밋 {doc['commit'][:7]} → {OUT}")


if __name__ == "__main__":
    main()
