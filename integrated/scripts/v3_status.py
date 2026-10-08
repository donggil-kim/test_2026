"""통합 보안위협 매트릭스 v3 — 공급망·신원·물리 재구성안 진행 점검·문안 골격 생성.

재구성안(integrated/docs/v3_재구성안.yaml)과 작성된 문안(integrated/data/<kind>/*.yaml)을 대조한다.

사용
  python3 integrated/scripts/v3_status.py                       # 진행 현황·재구성안 정합성·위험 재산정 미리보기
  python3 integrated/scripts/v3_status.py --cases identity SE    # 미작성 항목의 대표 사례 후보(구성 원본 참조 줄)와 이미 쓴 사고 표시
  python3 integrated/scripts/v3_status.py --skeleton identity SE # 문안 골격 파일 생성(파일이 없을 때만) — 이후 빈 필드를 채움
"""
import argparse
import collections
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

PLAN = os.path.join(common.ROOT, "integrated", "docs", "v3_재구성안.yaml")


def load_plan():
    """재구성안 → {kind: {도메인: {'status': …, 'items': [항목]}}} (공급망은 status만)."""
    return yaml.safe_load(open(PLAN, encoding="utf-8"))


def plan_items(plan, kind):
    out = []
    for dom, block in (plan.get(kind) or {}).items():
        if isinstance(block, dict) and block.get("items"):
            for it in block["items"]:
                out.append(dict(it, domain=dom, status=block.get("status")))
    return out


def used_incidents(kind, src, entries):
    """작성된 문안의 대표 사례가 가리키는 사고 ID → 항목 ID."""
    used = {}
    for e in entries:
        refs = "\n".join(common.source_refs(kind, src, m) for m in e.get("members") or [] if m in src["tech"])
        for _, incs in common.case_incidents(e.get("cases"), refs):
            for i in incs:
                used.setdefault(i, e["id"])
    return used


def planned_case_incidents(kind, src, it):
    """재구성안 cases('사례명(시점)') → 사고 ID 목록."""
    refs = common.normalize_terms("\n".join(src["tech"][m]["row"]["참조"] or "" for m in it["members"]))
    out = []
    for key in it.get("cases") or []:
        line = next((l for l in refs.split("\n") if key in l), "")
        out.append((key, common.INCIDENT_RE.findall(line), bool(line)))
    return out


def report(plan, src, summ):
    errs = 0
    for kind in common.TAXO:
        sk = src[kind]
        written = {e["id"]: e for e in summ[kind]}
        items = plan_items(plan, kind)
        print(f"\n== {common.LABEL[kind]} — 원본 {len(sk['tech'])}개")
        if not items:  # 공급망: 재구성안은 작성 완료 표시만
            print(f"  문안 {len(written)}개 작성 완료 (재구성안 status: {plan[kind].get('status')})")
            continue
        planned_ids = {it["id"] for it in items} | {e["id"] for e in summ[kind]}
        # 작성된 항목은 문안 쪽 members로 셈(재구성안과의 일치는 아래 done 검사에서 확인) — 이중 집계 방지
        members = collections.Counter(m for it in items if it["id"] not in written for m in it["members"])
        members.update(m for e in summ[kind] for m in e["members"])
        missing = [k for k in sk["tech"] if k not in members]
        dup = [k for k, v in members.items() if v > 1]
        unknown = [k for k in members if k not in sk["tech"]]
        for label, lst in [("재구성안 미배정", missing), ("중복 배정", dup), ("없는 원본 ID", unknown)]:
            if lst:
                errs += 1
                print(f"  [오류] {label}: {lst}")
        done = [it for it in items if it["id"] in written]
        todo = [it for it in items if it["id"] not in written]
        for it in done:
            if written[it["id"]]["members"] != it["members"]:
                errs += 1
                print(f"  [오류] {it['id']}: 문안 members가 재구성안과 다름")
        print(f"  요약 {len(planned_ids)}개 계획 · 문안 작성 {len(written)}개 · 미작성 {len(todo)}개")
        used = used_incidents(kind, sk, summ[kind])
        planned_use = collections.defaultdict(list)
        for it in todo:
            for key, incs, found in planned_case_incidents(kind, sk, it):
                if not found:
                    errs += 1
                    print(f"  [오류] {it['id']}: 재구성안 사례 '{key}'가 구성 원본 참조에 없음")
                for i in incs:
                    planned_use[i].append(it["id"])
                    if i in used:
                        print(f"  [경고] {it['id']}: 재구성안 사례 '{key}'의 {i}는 이미 {used[i]}에서 사용")
        for i, where in planned_use.items():
            if len(where) > 1:
                print(f"  [경고] 재구성안 사례 {i} 반복: {', '.join(where)}")
        by_dom = collections.OrderedDict((d, []) for d in common.DOMAINS[kind])
        for it in items:
            by_dom.setdefault(it["domain"], []).append(it)
        for dom, lst in by_dom.items():
            for it in lst:
                ev = common.evaluate_attack(dict(it, domain=dom), sk)
                mark = "작성" if it["id"] in written else "미작성"
                print(f"  {it['id']} [{mark}] {it['name']} | {ev['likelihood']}×{ev['severity']}={ev['risk']} · "
                      f"실제 사고 {ev['incidents']} · 최근 {ev['recent']} · {ev['evidence']}")
    return errs


def show_cases(plan, src, summ, kind, dom):
    sk = src[kind]
    used = used_incidents(kind, sk, summ[kind])
    for it in plan_items(plan, kind):
        if dom and it["domain"] != dom:
            continue
        print(f"\n## {it['id']} {it['name']}  (재구성안 사례: {', '.join(it.get('cases') or []) or '미배치'})")
        for m in it["members"]:
            print(f"  ▸ {m} {sk['tech'][m]['row']['세부위협(Lv3)']}")
            for line in (sk["tech"][m]["row"]["참조"] or "").split("\n"):
                line = line.strip()
                if line.startswith("- [") or line.startswith("- 공개 사고 미확인"):
                    incs = common.INCIDENT_RE.findall(line)
                    taken = [f"{i}→{used[i]}" for i in incs if i in used]
                    print(f"    {line[:150]}" + (f"  ※ 사용 중 {', '.join(taken)}" if taken else ""))


def skeleton(plan, src, kind, dom):
    path = os.path.join(common.DATA_DIR, kind, f"{dom}.yaml")
    if os.path.exists(path):
        sys.exit(f"이미 있음: {os.path.relpath(path, common.ROOT)} — 골격을 만들지 않음")
    items = [it for it in plan_items(plan, kind) if it["domain"] == dom]
    if not items:
        sys.exit(f"재구성안에 {kind} {dom} 항목 없음")
    n_src = sum(len(it["members"]) for it in items)
    label = src[kind]["tactics"][dom]
    lines = [f"# {label} — 재구성 Lv3 (원본 {n_src}개 → {len(items)})"]
    for it in items:
        lines += [f"- id: {it['id']}", f"  name: {it['name']}", "  summary: ",
                  f"  members: [{', '.join(it['members'])}]", f"  basis: {it['basis']}",
                  "  description: |-", "    - ", "    - ", "  scenario: |-", "    - ", "  cases: |-"]
        lines += [f"    # 후보: {c}" for c in it.get("cases") or []] + ["    - ", "  controls: |-", "    - ", "    - ", ""]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"골격 생성: {os.path.relpath(path, common.ROOT)} ({len(items)}개) — 빈 필드를 채운 뒤 python3 integrated/scripts/common.py")


def main():
    ap = argparse.ArgumentParser(description="v3 재구성안 진행 점검·문안 골격 생성")
    ap.add_argument("--cases", nargs="+", metavar=("KIND", "DOM"), help="대표 사례 후보 보기 (예: identity SE)")
    ap.add_argument("--skeleton", nargs=2, metavar=("KIND", "DOM"), help="문안 골격 파일 생성 (예: physical RC)")
    args = ap.parse_args()
    plan, src = load_plan(), common.load_sources()
    if args.skeleton:
        return skeleton(plan, src, *args.skeleton)
    summ = common.load_summary()
    if args.cases:
        return show_cases(plan, src, summ, args.cases[0], args.cases[1] if len(args.cases) > 1 else None)
    errs = report(plan, src, summ)
    print(f"\n재구성안 점검 오류 {errs}건" + ("" if errs else " — 문안 검증은 python3 integrated/scripts/common.py"))
    sys.exit(1 if errs else 0)


if __name__ == "__main__":
    main()
