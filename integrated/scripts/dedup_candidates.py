"""통합 보안위협 매트릭스 — 요약 위협 간 중복 후보 추출 (v4 중복 통합 검토 보조).

요약 위협 쌍마다 네 신호를 점수화해 겹칠 가능성이 큰 쌍을 뽑는다(v4 판정 때 v3 258개에 같은 방식으로 적용 — 점수 3 이상 635쌍).
  ① 연계 위협 표기(원본 연계 열·문안 links)              +2
  ② 구성 원본의 같은 ATT&CK 기법(하위기법 일치)             +2 / 기법마다, 상위기법만 일치 +0.5
  ③ 통합 사고사례 기준 같은 실제 사고(교차 DB 동일 사고 포함) +1 / 사고마다(최대 5)
  ④ 세부 위협명·핵심 요약의 글자 2-gram 자카드 유사도        ×6
출력 열 '현재 판정'은 data/dup_groups.yaml 기준 같은 그룹·다른 그룹·그룹 없음 — 점수가 높은데 같은 그룹이 아닌 쌍이 재검토 대상이다.
사고 공유(③)만 높은 쌍은 대개 같은 대형 사고의 다른 공격 단계(킬체인)라 중복이 아니다.

사용
  python3 integrated/scripts/dedup_candidates.py                 # 점수 상위 60쌍
  python3 integrated/scripts/dedup_candidates.py --top 200 --min 4 --cross   # Lv0 간 쌍만
  python3 integrated/scripts/dedup_candidates.py --csv out.csv  # 전체 후보 CSV
"""
import argparse
import collections
import csv
import itertools
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_integrated_matrix as B  # noqa: E402
import common  # noqa: E402
import incidents  # noqa: E402


def attack_ids(r, src):
    """구성 원본의 ATT&CK 기법 ID 집합 (AI는 ATLAS 기반이라 비움)."""
    if r["kind"] in ("cloud", "ot"):
        return {m for m in r["members"] if m.startswith("T")}
    if r["kind"] in common.TAXO:
        return {t.strip() for m in r["members"]
                for t in str(src[r["kind"]]["tech"][m]["row"]["ATT&CK ID"] or "").replace("\n", ",").split(",")
                if t.strip().startswith("T")}
    return set()


def bigrams(text):
    t = re.sub(r"\s+", "", text)
    return {t[i:i + 2] for i in range(len(t) - 1)}


def candidates(src, summ):
    rows, _ = B.build_rows(src, summ)
    cat = incidents.build_catalog([e for k in common.KINDS for e in summ[k]], src)
    inc = collections.defaultdict(set)
    for c in cat:
        for t in c["counted"]:
            inc[t].add(c["uid"])
    info = {r["id"]: dict(r=r, att=attack_ids(r, src), inc=inc[r["id"]], bg=bigrams(r["name"] + r["summary"]),
                          links={l.split(" ")[0] for l in r["links_text"].split("\n") if l}) for r in rows}
    group = {i: g["id"] for g in common.load_groups() for i in g["items"]}
    out = []
    for a, b in itertools.combinations(info, 2):
        x, y = info[a], info[b]
        same = x["att"] & y["att"]
        parent = {t.split(".")[0] for t in x["att"]} & {t.split(".")[0] for t in y["att"]} - {t.split(".")[0] for t in same}
        shared = len(x["inc"] & y["inc"])
        sim = len(x["bg"] & y["bg"]) / max(1, len(x["bg"] | y["bg"]))
        linked = b in x["links"]
        score = (2 if linked else 0) + 2 * len(same) + 0.5 * len(parent) + min(shared, 5) + 6 * sim
        ga, gb = group.get(a), group.get(b)
        verdict = f"같은 그룹 {ga}" if ga and ga == gb else (f"다른 그룹 {ga or '-'}/{gb or '-'}" if ga or gb else "그룹 없음")
        out.append(dict(score=round(score, 1), a=a, a_name=x["r"]["name"], b=b, b_name=y["r"]["name"],
                        cross=x["r"]["kind"] != y["r"]["kind"], linked=linked, attack=", ".join(sorted(same)),
                        shared_incidents=shared, similarity=round(sim, 2), verdict=verdict))
    return sorted(out, key=lambda d: -d["score"])


def main():
    ap = argparse.ArgumentParser(description="요약 위협 간 중복 후보 추출")
    ap.add_argument("--top", type=int, default=60)
    ap.add_argument("--min", type=float, default=3.0, help="최소 점수(기본 3)")
    ap.add_argument("--cross", action="store_true", help="Lv0 간 쌍만")
    ap.add_argument("--csv", help="후보 전체를 CSV로 저장")
    args = ap.parse_args()
    src, summ = common.load_sources(), common.load_summary()
    cands = [c for c in candidates(src, summ) if c["score"] >= args.min and (c["cross"] or not args.cross)]
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(cands[0]))
            w.writeheader()
            w.writerows(cands)
        print(f"저장: {args.csv} ({len(cands)}쌍)")
    print(f"후보 {len(cands)}쌍 (점수 ≥ {args.min}) — 상위 {min(args.top, len(cands))}쌍")
    for c in cands[:args.top]:
        print(f"{c['score']:5.1f}  {c['a']:9s} {c['a_name'][:22]:22s} | {c['b']:9s} {c['b_name'][:22]:22s} | "
              f"연계 {int(c['linked'])} · 기법 {c['attack'] or '-'} · 공유 사고 {c['shared_incidents']} · "
              f"유사도 {c['similarity']} | {c['verdict']}")


if __name__ == "__main__":
    main()
