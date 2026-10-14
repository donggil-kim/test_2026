"""통합 사고사례 목록 검증 원장 — 생성·병합·집계 (docs/v4_사고사례_검증_작업방향.md)

원장은 원본 사례 ID(묶음의 대표 기록)를 키로 한다. 통합 사례 ID(UC-)는 참고용이다.
웹 판정은 세션(서브에이전트 포함)에서 하고, 결과는 배치별 CSV(data/verification/batches/*.csv)에 쓴 뒤 이 스크립트로 원장에 합친다.

사용:
  python3 integrated/scripts/verify_incidents.py init     # 원장 새로 만들기(기존 판정은 키로 보존)
  python3 integrated/scripts/verify_incidents.py merge    # 배치 결과 → 원장 병합
  python3 integrated/scripts/verify_incidents.py stats    # 진행·판정 집계
  python3 integrated/scripts/verify_incidents.py batch P0-01   # 배치 입력 파일 생성(검증자에게 넘길 행)
"""
import collections
import csv
import glob
import math
import os
import random
import re
import sys

import common
import incidents

HERE = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(common.DATA_DIR, "verification")
LEDGER = os.path.join(VDIR, "incident_verification.csv")
BATCH_DIR = os.path.join(VDIR, "batches")
INPUT_DIR = os.path.join(VDIR, "inputs")
BATCH_SIZE = 25
SAMPLE_RATE, SAMPLE_MIN, SEED = 0.3, 5, 20261012

# 목록에서 가져오는 열(수정 금지)
BASE_COLS = ["원장 키", "원본 사례 ID", "통합 사례 ID", "사례명", "시점", "사례 구분", "지역", "행위자", "영향·대상", "요약", "출처",
             "출처 유형", "우선순위", "우선순위 사유", "본문 노출 위협", "대표 사례 인용 위협", "인용 문안", "웹 검증", "배치"]
# 검증자가 채우는 열 — 판정 값은 작업 방향서 5장
VERDICT_COLS = ["A 존재", "B 시점", "발생월", "공개월", "C 핵심 내용", "C 차이", "D 사례 구분", "D 제안", "E 출처", "E 메모",
                "F 묶음", "G 문안", "G 메모", "AI 활용", "종합 판정", "제안 정정", "근거 URL", "근거 등급", "검색일", "검증자", "비고"]
COLS = BASE_COLS + VERDICT_COLS
AGG_RE = re.compile(r"(Wiz|ramimac|GTI|SEC|Wiz, ramimac)")


def src_class(s):
    s = (s or "").strip()
    urls = re.findall(r"https?://[^\s|]+", s)
    if s.startswith("ATT&CK"):
        return "S5 ATT&CK"
    if s.startswith("OWASP") or s.startswith("CSA"):
        return "S6 OWASP·CSA"
    if not s:
        return "S0 출처 없음"
    if urls and all("atlas.mitre.org" in u for u in urls):
        return "S4 ATLAS"
    if urls:
        return "S1 URL"
    if AGG_RE.fullmatch(s):
        return "S2 집계기관"
    return "S3 텍스트"


def load_catalog():
    src, summ = common.load_sources(), common.load_summary()
    every = [e for k in common.KINDS for e in summ[k]]
    cat = incidents.build_catalog(every, src)
    recs = incidents.load_records(src)
    # 사례 qid → 인용한 대표 사례 줄, 본문(간략 매트릭스 = 대표 사례 첫 줄) 노출 위협
    cited_lines, body = collections.defaultdict(list), collections.defaultdict(set)
    for e in every:
        lines = [l for l in common._lines(e["cases"]) if l.strip()]
        for i, line in enumerate(lines):
            one = dict(e, cases=line)
            for qids, cite in incidents.case_refs(one, src, recs):
                q = qids if not cite else [cite["qid"]]
                for x in q:
                    cited_lines[x].append(f"{e['id']}: {line.strip()[2:]}")
                    if i == 0:
                        body[x].add(e["id"])
    return cat, cited_lines, body


def build_rows():
    cat, cited_lines, body = load_catalog()
    out = []
    for r in cat:
        qs = r["qids"]
        dbs = {d for d in r["dbs"] if d != "cite"}
        why = []
        b = sorted(set().union(*[body[q] for q in qs]))
        if b:
            why.append("본문 노출")
        if r["cited"]:
            why.append("대표 사례 인용")
        if r["recent"]:
            why.append("최근(2025~)")
        if len(dbs) > 1:
            why.append("동일 사고 묶음")
        if set(r["dbs"]) == {"cite"}:
            why.append("사고 DB 외 인용")
        prio = "P0" if b else ("P1" if why else "P2")
        s = src_class(r["source"])
        lines = list(dict.fromkeys(l for q in qs for l in cited_lines[q]))
        out.append({
            "원장 키": r["rep"], "원본 사례 ID": r["origin"], "통합 사례 ID": r["uid"], "사례명": r["name"], "시점": r["date"],
            "사례 구분": r["category"], "지역": r["region"] or "", "행위자": r["actor"] or "", "영향·대상": r["impact"] or "",
            "요약": r["summary"] or "", "출처": r["source"], "출처 유형": s, "우선순위": prio, "우선순위 사유": " · ".join(why),
            "본문 노출 위협": ", ".join(b), "대표 사례 인용 위협": ", ".join(sorted(r["cited"])), "인용 문안": "\n".join(lines),
            "웹 검증": "Y" if s[:2] in ("S0", "S1", "S2", "S3") else "로컬", "_dbs": r["dbs"]})
    # P2 층화 표본 — 대표 DB × 연대
    p2 = [x for x in out if x["우선순위"] == "P2" and x["웹 검증"] == "Y"]
    strata = collections.defaultdict(list)
    for x in p2:
        y = int(x["시점"][:4]) if re.match(r"\d{4}", x["시점"]) else 0
        band = "~2019" if y <= 2019 else "2020-2022" if y <= 2022 else "2023-2024" if y <= 2024 else "2025~"
        strata[(x["_dbs"][0], band)].append(x)
    rnd = random.Random(SEED)
    for k in sorted(strata):
        grp = sorted(strata[k], key=lambda x: x["원장 키"])
        n = min(len(grp), max(SAMPLE_MIN, math.ceil(SAMPLE_RATE * len(grp))))
        for x in rnd.sample(grp, n):
            x["우선순위"] = "P2 표본"
    # 배치: 우선순위·웹 여부 순, 최근 사건 먼저
    order = {"P0": 0, "P1": 1, "P2 표본": 2, "P2 확대": 3, "P2": 4}
    out.sort(key=lambda x: (order[x["우선순위"]], x["웹 검증"] != "Y", incidents._date_key(x["시점"])), reverse=False)
    out.sort(key=lambda x: (order[x["우선순위"]], x["웹 검증"] != "Y"))
    seq = collections.Counter()
    for x in out:
        if x["우선순위"] == "P2":
            x["배치"] = ""
            continue
        tag = {"P0": "P0", "P1": "P1", "P2 표본": "P2"}[x["우선순위"]] + ("" if x["웹 검증"] == "Y" else "L")
        seq[tag] += 1
        x["배치"] = f"{tag}-{(seq[tag] - 1) // BATCH_SIZE + 1:02d}"
    for x in out:
        del x["_dbs"]
    return out


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, cols):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def cmd_init():
    rows = build_rows()
    old = {r["원장 키"]: r for r in read_csv(LEDGER)} if os.path.exists(LEDGER) else {}
    for r in rows:
        for c in VERDICT_COLS:
            r[c] = old.get(r["원장 키"], {}).get(c, "")
    write_csv(LEDGER, rows, COLS)
    print(f"원장: {os.path.relpath(LEDGER)} — {len(rows)}행 (기존 판정 보존 {sum(1 for r in rows if r['종합 판정'])}행)")
    cmd_stats()


def cmd_batch(name):
    rows = [r for r in read_csv(LEDGER) if r["배치"] == name]
    if not rows:
        sys.exit(f"배치 없음: {name}")
    path = os.path.join(INPUT_DIR, f"{name}.csv")
    write_csv(path, rows, COLS)
    print(f"{os.path.relpath(path)} — {len(rows)}행")


def cmd_merge():
    ledger = read_csv(LEDGER)
    extra = [c for c in (ledger[0].keys() if ledger else []) if c not in COLS]
    idx = {r["원장 키"]: r for r in ledger}
    n, bad = 0, []
    for path in sorted(glob.glob(os.path.join(BATCH_DIR, "*.csv"))):
        for b in read_csv(path):
            k = b.get("원장 키", "")
            if k not in idx:
                bad.append((os.path.basename(path), k))
                continue
            for c in VERDICT_COLS:
                if b.get(c, "").strip():
                    idx[k][c] = b[c].strip()
            n += 1
    write_csv(LEDGER, ledger, COLS + extra)
    print(f"병합 {n}행" + (f" · 알 수 없는 키 {len(bad)}: {bad[:5]}" if bad else ""))
    cmd_stats()


def cmd_stats():
    rows = read_csv(LEDGER)
    c = collections.Counter
    print("우선순위:", dict(c(r["우선순위"] for r in rows)))
    print("배치 수:", len({r["배치"] for r in rows if r["배치"]}), "| 웹 검증 대상(배치 있음):",
          sum(1 for r in rows if r["배치"] and r["웹 검증"] == "Y"))
    done = [r for r in rows if r["종합 판정"]]
    print(f"판정 완료 {len(done)}/{sum(1 for r in rows if r['배치'])}")
    if done:
        print("  종합 판정:", dict(c(r["종합 판정"] for r in done)))
        print("  B 시점:", dict(c(r["B 시점"] for r in done)))
        by = collections.defaultdict(c)
        for r in done:
            by[r["우선순위"]][r["종합 판정"]] += 1
        for k, v in by.items():
            print(f"  {k}: {dict(v)}")


def _stratum(x):
    h = x["원장 키"]
    db = ("cloud" if h.startswith("CL/") else "ot" if h.startswith("OT/") else "supplychain" if h.startswith("SCI")
          else "identity" if h.startswith("IDI") else "physical" if h.startswith("PHI") else "other")
    m = re.match(r"(\d{4})", x["시점"])
    y = int(m.group(1)) if m else 0
    return db, ("~2019" if y <= 2019 else "2020-2022" if y <= 2022 else "2023-2024" if y <= 2024 else "2025~")


def cmd_expand(threshold=0.05):
    """P2 표본 결과로 확대 규칙(작업 방향서 6.3) 적용 — 오류율 기준 이상 층의 비표본 P2 행을 'P2 확대'로 배치 배정."""
    rows = read_csv(LEDGER)
    bad = lambda x: x["종합 판정"] in ("수정 필요", "확인 불가")
    st = collections.defaultdict(list)
    for x in rows:
        if x["우선순위"] == "P2 표본":
            st[_stratum(x)].append(x)
    hot = {k for k, v in st.items() if v and sum(map(bad, v)) / len(v) >= threshold}
    seq = 0
    for x in sorted(rows, key=lambda x: x["원장 키"]):
        if x["우선순위"] == "P2" and _stratum(x) in hot:
            x["우선순위"] = "P2 확대"
            x["배치"] = f"P2X-{seq // BATCH_SIZE + 1:02d}"
            seq += 1
    write_csv(LEDGER, rows, COLS)
    print(f"확대 층 {len(hot)}개: {sorted(hot)} → {seq}행")


def cmd_normalize():
    """판정 기준 정렬(검증자 지침) — '최종 판정' 열에 기록, 원 판정('종합 판정')은 보존."""
    rows = read_csv(LEDGER)
    cols = COLS + [c for c in ("최종 판정", "정렬 사유") if c not in COLS]
    n = collections.Counter()
    for x in rows:
        v, why = x["종합 판정"], ""
        if x["B 시점"] == "둘 다 아님" and v in ("통과", "경미 수정"):
            v, why = "수정 필요", "B 둘 다 아님"
        elif x["B 시점"] == "발생월 일치" and v == "통과":
            v, why = "경미 수정", "시점 → 최초 공개월(F2)"
        elif x["G 문안"] == "수정 필요" and v == "경미 수정":
            g = x["G 메모"] + " " + x["제안 정정"]
            datey = re.search(r"\(\d{4}(-\d{2})?\)\s*[→>-]+\s*\(?\d{4}", g) or "시점" in g
            fact = re.search(r"수치|기간|약 \d|행위자|구분|라벨|\[실증\]|서술|요약:", x["G 메모"])
            if fact and not datey:
                v, why = "수정 필요", "G 문안 사실 정정"
        if x.get("최종 판정") and x.get("정렬 사유", "").startswith("교차 검수"):
            continue  # 교차 검수로 확정한 값은 유지
        x["최종 판정"], x["정렬 사유"] = (v if x["종합 판정"] else ""), why
        n[why] += bool(why)
    write_csv(LEDGER, rows, cols)
    print("정렬:", dict(n))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    {"init": cmd_init, "merge": cmd_merge, "stats": cmd_stats, "expand": cmd_expand, "normalize": cmd_normalize}.get(cmd, lambda: cmd_batch(cmd if cmd != "batch" else sys.argv[2]))() \
        if cmd != "batch" else cmd_batch(sys.argv[2])
