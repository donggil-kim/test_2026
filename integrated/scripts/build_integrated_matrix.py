"""통합 AI·클라우드 보안위협 매트릭스 빌드 — 요약 문안(YAML)과 원본 2종을 보고서용 워크북 하나로 묶는다.

입력
  - 요약(재구성 Lv3) 문안: integrated/data/ai/D*.yaml, integrated/data/cloud/<전술>.yaml
  - 원본: sources/ai_v3.2 (AI v3.2 LITE, Lv3 124), output/통합_클라우드보안위협_매트릭스_v5.xlsx (154행)
출력
  - integrated/output/통합_AI클라우드_보안위협_매트릭스_v1.xlsx
  - integrated/output/통합_요약매트릭스_v1.csv (요약 매트릭스 검토·diff용)
  - integrated/output/통합_요약목록_v1.md (도메인별 요약 위협 목록)

사용: python3 integrated/scripts/build_integrated_matrix.py
"""
import collections
import csv
import datetime
import os
import re
import sys

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

VERSION = "v1"
OUT_DIR = os.path.join(common.ROOT, "integrated", "output")
XLSX = os.path.join(OUT_DIR, f"통합_AI클라우드_보안위협_매트릭스_{VERSION}.xlsx")
CSV = os.path.join(OUT_DIR, f"통합_요약매트릭스_{VERSION}.csv")
MD = os.path.join(OUT_DIR, f"통합_요약목록_{VERSION}.md")
LV0 = {"ai": "AI 보안위협", "cloud": "클라우드 보안위협"}

# ---------------------------------------------------------------- 서식 (클라우드 v5 빌드 스크립트와 같은 색 체계)
FONT = "맑은 고딕"
THIN = Side(style="thin", color="D0D0D0")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)
RISK_COLOR = {"매우 높음": ("C0392B", "FFFFFF"), "높음": ("E67E22", "FFFFFF"),
              "보통": ("F7DC6F", "000000"), "낮음": ("A9DFBF", "000000")}
LEVEL_COLOR = {"실제 사고 확인": "1E8449", "실사용 기법 포함": "2E86C1",
               "실증·공개 취약점": "B9770E", "이론·시나리오": "7F8C8D"}
LV0_FILL = {"ai": "EBDEF0", "cloud": "D6EAF8"}
LV0_BAND = {"ai": "6C3483", "cloud": "1F618D"}
NAVY, HDR = "1F3864", "34495E"
RISK_RANK = {r: i for i, r in enumerate(common.RISK_ORDER)}


def font(size=10, bold=False, color="000000"):
    return Font(name=FONT, size=size, bold=bold, color=color)


def fill(color):
    return PatternFill("solid", fgColor=color)


def widths(ws, ws_widths):
    for i, w in enumerate(ws_widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def title(ws, text, sub, ncols):
    c = ws.cell(1, 1, text)
    c.font, c.fill, c.alignment = font(13, True, "FFFFFF"), fill(NAVY), Alignment(vertical="center")
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=ncols)
    ws.row_dimensions[1].height = 24
    c = ws.cell(2, 1, sub)
    c.font = font(9, color="404040")
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=ncols)


def groups(ws, row, spec):
    c0 = 1
    for name, span, color in spec:
        if span > 1:
            ws.merge_cells(start_row=row, start_column=c0, end_row=row, end_column=c0 + span - 1)
        c = ws.cell(row, c0, name)
        c.fill, c.font, c.alignment = fill(color), font(10, True, "FFFFFF"), CENTER
        c0 += span


def header(ws, row, cols, color=HDR):
    for j, name in enumerate(cols, 1):
        c = ws.cell(row, j, name)
        c.fill, c.font, c.alignment, c.border = fill(color), font(10, True, "FFFFFF"), CENTER, BORDER
    ws.row_dimensions[row].height = 30


def put_row(ws, r, vals, size=10):
    for j, v in enumerate(vals, 1):
        c = ws.cell(r, j, v)
        c.font, c.alignment, c.border = font(size), WRAP, BORDER


def print_setup(ws, title_rows=None, paper="A3"):
    """인쇄: 가로·폭 맞춤(높이 자동), 표 머리글 반복."""
    ws.page_setup.orientation = "landscape"
    ws.page_setup.paperSize = ws.PAPERSIZE_A3 if paper == "A3" else ws.PAPERSIZE_A4
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.page_margins.left = ws.page_margins.right = 0.4
    ws.page_margins.top = ws.page_margins.bottom = 0.5
    if title_rows:
        ws.print_title_rows = title_rows


def paint_risk(c, risk, size=10):
    bg, fg = RISK_COLOR[risk]
    c.fill, c.font, c.alignment = fill(bg), font(size, risk in ("매우 높음", "높음"), fg), CENTER


def paint_level(c, level, size=10):
    c.font, c.alignment = font(size, True, LEVEL_COLOR[level]), CENTER


# ---------------------------------------------------------------- 요약 행 구성
def compress_ids(ids):
    """ATT&CK ID를 상위기법별로 묶어 짧게 표기: T1552, T1552.001·.008 / 비 ATT&CK(AZT…)는 그대로."""
    grouped = collections.OrderedDict()
    for t in ids:
        parent, _, sub = t.partition(".")
        grouped.setdefault(parent, []).append(sub)
    out = []
    for parent, subs in grouped.items():
        if "" in subs:
            out.append(parent)
        subs = [s for s in subs if s]
        if subs:
            out.append(f"{parent}.{subs[0]}" + "".join(f"·.{s}" for s in subs[1:]))
    return ", ".join(out)


def uniq(seq):
    return list(collections.OrderedDict.fromkeys(x for x in seq if x))


def build_rows(ai_src, cl_src, ai_sum, cl_sum):
    tactic_ko = {t: label.split("] ", 1)[1] for t, label in cl_src["tactics"].items()}
    ut_to_ai = {m: e["id"] for e in ai_sum for m in e["members"]}
    names = {e["id"]: e["name"] for e in ai_sum + cl_sum}
    order = {e["id"]: i for i, e in enumerate(ai_sum + cl_sum)}

    # 연계 위협: AI 문안의 수동 연계 + 클라우드 원본 'AI 매트릭스 연계(UT)' 열 → 양방향
    links = collections.defaultdict(set)
    for e in ai_sum + cl_sum:
        for target in e.get("links") or []:
            links[e["id"]].add(target)
            links[target].add(e["id"])
    for e in cl_sum:
        for m in e["members"]:
            for r in cl_src["rows"]:
                if str(r["ATT&CK ID"]) == m:
                    for ut in re.findall(r"UT-\d+\.\d+", r["AI 매트릭스 연계(UT)"] or ""):
                        links[e["id"]].add(ut_to_ai[ut])
                        links[ut_to_ai[ut]].add(e["id"])
    unknown = [t for k in links for t in links[k] if t not in names]
    if unknown:
        raise ValueError(f"연계 위협 ID 없음: {unknown}")

    rows = []
    for e in ai_sum:
        ev = common.evaluate_ai(e, ai_src)
        mem = [ai_src["lv3"][m] for m in e["members"]]
        owasp = uniq(x for d in mem for x in re.split(r",\s*", d["OWASP 매핑 (주)"] or ""))
        atlas = uniq(x.split(".")[0] for d in mem for x in re.split(r",\s*", d["ATLAS 기법 (주)"] or ""))
        refs = ([f"OWASP {', '.join(owasp)}"] if owasp else []) + ([f"ATLAS {', '.join(atlas)}"] if atlas else [])
        stages = uniq(re.sub(r"\([A-Za-z][^()]*\)$", "", d["주 공격 단계"]).strip() for d in mem)
        rows.append(dict(e, kind="ai", lv0=LV0["ai"], lv1=ai_src["domains"][e["domain"]], ev=ev,
                         stage="·".join(stages), refs="\n".join(refs), origin=", ".join(e["members"])))
    for e in cl_sum:
        ev = common.evaluate_cloud(e, cl_src)
        tech = [cl_src["tech"][m] for m in e["members"]]
        others = sorted({t for x in tech for t in x["tactics"]} - {e["domain"]}, key=common.TACTICS.index)
        stage = tactic_ko[e["domain"]] + (f" (연관: {'·'.join(tactic_ko[t] for t in others)})" if others else "")
        attack = [m for m in e["members"] if m.startswith("T")]
        azure = [m for m in e["members"] if not m.startswith("T")]
        csa = sorted({s for x in tech for s in re.findall(r"SI-\d+", x["row"]["CSA Top Threats 2026"] or "")})
        refs = ([f"ATT&CK {compress_ids(attack)}"] if attack else []) + \
               ([f"Azure ATRM {', '.join(azure)}"] if azure else []) + ([f"CSA {', '.join(csa)}"] if csa else [])
        rows.append(dict(e, kind="cloud", lv0=LV0["cloud"], lv1=cl_src["tactics"][e["domain"]], ev=ev,
                         stage=stage, refs="\n".join(refs), origin=", ".join(c for x in tech for c in x["ctc"])))
    for r in rows:
        r["links_text"] = "\n".join(f"{t} {names[t]}" for t in sorted(links[r["id"]], key=order.get))
    return rows


# ---------------------------------------------------------------- 재구성 매핑 (원본 Lv3 → 요약 Lv3)
def mapping_rows(ai_src, cl_src, ai_sum, cl_sum):
    out = []
    for e in ai_sum:
        n = len(e["members"])
        for m in e["members"]:
            d = ai_src["lv3"][m]
            kind = "단독 유지" if n == 1 else "유사 위협 통합"
            if d["domain"] != e["domain"]:
                kind = f"도메인 이동({d['domain']}→{e['domain']})" + ("" if n == 1 else " · 유사 위협 통합")
            out.append([LV0["ai"], d["도메인 (Lv1)"], m, "-", d["세부 위협 (Lv3)"], d["위험도"],
                        e["id"], e["name"], ai_src["domains"][e["domain"]], kind, e["basis"]])
    for e in cl_sum:
        n = len(e["members"])
        for m in e["members"]:
            tech = cl_src["tech"][m]
            for r in cl_src["rows"]:
                if str(r["ATT&CK ID"]) != m:
                    continue
                t = r["tactic"]
                if t == e["domain"]:
                    kind = "단독 유지" if n == 1 else "유사 위협 통합"
                elif e["domain"] in tech["tactics"]:
                    kind = f"전술 중복 통합({t}→{e['domain']})"
                else:
                    kind = f"전술 이동({t}→{e['domain']})" + ("" if n == 1 else " · 유사 위협 통합")
                out.append([LV0["cloud"], r["도메인(Lv1)"], r["CTC-ID"], m, r["세부위협(Lv3)"], r["위험도"],
                            e["id"], e["name"], cl_src["tactics"][e["domain"]], kind, e["basis"]])
    return out


# ---------------------------------------------------------------- 시트 작성
SUMMARY_COLS = ["구분(Lv0)", "도메인(Lv1)", "위협 ID", "세부 위협(Lv3)", "위협 설명", "공격 시나리오", "대표 사례",
                "발생가능성", "심각도", "위험도", "근거 수준", "실제 사고 수", "대응 방안",
                "공격 단계", "관련 기준", "연계 위협", "원본 Lv3 ID"]


def summary_values(r):
    ev = r["ev"]
    return [r["lv0"], r["lv1"], r["id"], r["name"], r["description"], r["scenario"], r["cases"],
            ev["likelihood"], ev["severity"], ev["risk"], ev["evidence"], ev["incidents"], r["controls"],
            r["stage"], r["refs"], r["links_text"], r["origin"]]


def sheet_summary(wb, rows, today):
    ws = wb.create_sheet("통합 요약 매트릭스")
    title(ws, f"통합 AI·클라우드 보안위협 매트릭스 {VERSION} — 보고서용 요약 (Lv0 구분 → Lv1 도메인 → Lv3 세부 위협)",
          f"AI {sum(r['kind'] == 'ai' for r in rows)}개 · 클라우드 {sum(r['kind'] == 'cloud' for r in rows)}개 | "
          f"원본: AI 보안위협 매트릭스 v3.2 LITE(Lv3 124) · 클라우드 보안위협 매트릭스 v5(Lv3 154행) | {today}",
          len(SUMMARY_COLS))
    groups(ws, 3, [("분류 체계", 4, "2E5496"), ("위협 내용", 3, "117A65"), ("위험 평가", 5, "A04000"),
                   ("대응", 1, "6C3483"), ("교차 매핑·추적", 4, "1F7A8C")])
    header(ws, 4, SUMMARY_COLS)
    for i, r in enumerate(rows, 5):
        put_row(ws, i, summary_values(r))
        ws.cell(i, 1).fill = fill(LV0_FILL[r["kind"]])
        ws.cell(i, 3).font = font(10, True)
        ws.cell(i, 4).font = font(10, True)
        for col in (8, 9, 12):
            ws.cell(i, col).alignment = CENTER
        paint_risk(ws.cell(i, 10), r["ev"]["risk"])
        paint_level(ws.cell(i, 11), r["ev"]["evidence"])
    ws.freeze_panes = "E5"
    ws.auto_filter.ref = f"A4:{get_column_letter(len(SUMMARY_COLS))}{len(rows) + 4}"
    widths(ws, [11, 18, 10, 22, 58, 52, 56, 7, 7, 9, 11, 7, 44, 18, 24, 30, 22])
    print_setup(ws, "3:4")


def sheet_matrix_view(wb, rows, ai_src, cl_src):
    ws = wb.create_sheet("매트릭스 뷰")
    ws.cell(1, 1, "매트릭스 뷰 — 셀 색 = 위험도 (빨강 매우 높음 · 주황 높음 · 노랑 보통 · 초록 낮음), [n] = 실제 사고 수, "
                  "같은 도메인 안에서 위험도·사고 수 순 정렬").font = font(11, True, NAVY)
    r0 = 3
    for kind, doms in [("ai", ai_src["domains"]), ("cloud", cl_src["tactics"])]:
        items = [r for r in rows if r["kind"] == kind]
        band = ws.cell(r0, 1, f"{LV0[kind]} — {len(items)}개 위협 · {len(doms)}개 도메인")
        band.fill, band.font, band.alignment = fill(LV0_BAND[kind]), font(11, True, "FFFFFF"), Alignment(vertical="center")
        ws.merge_cells(start_row=r0, start_column=1, end_row=r0, end_column=len(doms))
        ws.row_dimensions[r0].height = 20
        depth = 0
        for j, (code, label) in enumerate(doms.items(), 1):
            col = sorted((r for r in items if r["domain"] == code),
                         key=lambda r: (RISK_RANK[r["ev"]["risk"]], -r["ev"]["incidents"], r["id"]))
            h = ws.cell(r0 + 1, j, f"{label}\n({len(col)})")
            h.fill, h.font, h.alignment, h.border = fill(NAVY), font(9, True, "FFFFFF"), CENTER, BORDER
            for i, r in enumerate(col, r0 + 2):
                n = r["ev"]["incidents"]
                c = ws.cell(i, j, f"{r['id']} {r['name']}" + (f" [{n}]" if n else ""))
                paint_risk(c, r["ev"]["risk"], 9)
                c.alignment, c.border = Alignment(wrap_text=True, vertical="top"), BORDER
            depth = max(depth, len(col))
        ws.row_dimensions[r0 + 1].height = 44
        r0 += depth + 4
    widths(ws, [20] * max(len(ai_src["domains"]), len(cl_src["tactics"])))
    print_setup(ws)


def sheet_domain_summary(wb, rows, ai_src, cl_src):
    ws = wb.create_sheet("도메인 요약")
    cols = ["구분(Lv0)", "도메인(Lv1)", "원본 Lv3 수", "요약 위협 수", "매우 높음", "높음", "보통", "낮음",
            "실제 사고 확인", "주요 고위험 위협"]
    title(ws, "도메인 요약 — Lv1 도메인별 요약 위협 수·위험도 분포", "원본 Lv3 수: AI는 Lv3 항목 수, 클라우드는 v5 행 수"
          "(전술 중복 행 포함). 위험도는 같은 Lv0 안에서 비교", len(cols))
    header(ws, 4, cols)
    r = 5
    for kind, doms in [("ai", ai_src["domains"]), ("cloud", cl_src["tactics"])]:
        tot = collections.Counter()
        for code, label in doms.items():
            items = [x for x in rows if x["kind"] == kind and x["domain"] == code]
            if kind == "ai":
                n_src = sum(len(x["members"]) for x in items)
            else:
                n_src = sum(len(cl_src["tech"][m]["ctc"]) for x in items for m in x["members"])
            dist = collections.Counter(x["ev"]["risk"] for x in items)
            real = sum(x["ev"]["evidence"] == "실제 사고 확인" for x in items)
            top = sorted(items, key=lambda x: (RISK_RANK[x["ev"]["risk"]], -x["ev"]["incidents"], x["id"]))[:2]
            put_row(ws, r, [LV0[kind], label, n_src, len(items)] + [dist[k] for k in common.RISK_ORDER] +
                    [real, "\n".join(f"{x['id']} {x['name']} ({x['ev']['risk']})" for x in top)])
            ws.cell(r, 1).fill = fill(LV0_FILL[kind])
            for col in range(3, 10):
                ws.cell(r, col).alignment = CENTER
            tot.update({"src": n_src, "n": len(items), "real": real, **dist})
            r += 1
        put_row(ws, r, [LV0[kind], "합계", tot["src"], tot["n"]] + [tot[k] for k in common.RISK_ORDER] + [tot["real"], ""])
        for col in range(1, 11):
            ws.cell(r, col).font = font(10, True)
            ws.cell(r, col).fill = fill("F2F3F4")
        for col in range(3, 10):
            ws.cell(r, col).alignment = CENTER
        r += 2
    for k, col in zip(common.RISK_ORDER, range(5, 9)):
        ws.cell(4, col).fill = fill(RISK_COLOR[k][0])
        ws.cell(4, col).font = font(10, True, RISK_COLOR[k][1])
    ws.freeze_panes = "C5"
    widths(ws, [16, 30, 10, 10, 9, 9, 9, 9, 11, 60])
    print_setup(ws, "4:4", "A4")


AI_DETAIL_COLS = ["통합 위협 ID", "구분(Lv0)", "도메인(Lv1)", "Lv2 ID", "위협 분류(Lv2)", "원본 ID(Lv3)", "세부 위협(Lv3)",
                  "요약설명", "참조", "발생가능성", "심각도", "위험도", "근거 수준", "실제 사고 수", "심각도 근거",
                  "주 공격 단계", "ATLAS 기법 (주)", "OWASP 매핑 (주)", "핵심 통제 요약(Lv2)",
                  "ATLAS 사고 사례 ID", "OWASP 인용 사고 수"]
CLOUD_SRC_TAIL = ["ATT&CK ID", "통합된 기법", "구분", "Cloud 범위", "Cloud 플랫폼", "기타 플랫폼", "설명 출처",
                  "CSA Top Threats 2026", "AI 매트릭스 연계(UT)", "AWS (TTC)", "Azure (ATRM)", "Kubernetes",
                  "발생가능성 근거 (자동 산정)", "최근 사고(2025~)", "실증·연구 수", "ATT&CK 사례 수",
                  "사고 매핑 근거", "관련 사례 ID", "ATT&CK 링크", "탐지·대응 포인트"]
CLOUD_DETAIL_COLS = ["통합 위협 ID", "구분(Lv0)", "도메인(Lv1)", "Lv2 ID", "위협 분류(Lv2)", "원본 ID(Lv3)", "세부 위협(Lv3)",
                     "요약설명", "참조", "발생가능성", "심각도", "위험도", "근거 수준", "실제 사고 수", "심각도 근거"] + CLOUD_SRC_TAIL


def detail_sheet(wb, name, sub, cols, data, spec, col_widths):
    ws = wb.create_sheet(name)
    title(ws, name, sub, len(cols))
    groups(ws, 3, spec)
    header(ws, 4, cols)
    for i, (kind, vals, risk, level) in enumerate(data, 5):
        put_row(ws, i, vals, 9)
        ws.cell(i, 1).font = font(9, True)
        ws.cell(i, 2).fill = fill(LV0_FILL[kind])
        for col in (10, 11, 14):
            ws.cell(i, col).alignment = CENTER
        paint_risk(ws.cell(i, 12), risk, 9)
        paint_level(ws.cell(i, 13), level, 9)
    ws.freeze_panes = "H5"
    ws.auto_filter.ref = f"A4:{get_column_letter(len(cols))}{len(data) + 4}"
    widths(ws, col_widths)
    print_setup(ws, "3:4")


def sheet_ai_detail(wb, ai_src, ai_sum):
    back = {m: e["id"] for e in ai_sum for m in e["members"]}
    data = []
    for k, d in ai_src["lv3"].items():
        vals = [back[k], LV0["ai"], d["도메인 (Lv1)"], d["UT-ID"], d["위협 분류 (Lv2)"], k, d["세부 위협 (Lv3)"],
                d["요약설명"], d["참조"], d["발생가능성"], d["심각도"], d["위험도"], d["근거 수준"], d["실제 사고 수"],
                d["심각도 근거"], d["주 공격 단계"], d["ATLAS 기법 (주)"], d["OWASP 매핑 (주)"], d["핵심 통제 요약"],
                ", ".join(d["atlas_incidents"]), d["owasp_incidents"]]
        data.append(("ai", vals, d["위험도"], d["근거 수준"]))
    detail_sheet(wb, "AI 위협 상세", f"원본 그대로: 통합 AI 보안위협 매트릭스 v3.2 LITE 통합매트릭스 Lv3 {len(data)}개 "
                 "(위험도는 원본 수식 값을 정적 값으로 기록) + 통합 위협 ID 역참조 · 실제 사고 수 산정 근거(ATLAS 사고 사례·OWASP 인용)",
                 AI_DETAIL_COLS, data,
                 [("통합 추적", 2, "7B241C"), ("분류 체계 (원본)", 7, "2E5496"), ("위험 평가 (원본)", 6, "A04000"),
                  ("교차 매핑·통제 (원본)", 4, "1F7A8C"), ("실제 사고 근거", 2, "1E8449")],
                 [10, 11, 18, 7, 16, 8, 18, 50, 80, 7, 7, 9, 11, 7, 22, 16, 22, 13, 30, 16, 8])


def sheet_cloud_detail(wb, cl_src, cl_sum):
    back = {m: e["id"] for e in cl_sum for m in e["members"]}
    data = []
    for r in cl_src["rows"]:
        tid = str(r["ATT&CK ID"])
        vals = [back[tid], LV0["cloud"], r["도메인(Lv1)"], tid.split(".")[0], r["위협분류(Lv2)"], r["CTC-ID"],
                r["세부위협(Lv3)"], r["요약설명"], r["참조"], r["발생가능성"], r["심각도"], r["위험도"], r["근거 수준"],
                r["실제 사고 수"], r["심각도 근거"]] + [r[c] for c in CLOUD_SRC_TAIL]
        data.append(("cloud", vals, r["위험도"], r["근거 수준"]))
    detail_sheet(wb, "클라우드 위협 상세", f"원본 그대로: 통합 클라우드 보안위협 매트릭스 v5 통합 매트릭스 {len(data)}행 "
                 "(전술 중복 행 포함) + 통합 위협 ID 역참조. Lv2 ID는 ATT&CK 상위기법 ID",
                 CLOUD_DETAIL_COLS, data,
                 [("통합 추적", 2, "7B241C"), ("분류 체계 (원본)", 7, "2E5496"), ("위험 평가 (원본)", 6, "A04000"),
                  ("기법·교차 매핑 (원본)", 12, "1F7A8C"), ("실제 근거 (원본)", 7, "1E8449"), ("탐지·대응", 1, "6C3483")],
                 [10, 11, 15, 8, 20, 12, 22, 48, 60, 7, 7, 9, 11, 7, 24,
                  10, 12, 12, 11, 14, 14, 10, 24, 18, 20, 20, 16, 28, 8, 7, 7, 14, 22, 26, 48])


def sheet_mapping(wb, maps):
    ws = wb.create_sheet("부록-재구성 매핑")
    cols = ["구분(Lv0)", "원본 도메인(Lv1)", "원본 ID(Lv3)", "ATT&CK ID", "원본 세부 위협(Lv3)", "원본 위험도",
            "통합 위협 ID", "통합 세부 위협(Lv3)", "통합 도메인(Lv1)", "처리 유형", "통합 근거"]
    kinds = collections.Counter(m[9].split(" · ")[0].split("(")[0] for m in maps)
    title(ws, "부록 — 재구성 매핑 (원본 Lv3 → 통합 요약 Lv3)",
          f"AI {sum(m[0] == LV0['ai'] for m in maps)}개 · 클라우드 {sum(m[0] == LV0['cloud'] for m in maps)}행 전수 | "
          + " · ".join(f"{k} {v}" for k, v in kinds.most_common()), len(cols))
    groups(ws, 3, [("원본", 6, "2E5496"), ("통합 요약", 3, "7B241C"), ("재구성", 2, "1F7A8C")])
    header(ws, 4, cols)
    for i, m in enumerate(maps, 5):
        put_row(ws, i, m, 9)
        ws.cell(i, 1).fill = fill(LV0_FILL["ai" if m[0] == LV0["ai"] else "cloud"])
        paint_risk(ws.cell(i, 6), m[5], 9)
        ws.cell(i, 7).font = font(9, True)
        if not m[9].startswith(("단독", "유사")):
            ws.cell(i, 10).font = font(9, True, "A04000")
    ws.freeze_panes = "D5"
    ws.auto_filter.ref = f"A4:{get_column_letter(len(cols))}{len(maps) + 4}"
    widths(ws, [11, 20, 12, 10, 28, 9, 10, 26, 22, 22, 70])
    print_setup(ws, "3:4")


CRITERIA = [
    ("■ 1. 재구성 원칙", None),
    ("단위", "원본 Lv3(AI 124개, 클라우드 고유 기법 126개·154행)를 공격 메커니즘·대상·통제가 같은 것끼리 묶어 요약 Lv3로 재구성 "
             "(AI 61개, 클라우드 52개). 원본 Lv2는 요약표에서 생략하고 원본 상세 시트로 추적"),
    ("통합 기준", "같은 공격 흐름의 연속 단계이거나, 대상만 다른 같은 기법이거나, 같은 통제로 막히는 위협을 통합. 피해 규모·근거가 뚜렷이 "
                "다른 위협(예: 코드 저장소·CRM·DB 수집)은 분리 유지"),
    ("클라우드 전술 중복", "ATT&CK에서 여러 전술에 걸친 기법(원본의 중복 행)은 주 전술 1곳에만 배치하고 나머지는 '공격 단계'의 연관 전술로 표기: "
                       "T1078→초기 침투, T1133→초기 침투, T1053→지속성, T1072→실행, T1098.x→지속성(T1098.003만 권한 상승), "
                       "T1543.005→지속성, T1556.x→지속성, T1484.x→권한 상승, T1557→자격증명 접근"),
    ("경계 이동", "도메인·전술 경계를 넘긴 6건: T1684.x 은닉→초기 침투, T1546 지속성·권한 상승→실행, T1525 지속성→실행, "
                "T1550.x 횡적 이동→자격증명 접근, AZT704 영향→수집, AI UT-14.2 D04→D06"),
    ("단독 유지", "다른 항목과 메커니즘·통제가 달라 묶을 대상이 없는 항목. '통합 근거'에 '단독 유지 — 사유'로 기록"),
    ("■ 2. 위험 평가 (요약 Lv3 재산정)", None),
    ("발생가능성", "상: 구성 원본의 실제 사고(중복 제거 합집합) 2건 이상 / 중: 1건, 또는 구성 원본 중 발생가능성 '중' 이상이 있음 / 하: 그 외"),
    ("실제 사고 수", "AI: ATLAS Incident 유형 사례 ID(중복 제거) + 원본 OWASP 인용 사고 수 합. 클라우드: 사고 DB 680건 중 집계 대상 "
                  "유형(사고·캠페인·사례연구(익명)·규제공시(8-K)·위협인텔 보고서, 집계 포함=Y)의 사고 ID(중복 제거)"),
    ("심각도", "구성 원본 심각도의 최댓값"),
    ("위험도", "발생가능성 × 심각도 3×3: 상×상 매우 높음 / 상×중·중×상 높음 / 중×중·상×하·하×상 보통 / 그 외 낮음 (원본 두 매트릭스와 같은 표)"),
    ("근거 수준", "구성 원본 중 가장 강한 수준: 실제 사고 확인 > 실사용 기법 포함 > 실증·공개 취약점 > 이론·시나리오"),
    ("Lv0 간 비교 유의", "클라우드는 사고 DB(680건) 기반이라 실제 사고 근거가 AI(ATLAS 사례·OWASP 인용)보다 촘촘함. "
                       "위험도·사고 수는 같은 Lv0 안에서 비교하고, AI와 클라우드의 등급을 직접 비교하지 않음"),
    ("■ 3. 문안 작성 기준", None),
    ("위협 설명", "'- '로 시작하는 2줄. 1줄: 공격 방법·대상·결과를 담아 '~위협'으로 종결. 2줄: 영향·발생 조건·탐지 곤란 사유"),
    ("공격 시나리오", "1~2줄, 'A → B → C' 단계 흐름. 구성 원본의 참조·사례에 있는 경로만 사용"),
    ("대표 사례", "1~2줄, '[유형] 사례명(시점): 요지'. 구성 원본 참조에 있는 사례만 쓰며(빌드 검증기가 사례명·시점·유형 대조), "
              "실제 사고를 우선하고 같은 사고가 여러 행에 반복되지 않게 배치. 원본에 사례가 없으면 '공개 사고 미확인 — 사유'"),
    ("대응 방안", "2~3줄 명사형. 예방(권한·구성) → 차단·보호 → 탐지 순"),
    ("관련 기준", "AI: OWASP 주 매핑 + ATLAS 기법(상위 ID). 클라우드: ATT&CK ID(상위기법별 축약) + CSA Top Threats 2026 이슈 ID. "
              "CSA·CCM 문서 내용은 싣지 않고 연계 ID만 표기"),
    ("연계 위협", "AI↔클라우드 교차 연계. 클라우드 원본 'AI 매트릭스 연계(UT)' 열과 요약 작성 시 검토한 연계를 양방향으로 표기"),
    ("■ 4. 사례 유형", None),
    ("[실제 사고]", "공개 보도·공시·위협 인텔로 확인된 실제 침해·악용 (AI: ATLAS Incident·OWASP 인용 사고, 클라우드: 사고 DB 집계 대상)"),
    ("[공개 취약점]", "CVE·공개 보안 권고로 확인된 취약점"),
    ("[실증]", "연구·레드팀·벤더가 실제 제품에서 재현한 공격 (원본 '실증·연구' 포함)"),
    ("[ATT&CK 사례]", "MITRE ATT&CK에 기록된 그룹·소프트웨어·캠페인의 해당 기법 사용 사례"),
    ("[시나리오]", "OWASP 등 기준 문서의 가상 공격 시나리오"),
    ("■ 5. 용어", None),
    ("자격증명", "credential. 비밀번호·액세스 키·토큰·인증서 등 인증 수단 전체 (인증정보·크리덴셜 대신 사용)"),
    ("반출 / 유출", "반출: 공격자가 데이터를 밖으로 빼내는 행위(Exfiltration) / 유출: 데이터가 외부로 새어 나간 결과"),
    ("에이전트", "LLM이 도구 호출·코드 실행·외부 시스템 연동으로 작업을 자율 수행하는 AI 시스템"),
    ("제어 평면 / 데이터 평면", "클라우드 자원을 만들고 설정하는 관리 API 계층 / 워크로드·데이터에 직접 접근하는 계층"),
]


def sheet_criteria(wb):
    ws = wb.create_sheet("부록-작성·평가 기준")
    title(ws, "부록 — 작성·평가 기준", "요약 Lv3 재구성·위험 재산정·문안 작성 규칙 (원본 산정 규칙은 각 원본 워크북의 평가 기준 시트 참조)", 2)
    r = 4
    for k, v in CRITERIA:
        if v is None:
            c = ws.cell(r, 1, k)
            c.font = font(11, True, NAVY)
            r += 1
            continue
        put_row(ws, r, [k, v])
        ws.cell(r, 1).font = font(10, True)
        ws.cell(r, 1).fill = fill("F2F3F4")
        r += 1
    widths(ws, [20, 120])
    print_setup(ws, paper="A4")


def sheet_overview(wb, rows, ai_src, cl_src, maps, today):
    ws = wb.create_sheet("개요", 0)
    ws.cell(1, 1, f"통합 AI·클라우드 보안위협 매트릭스 {VERSION}").font = font(16, True, NAVY)
    ws.cell(2, 1, f"컨설팅 보고서용 요약 위협 매트릭스 | 작성 {today}").font = font(10, color="404040")
    r = 4

    def section(text):
        nonlocal r
        ws.cell(r, 1, text).font = font(12, True, NAVY)
        r += 1

    def line(k, v=""):
        nonlocal r
        ws.cell(r, 1, k).font = font(10, True)
        ws.cell(r, 1).alignment = Alignment(vertical="top")
        c = ws.cell(r, 2, v)
        c.font, c.alignment = font(10), Alignment(wrap_text=True, vertical="top")
        r += 1

    ai_n = sum(x["kind"] == "ai" for x in rows)
    cl_n = sum(x["kind"] == "cloud" for x in rows)
    section("■ 목적")
    line("", "AI 보안위협과 클라우드 보안위협을 하나의 체계(Lv0 구분 → Lv1 도메인 → Lv3 세부 위협)로 요약·통합해, 보고서에 바로 "
             "쓸 수 있는 위협 목록·위험 평가·대표 사례·대응 방안을 제공. 원본 상세 내용은 별도 시트로 함께 수록해 근거를 추적")
    r += 1
    section("■ 원본 (각 원본 데이터를 그대로 사용)")
    line("AI 보안위협", f"통합 AI 보안위협 매트릭스 v3.2 LITE — Lv1 도메인 10 · Lv2 36 · Lv3 {len(ai_src['lv3'])} | MITRE ATLAS "
                    "v2026.09 · OWASP LLM Top 10 2026 · Agentic Top 10 2026 · GenAI Data Security 2026 v1.0 · MCP Top 10(2025 beta)")
    line("클라우드 보안위협", f"통합 클라우드 보안위협 매트릭스 v5 — ATT&CK 전술 14 · Lv3 {len(cl_src['rows'])}행(고유 기법 "
                       f"{len(cl_src['tech'])}개) | ATT&CK Cloud v19.2 · AWS TTC · Azure ATRM · Kubernetes · CSA Top Threats 2026 · "
                       "클라우드 보안사고 DB 680건")
    r += 1
    section("■ 구조")
    line("Lv0 구분", "AI 보안위협 / 클라우드 보안위협")
    line("Lv1 도메인", f"AI: 원본 10개 도메인(D01~D10) / 클라우드: 원본 ATT&CK 14개 전술(RD~IM) 유지")
    line("Lv3 세부 위협", f"원본 Lv3를 내용 분석 후 재구성·재작성 — AI {len(ai_src['lv3'])} → {ai_n}개, 클라우드 "
                       f"{len(cl_src['rows'])}행({len(cl_src['tech'])}기법) → {cl_n}개, 합계 {ai_n + cl_n}개")
    line("요약 열", "위협 설명 · 공격 시나리오 · 대표 사례 · 위험 평가(발생가능성·심각도·위험도·근거 수준·실제 사고 수) · 대응 방안 · "
                  "공격 단계 · 관련 기준 · 연계 위협 · 원본 Lv3 ID")
    r += 1
    section("■ 결과 요약")
    cols = ["구분(Lv0)", "원본 Lv3", "요약 Lv3", "매우 높음", "높음", "보통", "낮음", "실제 사고 확인", "실사용 기법 포함",
            "실증·공개 취약점", "이론·시나리오"]
    for j, c in enumerate(cols, 1):
        cell = ws.cell(r, j, c)
        cell.fill, cell.font, cell.alignment, cell.border = fill(HDR), font(10, True, "FFFFFF"), CENTER, BORDER
    for k, col in zip(common.RISK_ORDER, range(4, 8)):
        ws.cell(r, col).fill, ws.cell(r, col).font = fill(RISK_COLOR[k][0]), font(10, True, RISK_COLOR[k][1])
    r += 1
    for kind, n_src in [("ai", len(ai_src["lv3"])), ("cloud", f"{len(cl_src['rows'])}행 / {len(cl_src['tech'])}기법")]:
        items = [x for x in rows if x["kind"] == kind]
        risk = collections.Counter(x["ev"]["risk"] for x in items)
        lvl = collections.Counter(x["ev"]["evidence"] for x in items)
        vals = [LV0[kind], n_src, len(items)] + [risk[k] for k in common.RISK_ORDER] + [lvl[k] for k in common.EVIDENCE_ORDER]
        for j, v in enumerate(vals, 1):
            c = ws.cell(r, j, v)
            c.font, c.alignment, c.border = font(10, j == 1), CENTER, BORDER
        ws.cell(r, 1).fill = fill(LV0_FILL[kind])
        r += 1
    kinds = collections.Counter(m[9].split(" · ")[0].split("(")[0] for m in maps)
    line("재구성 유형", " · ".join(f"{k} {v}" for k, v in kinds.most_common()) + " (원본 Lv3 단위, '부록-재구성 매핑' 시트)")
    r += 1
    section("■ 위험도 산정 (발생가능성 × 심각도, 원본 두 매트릭스와 같은 표)")
    for j, c in enumerate(["발생가능성 \\ 심각도", "상", "중", "하"], 1):
        cell = ws.cell(r, j, c)
        cell.fill, cell.font, cell.alignment, cell.border = fill(HDR), font(10, True, "FFFFFF"), CENTER, BORDER
    r += 1
    for lik in ["상", "중", "하"]:
        c = ws.cell(r, 1, lik)
        c.font, c.fill, c.alignment, c.border = font(10, True), fill("F2F3F4"), CENTER, BORDER
        for j, sev in enumerate(["상", "중", "하"], 2):
            c = ws.cell(r, j, common.risk_of(lik, sev))
            paint_risk(c, common.risk_of(lik, sev))
            c.border = BORDER
        r += 1
    line("", "발생가능성 — 상: 구성 원본의 실제 사고(중복 제거) 2건 이상 · 중: 1건, 또는 구성 원본 중 '중' 이상 · 하: 그 외 | "
             "심각도 — 구성 원본 최댓값 | 근거 수준 — 구성 원본 중 가장 강한 수준")
    r += 1
    section("■ 시트 안내")
    for k, v in [("통합 요약 매트릭스", "보고서용 본표 — Lv0·Lv1·Lv3 위협별 설명·시나리오·사례·위험 평가·대응 방안"),
                 ("매트릭스 뷰", "Lv0별로 도메인(열)마다 요약 위협을 위험도 색으로 배치한 한눈 보기"),
                 ("도메인 요약", "Lv1 도메인별 원본·요약 항목 수, 위험도 분포, 주요 고위험 위협"),
                 ("AI 위협 상세", "AI 원본 Lv3 124개 원문 그대로 + 통합 위협 ID 역참조·실제 사고 산정 근거"),
                 ("클라우드 위협 상세", "클라우드 원본 154행 원문 그대로 + 통합 위협 ID 역참조"),
                 ("부록-재구성 매핑", "원본 Lv3 → 요약 Lv3 대응, 처리 유형(단독·통합·전술 중복·이동)과 통합 근거"),
                 ("부록-작성·평가 기준", "재구성 원칙, 위험 재산정 규칙, 문안·사례 표기 기준, 용어")]:
        line(k, v)
    r += 1
    section("■ 활용 시 유의사항")
    for v in ["위험도·실제 사고 수는 같은 Lv0 안에서 비교 — 클라우드는 사고 DB 기반이라 AI보다 실제 사고 근거가 촘촘함",
              "요약의 위험도는 구성 원본에서 재산정한 값(규칙: 부록-작성·평가 기준). 원본 개별 값은 원본 상세 시트에 그대로 유지",
              "대표 사례는 구성 원본 참조에 수록된 사례만 사용(빌드 시 자동 대조) — 새로운 사실을 추가하지 않음",
              "CSA Top Threats·CCM은 연계 ID만 표기(문서 내용 재배포 없음). 원본 상세 시트의 CSA 열은 원본 표기를 그대로 둠",
              "모든 값은 정적 값(수식 없음). 재생성: python3 integrated/scripts/build_integrated_matrix.py"]:
        line("·", v)
    widths(ws, [20, 14, 10, 10, 9, 9, 9, 13, 13, 13, 12])
    print_setup(ws, paper="A4")
    # 서술형 줄은 B~K 병합으로 폭 확보 (결과 요약 표 행 제외)
    for row in range(4, r):
        if ws.cell(row, 2).value and isinstance(ws.cell(row, 2).value, str) and ws.cell(row, 3).value is None \
                and len(ws.cell(row, 2).value) > 14:
            ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=11)
            ws.row_dimensions[row].height = 15 * (1 + len(ws.cell(row, 2).value) // 95)


# ---------------------------------------------------------------- 요약 목록 (Markdown, 저장소에서 바로 보기용)
def write_markdown(path, rows, ai_src, cl_src):
    out = [f"# 통합 AI·클라우드 보안위협 요약 목록 {VERSION}", "",
           "> 빌드 산출물(`build_integrated_matrix.py`가 생성) — 직접 고치지 말고 `integrated/data/` 문안을 고친 뒤 다시 빌드",
           "", "| 구분 | 위협 수 | 매우 높음 | 높음 | 보통 | 낮음 |", "|---|---:|---:|---:|---:|---:|"]
    for kind in ["ai", "cloud"]:
        items = [x for x in rows if x["kind"] == kind]
        dist = collections.Counter(x["ev"]["risk"] for x in items)
        out.append(f"| {LV0[kind]} | {len(items)} | " + " | ".join(str(dist[k]) for k in common.RISK_ORDER) + " |")
    for kind, doms in [("ai", ai_src["domains"]), ("cloud", cl_src["tactics"])]:
        out += ["", f"## {LV0[kind]}"]
        for code, label in doms.items():
            items = [x for x in rows if x["kind"] == kind and x["domain"] == code]
            out += ["", f"### {label} ({len(items)})", "",
                    "| 위협 ID | 세부 위협(Lv3) | 위험도 | 근거 수준 | 실제 사고 | 원본 Lv3 |", "|---|---|---|---|---:|---|"]
            for x in items:
                origin = ", ".join(x["members"])
                out.append(f"| {x['id']} | {x['name']} | {x['ev']['risk']} | {x['ev']['evidence']} | "
                           f"{x['ev']['incidents']} | {origin} |")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


# ---------------------------------------------------------------- 산출물 재검증
def verify(path, rows, n_ai, n_cloud_rows, n_maps):
    """저장한 워크북을 다시 열어 시트·행 수·역참조·값 유효성을 확인."""
    import openpyxl
    wb = openpyxl.load_workbook(path)
    expect = ["개요", "통합 요약 매트릭스", "매트릭스 뷰", "도메인 요약", "AI 위협 상세", "클라우드 위협 상세",
              "부록-재구성 매핑", "부록-작성·평가 기준"]
    assert wb.sheetnames == expect, wb.sheetnames
    ids = {r["id"] for r in rows}

    def body(name, ncol):
        ws = wb[name]
        return [[ws.cell(i, j).value for j in range(1, ncol + 1)] for i in range(5, ws.max_row + 1)
                if ws.cell(i, 1).value is not None]

    summ = body("통합 요약 매트릭스", len(SUMMARY_COLS))
    assert len(summ) == len(rows) and {v[2] for v in summ} == ids
    assert all(v[9] in RISK_COLOR and v[10] in LEVEL_COLOR for v in summ)
    for name, n in [("AI 위협 상세", n_ai), ("클라우드 위협 상세", n_cloud_rows)]:
        det = body(name, 14)
        assert len(det) == n and all(v[0] in ids for v in det), name
        assert all(v[11] in RISK_COLOR for v in det), name
    maps = body("부록-재구성 매핑", 11)
    assert len(maps) == n_maps and all(v[6] in ids for v in maps)
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for c in row:
                if isinstance(c.value, str) and c.value.startswith("="):
                    raise AssertionError(f"수식 셀: {ws.title}!{c.coordinate}")
    return len(summ)


# ---------------------------------------------------------------- 실행
def main():
    ai_src, cl_src = common.load_ai(), common.load_cloud()
    ai_sum, cl_sum = common.load_summary()
    errs, warns = common.check_all(ai_src, cl_src, ai_sum, cl_sum)
    for w in warns:
        print("  [경고]", w)
    if errs:
        for e in errs:
            print("  [오류]", e)
        sys.exit(f"검증 오류 {len(errs)}건 — 빌드 중단")
    rows = build_rows(ai_src, cl_src, ai_sum, cl_sum)
    maps = mapping_rows(ai_src, cl_src, ai_sum, cl_sum)
    assert len([m for m in maps if m[0] == LV0["ai"]]) == len(ai_src["lv3"])
    assert len([m for m in maps if m[0] == LV0["cloud"]]) == len(cl_src["rows"])

    today = datetime.date.today().isoformat()
    wb = Workbook()
    wb.remove(wb.active)
    sheet_summary(wb, rows, today)
    sheet_matrix_view(wb, rows, ai_src, cl_src)
    sheet_domain_summary(wb, rows, ai_src, cl_src)
    sheet_ai_detail(wb, ai_src, ai_sum)
    sheet_cloud_detail(wb, cl_src, cl_sum)
    sheet_mapping(wb, maps)
    sheet_criteria(wb)
    sheet_overview(wb, rows, ai_src, cl_src, maps, today)
    for ws, color in zip(wb.worksheets, ["1F3864", "C0392B", "E67E22", "2E5496", "6C3483", "1F618D", "7F8C8D", "7F8C8D"]):
        ws.sheet_properties.tabColor = color
    os.makedirs(OUT_DIR, exist_ok=True)
    wb.save(XLSX)
    with open(CSV, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(SUMMARY_COLS)
        for r in rows:
            w.writerow(summary_values(r))

    write_markdown(MD, rows, ai_src, cl_src)
    n = verify(XLSX, rows, len(ai_src["lv3"]), len(cl_src["rows"]), len(maps))
    print(f"저장: {os.path.relpath(XLSX, common.ROOT)} (재검증 통과: 요약 {n}행)")
    for kind in ["ai", "cloud"]:
        items = [x for x in rows if x["kind"] == kind]
        dist = collections.Counter(x["ev"]["risk"] for x in items)
        lvl = collections.Counter(x["ev"]["evidence"] for x in items)
        print(f"  {LV0[kind]} {len(items)}개 | " + " · ".join(f"{k} {dist[k]}" for k in common.RISK_ORDER)
              + " | " + " · ".join(f"{k} {lvl[k]}" for k in common.EVIDENCE_ORDER))
    print(f"  재구성 매핑 {len(maps)}행 | 연계 위협이 있는 항목 {sum(bool(x['links_text']) for x in rows)}개")


if __name__ == "__main__":
    main()
