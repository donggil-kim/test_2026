# -*- coding: utf-8 -*-
"""
통합본 v5 — 고도화 엔터프라이즈 침해 '뷰(view) Lv0' 편입 빌더 (작업방향 D9)
----------------------------------------------------------------
고도화 엔터프라이즈 침해 매트릭스는 방어 난이도(레거시 공백)를 축으로 하는 '렌즈 매트릭스'라 기존 6개 매트릭스와 대량 겹친다.
통합본에 일반 Lv0로 더하면 고유 위협 수가 부풀려지므로, 재수록 대신 **뷰(view) Lv0**로 얹어
기존 237개 요약 위협에 연계만 하고 고유 위협 수에는 넣지 않는다(이중계산 방지).

입력(읽기 전용, 기존 산출물 변경 없음)
  · enterprise/data/taxonomy.yaml           — 고도화 엔터프라이즈 침해 세부위협 35개와 통합 v4.1 연계 ID(AI·CL·OT·SC·ID·PH)
  · enterprise/output/..._v2.csv            — 위험도·우선순위(빌드 산정 결과)
  · integrated/output/통합_요약매트릭스_v4.1.csv — 기존 237개 요약 위협(Lv0·명칭·위험도)

출력
  · integrated/output/통합_보안위협_매트릭스_v5_엔터프라이즈뷰.xlsx — 뷰 워크북(개요·뷰·교차·커버리지·평가 기준)
  · integrated/output/통합_엔터프라이즈뷰_v5.md                     — 저장소에서 바로 보는 요약
  · integrated/output/통합_엔터프라이즈뷰_교차_v5.csv               — 렌즈→기존 요약 위협 교차 매핑(diff용)

실행 : python3 enterprise/scripts/build_integrated_view.py   (빌드 전 enterprise/scripts/validate.py --strict 자동 실행)
"""
import collections
import csv
import datetime
import subprocess
import sys
from pathlib import Path

import openpyxl
import yaml
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = Path(__file__).resolve().parents[1]          # enterprise/
REPO = ROOT.parent
TAX = yaml.safe_load((ROOT / "data" / "taxonomy.yaml").read_text(encoding="utf-8"))
AV_CSV = ROOT / "output" / "통합_고도화엔터프라이즈_보안위협_매트릭스_v2.csv"
BASE_CSV = REPO / "integrated" / "output" / "통합_요약매트릭스_v4.1.csv"
OUT_XLSX = REPO / "integrated" / "output" / "통합_보안위협_매트릭스_v5_엔터프라이즈뷰.xlsx"
OUT_MD = REPO / "integrated" / "output" / "통합_엔터프라이즈뷰_v5.md"
OUT_CSV = REPO / "integrated" / "output" / "통합_엔터프라이즈뷰_교차_v5.csv"

LINK_FIELDS = [("ai", "AI 연계"), ("cl", "클라우드 연계"), ("ot", "OT 연계"),
               ("sc", "공급망 연계"), ("idn", "신원 연계"), ("ph", "물리 연계")]
RISK_ORDER = ["매우 높음", "높음", "보통", "낮음"]
RISK_COLOR = {"매우 높음": ("C0392B", "FFFFFF"), "높음": ("E67E22", "FFFFFF"),
              "보통": ("F7DC6F", "000000"), "낮음": ("A9DFBF", "000000")}
NAVY, HDR, GRAY = "1F3864", "34495E", "8C8C8C"
THIN = Side(style="thin", color="D0D0D0")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP = Alignment(wrap_text=True, vertical="top")
CENTER = Alignment(horizontal="center", vertical="center", wrap_text=True)


def run_validate():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate.py"), "--strict"],
                       capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print(r.stdout)
        raise SystemExit("enterprise 검증 오류·경고 — 먼저 해결(--skip 없음)")


def load():
    base = {r["위협 ID"]: r for r in csv.DictReader(open(BASE_CSV, encoding="utf-8-sig"))}
    av = {r["ENT-ID"]: r for r in csv.DictReader(open(AV_CSV, encoding="utf-8-sig"))}
    rows = []
    for d in TAX["domains"]:
        for l2 in d["lv2"]:
            for x in l2["lv3"]:
                links = []
                for fld, _ in LINK_FIELDS:
                    links += list(x.get(fld) or [])
                a = av.get(x["id"], {})
                rows.append(dict(id=x["id"], code=d["code"], domain=f"[{d['code']}] {d['ko']}", name=x["name"],
                                 legacy_gap=" · ".join(x["legacy_gap"]), defense_level=x["defense_level"],
                                 risk=a.get("위험도", ""), rank=a.get("우선순위", ""), links=links))
    return base, rows


def _w(ws, widths):
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w


def _hdr(ws, row, cols):
    for j, c in enumerate(cols, 1):
        cell = ws.cell(row, j, c)
        cell.fill = PatternFill("solid", fgColor=HDR)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.alignment = CENTER
        cell.border = BORDER


def _risk(cell):
    v = cell.value
    if v in RISK_COLOR:
        bg, fg = RISK_COLOR[v]
        cell.fill = PatternFill("solid", fgColor=bg)
        cell.font = Font(bold=v in ("매우 높음", "높음"), color=fg)
    cell.alignment = CENTER


def _row(ws, r, vals):
    for j, v in enumerate(vals, 1):
        c = ws.cell(r, j, v)
        c.alignment = WRAP
        c.border = BORDER


def build(base, rows):
    wb = openpyxl.Workbook()
    today = datetime.date.today().isoformat()
    touched = collections.OrderedDict()   # base id -> set(AIA ids)
    for o in rows:
        for k in o["links"]:
            touched.setdefault(k, set()).add(o["id"])
    base_lv0 = collections.Counter(base[k]["구분(Lv0)"] for k in base)
    touch_lv0 = collections.Counter(base[k]["구분(Lv0)"] for k in touched if k in base)
    rc = collections.Counter(o["risk"] for o in rows)

    # ---------------- 개요 ----------------
    ws = wb.active
    ws.title = "개요"
    meta = [
        ("통합 보안위협 매트릭스 v5 — 고도화 엔터프라이즈 침해 뷰(view) Lv0", ""),
        ("무엇", "기존 통합본 v4.1(요약 위협 237개, 6개 Lv0)에 '고도화 엔터프라이즈 침해' 매트릭스를 뷰(view) Lv0로 얹은 레이어"),
        ("왜 뷰인가(D9)", "고도화 엔터프라이즈 침해는 방어 난이도(레거시 공백)를 축으로 하는 렌즈 매트릭스라 기존 6개와 대량 겹침. 일반 Lv0로 더하면 "
                       "고유 위협 수가 부풀려지므로, 재수록 대신 연계만 하고 고유 위협 수에는 넣지 않음"),
        ("고유 위협 수", f"통합 v4.1 기준 그대로 유지(변동 없음) — 뷰 레이어 {len(rows)}개는 고유 위협 수에 더하지 않음"),
        ("생성일", today),
        ("", ""),
        ("■ 뷰 레이어 요약", ""),
        ("고도화 엔터프라이즈 침해 세부위협", f"{len(rows)}개(ATT&CK 전술 12단계) — 위험도 " + " · ".join(f"{k} {rc.get(k,0)}" for k in RISK_ORDER)),
        ("기존 요약 위협 연계", f"기존 237개 중 {len(touched)}개를 고도화 엔터프라이즈 침해 렌즈가 닿음(연계). 나머지는 이 렌즈 밖"),
        ("Lv0별 연계(닿는 요약 위협 수)", " · ".join(f"{k} {touch_lv0.get(k,0)}/{base_lv0[k]}" for k in base_lv0)),
        ("", ""),
        ("■ 시트", ""),
        ("고도화 엔터프라이즈 침해 뷰", "뷰 Lv0의 세부위협 51개 — 전술·위험도·레거시 공백 유형·요구 방어 수준·연계 기존 요약 ID"),
        ("렌즈 교차 매핑", "뷰 세부위협 → 연계된 기존 요약 위협(Lv0·명칭·위험도) 전개"),
        ("기존 매트릭스 커버리지", "기존 6개 Lv0별로 고도화 엔터프라이즈 침해 렌즈가 닿는 요약 위협 수·목록"),
        ("평가 기준·메모", "뷰 Lv0 원칙·경계·한계"),
        ("", ""),
        ("■ 주의", ""),
        ("이중계산 금지", "뷰 레이어의 위협은 기존 Lv0 위협과 겹치므로, Lv0를 가로지른 '고유 위협 수'에 더하지 않음. "
                      "위험도·사고 수 비교는 각 매트릭스 안에서만"),
        ("원본 불변", "이 뷰는 기존 통합본 v4.1 산출물을 바꾸지 않는 별도 레이어 — 통합 빌드(build_integrated_matrix.py)와 독립"),
        ("경계", "AI 도구 자체가 오염·위장되는 공급망 위협은 AI 매트릭스 D08·공급망 Lv0에 있음(이 뷰가 아님)"),
    ]
    for i, (a, b) in enumerate(meta, 1):
        ws.cell(i, 1, a).font = Font(bold=a.startswith("■"), color=NAVY if a.startswith("■") else "000000")
        ws.cell(i, 2, b).alignment = WRAP
    ws.cell(1, 1).font = Font(size=14, bold=True, color=NAVY)
    _w(ws, [30, 130])

    # ---------------- 고도화 엔터프라이즈 침해 뷰 ----------------
    ws = wb.create_sheet("고도화 엔터프라이즈 침해 뷰")
    ws.cell(1, 1, "고도화 엔터프라이즈 침해 뷰(view) Lv0 — 고유 위협 수에 더하지 않는 렌즈 레이어").font = Font(size=12, bold=True, color=NAVY)
    cols = ["전술(Lv1)", "ENT-ID", "세부위협(Lv3)", "위험도", "우선순위", "레거시 공백 유형", "요구 방어 수준",
            "연계 기존 요약 위협(ID)", "연계 수"]
    _hdr(ws, 3, cols)
    for r, o in enumerate(sorted(rows, key=lambda o: (RISK_ORDER.index(o["risk"]) if o["risk"] in RISK_ORDER else 9,
                                                      o["id"])), 4):
        _row(ws, r, [o["domain"], o["id"], o["name"], o["risk"], o["rank"], o["legacy_gap"], o["defense_level"],
                     ", ".join(o["links"]), len(o["links"])])
        _risk(ws.cell(r, 4))
        for j in (5, 7, 9):
            ws.cell(r, j).alignment = CENTER
    ws.freeze_panes = "C4"
    ws.auto_filter.ref = f"A3:{get_column_letter(len(cols))}{len(rows) + 3}"
    _w(ws, [16, 13, 30, 9, 7, 26, 16, 40, 7])

    # ---------------- 렌즈 교차 매핑 ----------------
    ws = wb.create_sheet("렌즈 교차 매핑")
    ws.cell(1, 1, "고도화 엔터프라이즈 침해 뷰 세부위협 → 연계된 기존 요약 위협(통합 v4.1)").font = Font(size=12, bold=True, color=NAVY)
    cols = ["ENT-ID", "고도화 엔터프라이즈 침해 세부위협", "ENT 위험도", "연계 기존 Lv0", "기존 요약 ID", "기존 요약 위협", "기존 위험도"]
    _hdr(ws, 3, cols)
    r = 4
    cross_rows = []
    for o in sorted(rows, key=lambda o: o["id"]):
        for k in o["links"]:
            b = base.get(k, {})
            _row(ws, r, [o["id"], o["name"], o["risk"], b.get("구분(Lv0)", "(미확인)"), k,
                         b.get("세부 위협(Lv3)", ""), b.get("위험도", "")])
            _risk(ws.cell(r, 3))
            _risk(ws.cell(r, 7))
            cross_rows.append([o["id"], o["name"], o["risk"], b.get("구분(Lv0)", ""), k,
                               b.get("세부 위협(Lv3)", ""), b.get("위험도", "")])
            r += 1
    ws.freeze_panes = "B4"
    ws.auto_filter.ref = f"A3:{get_column_letter(len(cols))}{r - 1}"
    _w(ws, [13, 30, 9, 18, 14, 34, 9])

    # ---------------- 기존 매트릭스 커버리지 ----------------
    ws = wb.create_sheet("기존 매트릭스 커버리지")
    ws.cell(1, 1, "기존 6개 Lv0별 — 고도화 엔터프라이즈 침해 렌즈가 닿는 요약 위협").font = Font(size=12, bold=True, color=NAVY)
    _hdr(ws, 3, ["기존 Lv0", "요약 위협 수", "렌즈가 닿는 수", "비율(%)", "닿는 요약 위협(ID)"])
    r = 4
    for lv0 in base_lv0:
        ids = sorted(k for k in touched if k in base and base[k]["구분(Lv0)"] == lv0)
        pct = round(100 * len(ids) / base_lv0[lv0]) if base_lv0[lv0] else 0
        _row(ws, r, [lv0, base_lv0[lv0], len(ids), pct, ", ".join(ids)])
        for j in (2, 3, 4):
            ws.cell(r, j).alignment = CENTER
        r += 1
    _row(ws, r, ["합계", sum(base_lv0.values()), len(touched),
                 round(100 * len(touched) / sum(base_lv0.values())), ""])
    ws.cell(r, 1).font = Font(bold=True)
    for j in (2, 3, 4):
        ws.cell(r, j).alignment = CENTER
    _w(ws, [20, 11, 12, 9, 90])

    # ---------------- 평가 기준·메모 ----------------
    ws = wb.create_sheet("평가 기준·메모")
    notes = [
        ("■ 뷰(view) Lv0 원칙(D9)", ""),
        ("정의", "방어 난이도(레거시 공백)를 축으로 하는 렌즈 매트릭스를 통합본에 얹되, 기존 Lv0 위협과의 겹침을 연계로만 표시하는 레이어"),
        ("고유 위협 수", "뷰 레이어는 고유 위협 수에 더하지 않음 — 통합 v4.1의 고유 위협 수(추정)는 그대로"),
        ("연계 ID", "고도화 엔터프라이즈 침해 세부위협의 ai·cl·ot·sc·idn·ph 연계가 통합 v4.1 요약 ID(AI·CL·OT·SC·ID·PH)를 가리킴"),
        ("비교 규칙", "위험도·사고 수는 각 매트릭스 안에서만 비교(매트릭스 간 합산·직접 비교 금지)"),
        ("", ""),
        ("■ 경계", ""),
        ("AI 매트릭스와의 구분", "AI 매트릭스(Lv0=AI)는 방어자의 AI가 공격받는 관점, 이 뷰는 공격자의 AI가 대상을 치는 관점"),
        ("공급망", "AI 도구 자체가 오염·위장되는 위협은 AI D08·공급망 Lv0에 있음(이 뷰가 아님)"),
        ("", ""),
        ("■ 한계", ""),
        ("렌즈 커버리지", "고도화 엔터프라이즈 침해은 신흥·빠른 변화 영역이라 기존 요약 위협과의 연계는 현재 확인된 접점 위주 — 역량 성숙도에 따라 넓어질 수 있음"),
        ("독립성", "이 뷰는 통합 빌드(build_integrated_matrix.py)와 독립된 별도 산출물 — v4.1 워크북·CSV를 바꾸지 않음"),
    ]
    for i, (a, b) in enumerate(notes, 1):
        ws.cell(i, 1, a).font = Font(bold=a.startswith("■"), color=NAVY if a.startswith("■") else "000000")
        ws.cell(i, 2, b).alignment = WRAP
    _w(ws, [26, 120])

    wb.save(OUT_XLSX)
    return touched, base_lv0, touch_lv0, rc, cross_rows


def write_md(touched, base_lv0, touch_lv0, rc, rows):
    today = datetime.date.today().isoformat()
    L = []
    L.append("# 통합 보안위협 매트릭스 v5 — 고도화 엔터프라이즈 침해 뷰(view) Lv0\n")
    L.append(f"> 생성일 {today} · 기존 통합본 v4.1(요약 위협 237개)에 '고도화 엔터프라이즈 침해' 매트릭스를 **뷰(view) Lv0**로 얹은 레이어.\n")
    L.append("## 왜 뷰인가 (D9)\n")
    L.append("고도화 엔터프라이즈 침해는 방어 난이도(레거시 공백)를 축으로 하는 렌즈 매트릭스라 기존 6개 매트릭스와 대량 겹칩니다. "
             "일반 Lv0로 더하면 고유 위협 수가 부풀려지므로 **재수록 대신 연계만** 하고, **고유 위협 수에는 넣지 않습니다**. "
             "통합 v4.1의 고유 위협 수(추정)는 그대로입니다.\n")
    L.append(f"- 고도화 엔터프라이즈 침해 세부위협 **{len(rows)}개**(ATT&CK 전술 12단계) — 위험도 "
             + " · ".join(f"{k} {rc.get(k,0)}" for k in RISK_ORDER) + "\n")
    L.append(f"- 기존 237개 요약 위협 중 **{len(touched)}개**를 고도화 엔터프라이즈 침해 렌즈가 닿음(연계)\n")
    L.append("\n## 기존 매트릭스 커버리지\n")
    L.append("| 기존 Lv0 | 요약 위협 | 렌즈가 닿는 수 | 비율 |")
    L.append("|---|---:|---:|---:|")
    for lv0 in base_lv0:
        pct = round(100 * touch_lv0.get(lv0, 0) / base_lv0[lv0]) if base_lv0[lv0] else 0
        L.append(f"| {lv0} | {base_lv0[lv0]} | {touch_lv0.get(lv0,0)} | {pct}% |")
    tot = sum(base_lv0.values())
    L.append(f"| **합계** | **{tot}** | **{len(touched)}** | **{round(100*len(touched)/tot)}%** |")
    L.append("\n## 산출물\n")
    L.append("- `통합_보안위협_매트릭스_v5_엔터프라이즈뷰.xlsx` — 뷰 워크북(개요·고도화 엔터프라이즈 침해 뷰·렌즈 교차 매핑·기존 매트릭스 커버리지·평가 기준)")
    L.append("- `통합_엔터프라이즈뷰_교차_v5.csv` — 렌즈→기존 요약 위협 교차 매핑")
    L.append("\n> 이 뷰는 통합 빌드와 독립된 별도 레이어로, v4.1 산출물을 바꾸지 않습니다. "
             "위험도·사고 수는 각 매트릭스 안에서만 비교합니다.\n")
    OUT_MD.write_text("\n".join(L), encoding="utf-8")


def write_csv(cross_rows):
    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ENT-ID", "고도화 엔터프라이즈 침해 세부위협", "ENT 위험도", "연계 기존 Lv0", "기존 요약 ID", "기존 요약 위협", "기존 위험도"])
        w.writerows(cross_rows)


def main():
    run_validate()
    base, rows = load()
    touched, base_lv0, touch_lv0, rc, cross_rows = build(base, rows)
    write_md(touched, base_lv0, touch_lv0, rc, rows)
    write_csv(cross_rows)
    print(f"v5 뷰 빌드 완료 — 고도화 엔터프라이즈 침해 뷰 {len(rows)}개 · 기존 요약 연계 {len(touched)}/237 · 교차 {len(cross_rows)}건")
    print(f"  → {OUT_XLSX.relative_to(REPO)}")
    print(f"  → {OUT_MD.relative_to(REPO)} · {OUT_CSV.relative_to(REPO)}")


if __name__ == "__main__":
    main()
