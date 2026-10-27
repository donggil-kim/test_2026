# 고도화·레거시 우회 엔터프라이즈 침해 보안위협 매트릭스 (enterprise/)

MITRE ATT&CK Enterprise에서 **① 고도화됐고 ② 최근 실제 사례가 많으며 ③ 레거시 보안체계(시그니처 AV·경계 방화벽·레거시 SIEM)로 막기 어려운** 기법을 선별해, **레거시 방어 공백**·**요구 방어 수준**을 축으로 붙인 렌즈 매트릭스입니다. 자산이 무엇이든 "레거시로 막기 어렵다"로 묶습니다.

> **현재 상태: 영역 2 ①~④ 완료 — 2026-10-26.** ①분류·참조·사고 DB · ②v1 빌드 · ③v2 관점 문구·시나리오 · ④통합 v5 뷰.
> 세부위협 51개(전술 12·위협분류), 사고 DB 28건(v3 — 기법 일반 서술 9건 제거·4건 재구성·최근 4건 보강), 관점 문구 51/51, 공격 체인 시나리오 8개, 검증 오류·경고 0(`--strict`).
> **v3 빌드**: 15시트 워크북·CSV — 위험도 매우 높음 6·높음 15·보통 25·낮음 5(심각도 영향만 재판정·빈발 지수·실제 사고 정리 반영). 상위는 랜섬웨어·갈취·대량 반출·MSP 신뢰·복구 방해·웜 등 영향 행이고, 엣지 0-day·EDR 무력화는 높음(발생가능성 상 × 심각도 중, 우선순위는 상위).
> 방법론은 [`docs/methodology.md`](docs/methodology.md), 진행·결정 기록은 [`docs/작업방향.md`](docs/작업방향.md)·[`../emerging/작업방향.md`](../emerging/작업방향.md), 참조 자료는 [`reference/README.md`](reference/README.md).

## 분류 체계 — ATT&CK Enterprise 전술(침투~영향 12개)

| 코드 | 전술 | 세부위협 | 핵심 |
|---|---|---:|---|
| IA | 초기 침투 | 5 | 엣지 0-day·외부 원격 서비스·드라이브바이·이동식 매체·신뢰 관계 |
| EX | 실행 | 4 | PowerShell·WMI·LOLBin·네이티브 API(파일리스) |
| PE | 지속 | 4 | 서비스·자동 실행·예약 작업·계정 조작 |
| PV | 권한 상승 | 4 | 프로세스 인젝션·토큰·UAC·취약점(BYOVD) |
| DE | 방어 회피 | 8 | EDR 무력화(BYOVD)·드라이버·지표 삭제·위장·난독화·인메모리·루트킷·펌웨어 |
| CA | 자격증명 접근 | 4 | LSASS·캐시·Kerberoasting·키로깅 |
| DI | 탐색 | 3 | 호스트·AD 열거·보안 SW 탐색 |
| LM | 측면 이동 | 4 | RDP/SMB·PtH/PtT·도구 전송·원격 취약점 웜 |
| CO | 수집 | 2 | 로컬·공유 수집·스테이징 |
| C2 | 명령·제어 | 6 | 암호화·HTTPS·웹 서비스·도메인 프런팅·인그레스·DNS |
| EF | 반출 | 2 | C2 채널·웹 서비스 경유 |
| IM | 영향 | 5 | 랜섬웨어·복구 방해·파괴·서비스 중지·갈취 |

- ID: `ENT-<전술>-NN`(Lv2)·`ENT-<전술>-NN.m`(Lv3). 고유 축: **레거시 방어 공백 유형**(8종)·**요구 방어 수준**(레거시 / EDR·XDR / 행위·네트워크·아이덴티티).

## 사고 DB

- 24건(v3) — 경계·엣지 0-day(Citrix Bleed·MOVEit·Fortinet·Ivanti·Cisco IOS XE·PAN-OS·ScreenConnect·Cleo), 국가배후 LotL(Volt Typhoon·APT28), 사람 운영 랜섬웨어(Black Basta·Scattered Spider·Akira·LockBit·RansomHub), BYOVD(RansomHub·TrueSight), 웜(NotPetya·WannaCry), 펌웨어(BlackLotus·LoJax·MoonBounce), Cobalt Strike 단속(Operation MORPHEUS), Gamaredon USB. **편재 기법(LOLBin·WMI·Kerberoasting·UAC·지표 삭제 등)은 단독 사건이 아니므로 사고가 아니라 빈발 지수(ATT&CK 절차 수)로 반영**(검토 5.3). 실제 사고 매핑 30/51(국내 SKT·롯데카드 2건, 2025년 이후 6건). CVE는 KEV 목록과 대조.

## 구성·재현

```
enterprise/
  README.md · docs/methodology.md · docs/작업방향.md
  data/   taxonomy.yaml · incidents.yaml · frameworks.yaml · changelog.yaml · text/*.yaml(51) · scenarios.yaml(8)
  scripts/ prepare_attack.py · prepare_kev.py · prepare_lolbas.py · prepare_refs.py · validate.py · taxonomy_rules.py ·
           build_enterprise_threat_matrix.py · build_integrated_view.py
  reference/ attack/ · kev/ · lolbas/ · nist/ · links/ (reference/README.md)
  output/  통합_고도화엔터프라이즈_보안위협_매트릭스_v2.xlsx · .csv · v1.xlsx · .csv (각 15시트)
```

```bash
python3 scripts/prepare_attack.py && python3 scripts/prepare_kev.py && python3 scripts/prepare_lolbas.py && python3 scripts/prepare_refs.py
python3 scripts/validate.py --strict
python3 scripts/build_enterprise_threat_matrix.py --version v2
python3 scripts/build_integrated_view.py   # ④ 통합 v5 뷰
```

## 경계·연계

렌즈 매트릭스라 기존 6개와 겹칩니다 — 재수록 대신 **통합 v4.1 요약 ID(AI·CL·OT·SC·ID·PH)로 연계만**(D9). 범위는 호스트·엔드포인트·네트워크·C2·방어 회피·온프레미스 AD 인접이며, 클라우드·신원·OT·AI·공급망 특화는 연계합니다(D7).

> 위험도·사고 수는 같은 매트릭스 안에서만 비교합니다. 선정·위험 값은 기준값이며 조직 맥락에서 재검토를 권합니다. 벤더·2차 수치는 참고치이고 사고 DB에는 1차 확인 사례만 편입합니다.
