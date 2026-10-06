# 참조 자료 — 물리·인적 보안위협 매트릭스

빌드 입력으로 쓰는 원천 자료입니다. **공개 저장소이므로 유료 표준 원문·비공개 자료·개인정보는 올리지 않습니다.**
재배포가 허용된 자료만 최소 추출본을 두고, 나머지는 ID·명칭만 `data/frameworks.yaml`에 옮겼습니다.
모든 경로는 `physical/` 폴더 기준입니다.

## 한눈에 보기

| 자료 | 역할 | 이용 조건 | 저장소에 두는 것 |
| --- | --- | --- | --- |
| MITRE ATT&CK Enterprise v19.2 | ② 교차 매핑 — 물리·인적 접점 기법 24개 | MITRE 이용약관 — ID·명칭 | `attack/` 최소 추출본 |
| MITRE CTID Insider Threat TTP KB(ITKB) | ② 교차 매핑 — 내부자 관측 기법 표시 | **Apache-2.0** | `itkb/` 추출본 + 라이선스 원문 |
| 다른 매트릭스 ID(아이덴티티·공급망·OT·통합) | ② 교차 매핑 — 연계 열 | 저장소 내부 산출물 | `links/` ID·명칭·위험도 |
| NIST SP 800-53 Rev.5 | ③ 대응 기준 — PE·PS·MP 등 | 공공 영역 | `nist/` 통제명(OSCAL 5.2.0) |
| ISO/IEC 27001:2022 부속서 A 5~7 | ③ 대응 기준 | 유료 표준 — **원문 비수록** | `data/frameworks.yaml` 번호·제목만 |
| ISMS-P 인증기준 2.2~2.4(+관련 항목) | ③ 대응 기준 | 공공 기준 — 번호·명칭 | `data/frameworks.yaml` |
| CERT 내부자 가이드 7판 실천과제 22개 | ③ 대응 기준 | © CMU — 번호·제목 | `data/frameworks.yaml` |
| NPSA 지침 8종 · CISA 지침 2종 · ISO 22341 | ⑤ 참고 문헌 — 분류 근거·위협 내용·대응 문구 | 아래 표 | `data/frameworks.yaml` `references` 카탈로그(서지·URL·확인일)만 |

## `attack/` — MITRE ATT&CK Enterprise v19.2 최소 추출본

| 파일 | 설명 |
| --- | --- |
| `enterprise-attack-v19.2-subset.json` | 분류 체계가 쓰는 기법 24개의 명칭·전술·URL과 그 기법을 쓰는 주체 371개의 절차 설명, 전체 기법·그룹·소프트웨어·캠페인 ID→명칭 색인 1,754개(검증기 ID 확인용) |

- 추출: `scripts/prepare_attack.py`(아이덴티티·공급망 매트릭스와 같은 스크립트). 원천은 저장소 루트의 `enterprise-attack-v19.2.xlsx`입니다.
- ATT&CK은 물리 침입·감시·포섭을 거의 다루지 않습니다. 45개 세부위협 중 연계가 없는 행은 `attack_none`에 미연계 사유를 적었습니다.
- 'ATT&CK 사례 수(물리·인적 맥락)'는 장치 추가·물리 매체·근접 Wi-Fi·하드웨어 공급망·이동식 매체 전파 기법의 절차 전체와,
  위장 프로필·인물 정찰 기법 중 인적 단서(LinkedIn·채용·위장 프로필·직원 식별)가 있는 절차만 셉니다(`scripts/taxonomy_rules.py`).
- MITRE ATT&CK® © The MITRE Corporation — [이용약관](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)

## `itkb/` — MITRE CTID Insider Threat TTP Knowledge Base

| 파일 | 설명 |
| --- | --- |
| `insider-threat-ttp-kb.json` | 내부자 관측 기법 70개(기법 43 · 하위 27, 전술 조합 76행)의 명칭·전술·완화책(M-ID)·데이터 소스(DS-ID), v19.2 대응 ID, 관측 가능한 인적 지표(OHI) 9종 |
| `LICENSE-Apache-2.0.txt` | 원본 라이선스(Apache-2.0) |

- 원본: [center-for-threat-informed-defense/insider-threat-ttp-kb](https://github.com/center-for-threat-informed-defense/insider-threat-ttp-kb) 커밋 `0f816d4`(2026-07-06), ATT&CK v14 기준.
- 추출: `scripts/prepare_itkb.py --repo <클론 경로>`.
- v14 → v19.2 ID 변경 3건을 추출본에 기록했습니다: T1562·T1562.001 → T1685(방어 무력화 전술 신설), T1070.001 → T1685.005.
- 쓰는 자리(D7)
  - 행의 ATT&CK 기법이 이 목록에 있으면 'ITKB' 열에 "내부자 관측 기법"으로 표시하고, 실사용 근거('중' 상한)로 반영합니다.
  - OHI 9종(특권 보유·모니터링 상태·원격 근무·성과 개선 계획·직무 이직률·근속 기간·관리 직급·연차·보안 인가)은 IN 행 탐지 문구의 참고 자료로만 씁니다.
    OHI는 객관적 행동·직무 사실만 다루며 출신·종교·성별 등 보호 특성은 쓰지 않습니다(작업방향 9장).
- IT 시스템 위의 내부자 행위만 다루므로 물리 침입·감시·포섭 행에는 걸리지 않습니다.

## `nist/` — NIST SP 800-53 Rev.5 통제명

| 파일 | 설명 |
| --- | --- |
| `sp800-53r5-names.json` | 통제·보강 통제 ID→영문 명칭 1,196개(OSCAL 5.2.0, 2026-05-11 수정본) |

- `identity/reference/nist/` 추출본을 `scripts/prepare_refs.py`로 복사했습니다(`--nist <OSCAL 카탈로그>`를 주면 새로 추출). 공공 영역.

## `links/` — 다른 매트릭스 연계 ID

| 파일 | 설명 |
| --- | --- |
| `other_matrices.json` | 연계 ID 429개 — 아이덴티티 v2(IDT- 65) · 공급망 v2(SCT- 60) · OT v5(OTC- 141) · 통합 v2 요약 ID(AI- 61 · CL- 52 · OT- 50)의 명칭·위험도 |

- 원천: 이 저장소의 `identity/`·`supplychain/` 분류 체계와 v2 CSV, `ot/output/통합_OT보안위협_매트릭스_v5.xlsx`, `integrated/output/통합_요약매트릭스_v2.csv`.
  `scripts/prepare_refs.py`로 갱신합니다.

## 참고 문헌(`data/frameworks.yaml` `references`) — 이용 조건과 인용 규칙

| 키 | 자료 | 이용 조건 | 확인 |
| --- | --- | --- | --- |
| NPSA-TOP · DEF · IRMF · HR · CUAS · SI · TR · TBYL | 영국 NPSA(MI5 산하 물리·인적 보호보안 당국, 구 CPNI) 지침 | npsa.gov.uk: Crown copyright(공개 사이트 재이용 조건은 미확인) · GOV.UK 게시본: 기본 OGL v3.0 | 검색 결과 기준(직접 열람 차단). IRMF·Secure Innovation은 영국 정부 웹 아카이브 스냅숏(2026-04-07) 확인 |
| CISA-ITMG | CISA Insider Threat Mitigation Guide(2020-11) · Defining Insider Threats | 미국 정부 저작물(공공 영역) | 검색 결과 기준 |
| CISA-UAS | CISA 무인기 지침 3종(2025-11-19, 탐지 기술·의심 비행 대응·추락 기체 처리) | 미국 정부 저작물(공공 영역) | 검색 결과 기준 |
| ISO-22341 | ISO 22341:2021 환경설계를 통한 범죄 예방(CPTED) | 유료 표준 — 번호·제목만 | 번호·제목 확인 |

- **인용 규칙**(작업방향 6.5.4)
  - 행 데이터: `refs` 필드(0~3개) → 워크북 '참고 문헌' 열. 검증기가 카탈로그 존재를 확인합니다.
  - 문구: `reference`의 ■ 물리 관점과 `detect`의 ■ 대응 끝에 `참고: NPSA 〈적대적 정찰〉` 형식으로만 씁니다. 사례 라벨로 쓰지 않습니다.
  - 요지를 우리말로 의역하고 출처를 표기합니다. 원문 인용은 정의처럼 짧은 문장만 쓰고, PDF·이미지는 저장소에 넣지 않습니다.
  - 영국 제도(국가안보투자법·대드론 법적 권한)는 국내 제도(산업기술보호법·전파법·항공안전법)로 바꿔 쓰거나 "영국 지침"으로 표기합니다.
- 참고 문헌은 지침이지 사고가 아니므로 발생가능성·근거 수준 산정에 넣지 않습니다.
- 같은 약칭의 영국 국가환자안전청(2012년 폐지) 자료와 섞이지 않도록 출처 도메인(npsa.gov.uk·cpni.gov.uk·GOV.UK·mi5.gov.uk)을 확인했습니다.

## 사고 DB 출처

사고 DB(`data/incidents.yaml`)의 사례는 정부 발표·법원 기소문·공신력 있는 보도 등 **공개 출처 URL**을 반드시 함께 적습니다.
개인은 실명을 쓰지 않고("전 직원" 등), 국내 피해 기업명이 공개 발표에 없으면 업종으로만 적습니다.
이 환경에서는 `curl`과 대부분 도메인의 직접 열람이 막혀 있어 웹 검색 결과로 출처를 확인했습니다. 1차 출처를 직접 열지 못한 경우
확인 수준(`verification`)을 그에 맞춰 기록합니다.
