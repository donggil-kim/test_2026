# 참조 자료 — 통합 신원(아이덴티티)·계정 보안위협 매트릭스

빌드 입력으로 쓰는 원천 자료입니다. 재배포가 허용된 자료는 원본 그대로 두거나 최소 추출본만 둡니다. 나머지는 ID·명칭만
`data/frameworks.yaml`에 옮겼습니다. 모든 경로는 `identity/` 폴더 기준이라 폴더째 옮겨도 빌드됩니다.

## `push-bia/` — Browser & Identity Attacks Matrix (Push Security, 구 SaaS Attacks Matrix)

| 파일 | 설명 |
| --- | --- |
| `techniques.json` | 기법 51개(SAT1001~SAT1051) — ID·명칭·전술·요약 첫 문장·앱별 예시 이름·참고 링크·ATT&CK 링크 |
| `LICENSE-CC-BY-4.0.txt` | 원본 라이선스 |

- 원본: [pushsecurity/saas-attacks](https://github.com/pushsecurity/saas-attacks) 커밋 `20bf340`(2026-04-21). CC BY 4.0.
- 추출: `scripts/prepare_push.py`. 예시 파일 속 제3자 앱 화면 캡처는 옮기지 않았습니다.
- 사용처
  - 51개 기법 전부를 세부위협의 'SAT-ID' 열에 매핑합니다.
  - 분류 체계의 누락 점검에 씁니다.
  - 앱별 예시(시연)가 있는 42개 기법(예시 63건)은 '실증' 근거로만 집계합니다. 실제 사고 수에는 넣지 않습니다.
- 저자 스스로 이 매트릭스에 관측 기반 기법만이 아니라 탐색적 기법도 포함된다고 밝혔으므로 실증 이상으로 쓰지 않습니다.

## `advisories/` — CISA KEV

| 파일 | 설명 |
| --- | --- |
| `known_exploited_vulnerabilities.json` | CISA KEV 카탈로그(2026.10.02판, 1,733건). 출처: [cisagov/kev-data](https://github.com/cisagov/kev-data). 미국 정부 저작물(공공 영역) |

- 신원 판정 81건은 `scripts/taxonomy_rules.py`의 `KEV_IDENTITY`에 있습니다(7개 구분, 행 매핑·비고 포함).
- 판정 방식
  - 먼저 인증 계열 CWE 후보와 신원·접근 인프라 제품 후보, 합계 375건을 뽑았습니다.
  - 이를 수동 판정했고, 일반 원격 코드 실행·소비자 기기·OT 기기 취약점은 뺐습니다.
- 공급망 매트릭스(`supplychain/reference/advisories/`)와 같은 판본입니다.

## `attack/` — MITRE ATT&CK Enterprise v19.2 최소 추출본

| 파일 | 설명 |
| --- | --- |
| `enterprise-attack-v19.2-subset.json` | 분류 체계가 쓰는 기법 100개의 명칭·전술·URL과 그 기법을 쓰는 주체 641개(그룹·소프트웨어·캠페인)의 절차 설명, 전체 기법·그룹·소프트웨어·캠페인의 ID→명칭 색인 1,754개(`scripts/validate.py`의 ID 검증용) |

- 추출: `scripts/prepare_attack.py`(공급망 매트릭스와 같은 스크립트). 원천은 저장소 루트의 `enterprise-attack-v19.2.xlsx`입니다.
- v19 체계 변경을 따릅니다.
  - Defense Evasion 전술은 Stealth와 Defense Impairment로 나뉩니다.
  - 기법 ID 변경: T1656 → T1684.001, T1562.008 → T1685.002.
- MITRE ATT&CK® © The MITRE Corporation — [이용약관](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)

## `nist/` — NIST SP 800-53 Rev.5 통제명

| 파일 | 설명 |
| --- | --- |
| `sp800-53r5-names.json` | 통제·보강 통제 ID→영문 명칭 1,196개(OSCAL 5.2.0, 2026-05-11 수정본) |

- 원본: [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) `nist.gov/SP800-53/rev5/json/`. 공공 영역.
- 추출: `scripts/prepare_refs.py --nist <카탈로그 JSON>`. 대응 기준 열의 통제명과 검증기의 ID 존재 확인(IA-13 등 최신 통제 포함)에 씁니다.

## `links/` — 다른 매트릭스 연계 ID

| 파일 | 설명 |
| --- | --- |
| `other_matrices.json` | 연계 ID 223개 — 통합 AI·클라우드·OT 매트릭스 v2 요약 ID(AI- 61 · CL- 52 · OT- 50)와 공급망 매트릭스 v2 세부위협 ID(SCT- 60)의 명칭·위험도 |

- 원천: 이 저장소의 `integrated/output/통합_요약매트릭스_v2.csv`와 `supplychain/data/taxonomy.yaml`. `scripts/prepare_refs.py`로 갱신합니다.
- 사용처: '클라우드·AI·OT·공급망 매트릭스 연계' 열, '다른 매트릭스 연계' 시트, 문구 속 연계 ID 검증.

## 이 폴더에 두지 않은 자료(ID·명칭만 `data/frameworks.yaml`에 연계)

| 자료 | 버전 | 출처 | 이용 조건 |
| --- | --- | --- | --- |
| OWASP Non-Human Identities Top 10 | 2025 | [OWASP/www-project-non-human-identities-top-10](https://github.com/OWASP/www-project-non-human-identities-top-10) | CC BY-SA 4.0 — ID·명칭만 인용 |
| OWASP ASVS | 5.0(커밋 9b5da31) | [OWASP/ASVS](https://github.com/OWASP/ASVS) `5.0/en` | CC BY-SA 4.0 — 장·절 ID·명칭만 인용 |
| OWASP Automated Threats to Web Applications | 커밋 14da2ff(2026-09) | [OWASP/www-project-automated-threats-to-web-applications](https://github.com/OWASP/www-project-automated-threats-to-web-applications) | CC BY-SA 3.0 — OAT ID·명칭만 인용 |
| NIST SP 800-63-4 Digital Identity Guidelines | Revision 4(2025) | [pages.nist.gov/800-63-4](https://pages.nist.gov/800-63-4/) | 공공 영역 — 63A·63B·63C 주제를 매트릭스 자체 주제 코드(예: 63B-RECOV)로 묶어 연계 |
| CSA Cloud Controls Matrix | v4.1.0 | 저장소 루트 `CCMv4.1.0-generated_at_2026_01_13.xlsx` | CSA 이용 조건 — 통제 ID·명칭만 |
| CIS Critical Security Controls | v8.1 | [cisecurity.org/controls](https://www.cisecurity.org/controls) | CC BY-NC-ND 4.0 — 세이프가드 ID·명칭만 |
| ISMS-P 인증기준 | 2023 개정 고시 기준 | [isms.kisa.or.kr](https://isms.kisa.or.kr) | 인증기준 항목 번호·명칭만 |
| 공개 사고 보고·분석 | 2011~2025 | 피해 기관 공지·정부 발표·소송·보안업체 분석 | 사고 DB(`data/incidents.yaml`)에 사고별 '출처 \| URL'로 표기, 원문 비수록 |
