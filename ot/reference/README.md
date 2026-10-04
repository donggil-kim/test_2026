# 참조 자료 — 통합 OT/ICS/IoT 보안위협 매트릭스

빌드 입력으로 쓰는 원천 자료와 구조·문체 참고 자료입니다. 원문 저작물은 재배포가 허용된 것만 수록합니다.

## `attack-ics/` — MITRE ATT&CK for ICS v19.2

| 파일 | 설명 |
| --- | --- |
| `ics-attack-19.2.json` | ICS 도메인 STIX 2.1 번들(전술 12 · 기법 79 · 하위기법 18 · 자산 18 · 캠페인 8 · 소프트웨어 23 · 그룹 14 · 완화책 52 · 탐지 전략 97). 출처: [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) |

## `attack-enterprise/` — MITRE ATT&CK Enterprise v19.2

| 파일 | 설명 |
| --- | --- |
| `enterprise-attack-v19.2.xlsx` | Enterprise 전체(기법·관계 등). ICS 캠페인·소프트웨어의 Enterprise 절차로 IT/OT 경계 기법을 판정하는 데 사용 |

MITRE ATT&CK® © The MITRE Corporation — 이용약관: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/

## `advisories/` — 실제 악용 취약점

| 파일 | 설명 |
| --- | --- |
| `known_exploited_vulnerabilities.json` | CISA KEV 카탈로그(2026-10-02판, 1,733건). 출처: [cisagov/kev-data](https://github.com/cisagov/kev-data) |

CISA ICS 권고(CSAF 2.0, 2010~2026, 약 100MB)는 용량 때문에 수록하지 않고 `scripts/prepare_vuln_evidence.py`로 추출한
`data/ics_advisory_cves.csv`만 둡니다. 원본: [cisagov/CSAF](https://github.com/cisagov/CSAF) `csaf_files/OT/white`. 미국 정부 저작물(공공 영역).

## MITRE EMB3D (v3)

임베디드 장치 위협 모델입니다. 원본 STIX는 용량·이용 조건상 수록하지 않고, `scripts/prepare_emb3d.py`로 추출한
`data/emb3d.yaml`(ID·명칭·분류·성숙도·CWE·완화책·IEC 62443 매핑)만 둡니다.
원본: [mitre/emb3d](https://github.com/mitre/emb3d) `assets/emb3d-stix-2.x.json`.

EMB3D™ © The MITRE Corporation — 이용 조건: https://emb3d.mitre.org/subtabs/terms-of-use.html
(사본에 저작권 표시·라이선스 문구 포함, EMB3D@mitre.org에 이용 통지 — `data/emb3d.yaml` 머리말에 반영)

## `standards/` — 표준·가이드 (ID 목록만)

IEC 62443·NIST SP 800-53은 유료·공식 표준이므로 원문을 두지 않고, ATT&CK·EMB3D 완화책에 붙은 요구사항 ID만 연계합니다(v4).
다음 자료는 이 환경에서 접속이 차단돼 받지 못했습니다. 필요 시 업로드해 주세요.

- NIST SP 800-82 Rev.3(nvlpubs.nist.gov) — 대응 지침 연계(이후 단계)
- OWASP IoT Top 10(owasp.org) — IoT 점검 항목 연계(이후 단계)

## `style/` — 구조·문체 참고용 (데이터 직접 인용 금지)

| 파일 | 설명 |
| --- | --- |
| `통합_클라우드보안위협_매트릭스_v5.xlsx` | 시트 구성·열 구조·평가 기준의 기준 양식 |
| `통합_AI보안위협_매트릭스_v3.2_LITE.xlsx` | 요약설명·참조 문체와 사례 라벨 규칙의 기준 양식 |
