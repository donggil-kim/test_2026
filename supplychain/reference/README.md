# 참조 자료 — 통합 소프트웨어 공급망 보안위협 매트릭스

빌드 입력으로 쓰는 원천 자료입니다. 재배포가 허용된 자료만 원본 그대로 두고, 나머지는 ID·명칭만
`data/frameworks.yaml`에 옮기거나 추출 스크립트로 만든 최소 추출본만 둡니다.

## `sap-risk-explorer/` — SAP Risk Explorer for Software Supply Chains

| 파일 | 설명 |
| --- | --- |
| `taxonomy.json` | 공격 트리(AV-000 최상위 → 세부 공격 벡터) |
| `attackvectors.json` | 공격 벡터 52개 — 설명·영향·매핑 대응책(SG) |
| `safeguards.json` | 대응책 43개(SG-001~043) |
| `references.json` | 문헌·사례 379건(태그: peer-reviewed·attack·proof-of-concept 등, AV 매핑) |
| `LICENSE-Apache-2.0.txt` | 원본 라이선스 |

- 원본: [SAP/risk-explorer-for-software-supply-chains](https://github.com/SAP/risk-explorer-for-software-supply-chains)
  `src/data/` (커밋 `79e2a39`, 2026-05-27). Apache-2.0.
- 분류의 학술 근거: Ladisa et al., "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains", IEEE S&P 2023.
- 사용: 세부위협의 'SAP 공격 벡터(AV)' 매핑(52개 전부), 연구·실증 문헌의 '공격 분류 문헌' 근거 집계,
  공격 사례 문헌('attack' 태그 88건)은 사고 DB를 만드는 출발점으로 사용(사고 DB에 원 출처 링크로 반영).

## `advisories/` — CISA KEV

| 파일 | 설명 |
| --- | --- |
| `known_exploited_vulnerabilities.json` | CISA KEV 카탈로그(2026-10-02판, 1,733건). 출처: [cisagov/kev-data](https://github.com/cisagov/kev-data). 미국 정부 저작물(공공 영역) |

공급망 판정(80건)은 `scripts/taxonomy_rules.py`의 `KEV_SUPPLYCHAIN`에 있습니다.

## `attack/` — MITRE ATT&CK Enterprise v19.2 최소 추출본

| 파일 | 설명 |
| --- | --- |
| `enterprise-attack-v19.2-subset.json` | 분류 체계가 쓰는 기법 52개의 명칭·전술·URL과 그 기법을 쓰는 주체(그룹·소프트웨어·캠페인)의 절차 설명, 전체 기법·그룹·소프트웨어·캠페인의 ID→명칭 색인 1,754개(`scripts/validate.py`의 ID 검증용) |

- `scripts/prepare_attack.py`가 저장소 루트의 `enterprise-attack-v19.2.xlsx`에서 만듭니다(폴더만 옮겨도 빌드가 재현되도록).
- MITRE ATT&CK® © The MITRE Corporation — [이용약관](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)

## 이 폴더에 두지 않은 자료(ID·명칭만 `data/frameworks.yaml`에 연계)

| 자료 | 버전 | 출처 | 이용 조건 |
| --- | --- | --- | --- |
| SLSA Threats & mitigations | v1.2 | [slsa-framework/slsa](https://github.com/slsa-framework/slsa) `releases/v1.2` | Community Specification License 1.0 — 명칭·버전·출처 표기 |
| OWASP Top 10 CI/CD Security Risks | 2022 | [OWASP/www-project-top-10-ci-cd-security-risks](https://github.com/OWASP/www-project-top-10-ci-cd-security-risks) | CC BY-SA 4.0 — ID·명칭만 인용 |
| OWASP Top 10 Open Source Software Risks | 2023 | [OWASP/www-project-open-source-software-top-10](https://github.com/OWASP/www-project-open-source-software-top-10) | CC BY-SA 4.0 — ID·명칭만 인용 |
| CNCF Catalog of Supply Chain Compromises | 2025-12 | [cncf/tag-security](https://github.com/cncf/tag-security/tree/main/community/catalog/compromises) | 문서 CC BY 4.0 — 유형명 인용, 사례는 원 출처 링크로 사고 DB에 반영 |
| OpenSSF S2C2F | OpenSSF 이관본 | [ossf/s2c2f](https://github.com/ossf/s2c2f) | Community Specification License 1.0 — 요구사항 ID·제목 |
| OpenSSF Scorecard checks | 2026-10 | [ossf/scorecard](https://github.com/ossf/scorecard) `docs/checks.md` | Apache-2.0 — 점검 항목명 |
| NIST SP 800-53 Rev.5 | OSCAL 5.2.0 | [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content) | 공공 영역 — 통제명 |
| NIST SP 800-218 SSDF | v1.1 | NIST CSRC | 공공 영역 — 실천과제 ID·명칭 |
| OpenSSF Malicious Packages | 커밋 `28e8e300` (2026-10-05) | [ossf/malicious-packages](https://github.com/ossf/malicious-packages) | Apache-2.0 — `scripts/prepare_osv_counts.py`로 생태계·연도별 건수만 추출(`data/osv_malicious_counts.csv`) |

> 이 저장소는 공개 저장소이므로 유료 표준 원문이나 비공개 자료는 올리지 마세요.
