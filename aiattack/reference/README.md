# 참조 자료(reference/) — 출처·라이선스·추출 방법

이 폴더는 교차 매핑·대응 기준·연계 ID의 **추출본**만 둡니다. 유료 표준 원문·비공개 자료·개인정보는 올리지 않고,
프레임워크·표준은 ID·명칭만 연계합니다. 세부위협 문구는 분석가가 새로 작성합니다(원문 미수록).

| 경로 | 내용 | 출처 | 이용 조건 | 추출 |
|---|---|---|---|---|
| `atlas/ATLAS-2026.09.yaml` | MITRE ATLAS 공개 배포본(원본) | [mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data) `dist/v6/ATLAS-latest.yaml`(2026.09, format 6.0.0) | © The MITRE Corporation, 공개 배포본 | 다운로드 사본 |
| `atlas/atlas-2026.09-subset.json` | 사용 기법(명칭·전술·성숙도·ATT&CK 대응)·전체 ID 색인 | 위 원본 | ID·명칭만 | `scripts/prepare_atlas.py` |
| `attack/enterprise-attack-v19.2-subset.json` | AI가 가속하는 ATT&CK 기법·주체·절차·ID 색인 | 저장소 루트 `enterprise-attack-v19.2.xlsx` | © The MITRE Corporation — [ATT&CK 이용약관](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), ID·명칭만 | `scripts/prepare_attack.py` |
| `nist/sp800-53r5-names.json` | NIST SP 800-53 Rev.5 통제명 | [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content)(OSCAL 5.2.0) — `identity/` 추출본 재사용 | 미국 정부 저작물(공공 영역) | `scripts/prepare_refs.py` |
| `links/other_matrices.json` | 통합 v4.1 요약 ID(AI·CL·OT·SC·ID·PH 237개)→명칭·위험도 | `integrated/output/통합_요약매트릭스_v4.1.csv` | 같은 저장소 | `scripts/prepare_refs.py` |

## 재생성

```bash
python3 scripts/prepare_atlas.py     # ATLAS 추출본(원본 갱신은 --src <ATLAS yaml>)
python3 scripts/prepare_attack.py    # ATT&CK 추출본(--xlsx <경로>, 기본 저장소 루트)
python3 scripts/prepare_refs.py      # NIST 통제명 복사 + 통합 v4.1 연계 ID
python3 scripts/validate.py --strict # 데이터 검증(오류·경고 0)
```

- ATLAS 성숙도(Realized·Demonstrated·Feasible)는 발생가능성의 'AI 역량 성숙도' 신호로 참고합니다(D4, `taxonomy_rules.MATURITY_ATLAS`).
- OWASP LLM Top 10(2025)·Agentic 위협은 ID·명칭만 `data/frameworks.yaml`에 두고, 공격에 악용되는 제3자 AI가 있을 때만 연계합니다.
- NIST AI RMF·GenAI 프로파일은 거버넌스 맥락으로 명칭만 연계하고 행 매핑에는 쓰지 않습니다.
