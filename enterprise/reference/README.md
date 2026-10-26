# 참조 자료(reference/) — 출처·라이선스·추출 방법

교차 매핑·근거의 **추출본**만 둡니다. 유료 표준 원문·비공개 자료·개인정보는 올리지 않고 ID·명칭만 연계합니다.
세부위협 문구는 분석가가 새로 작성합니다.

| 경로 | 내용 | 출처 | 이용 조건 | 추출 |
|---|---|---|---|---|
| `attack/enterprise-attack-v19.2-subset.json` | 사용 기법·주체·절차·ID 색인 | 저장소 루트 `enterprise-attack-v19.2.xlsx` | © The MITRE Corporation — [ATT&CK 이용약관](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/), ID·명칭만 | `scripts/prepare_attack.py` |
| `kev/kev-subset.json` | CVE 색인 + 연도별 등재·엣지 비중·같은 해 악용 통계 | 저장소 KEV 사본(2026.10.02, 1,733건) | 미국 정부 저작물(공공 영역) | `scripts/prepare_kev.py` |
| `lolbas/lolbas-subset.json` | LOLBin 245개·명령 분류 | [lolbas-project.github.io](https://lolbas-project.github.io/) | MIT, ID·명칭·분류만 | `scripts/prepare_lolbas.py` |
| `lolbas/loldrivers-subset.json` | 취약/악성 드라이버 706개 분류·ATT&CK 매핑 | [loldrivers.io](https://www.loldrivers.io/) | MIT, ID·명칭·분류만 | `scripts/prepare_lolbas.py` |
| `nist/sp800-53r5-names.json` | NIST SP 800-53 Rev.5 통제명 | usnistgov/oscal-content — `identity/` 추출본 재사용 | 미국 정부 저작물(공공 영역) | `scripts/prepare_refs.py` |
| `links/other_matrices.json` | 통합 v4.1 요약 ID(AI·CL·OT·SC·ID·PH 237개) | `integrated/output/통합_요약매트릭스_v4.1.csv` | 같은 저장소 | `scripts/prepare_refs.py` |

## 재생성

```bash
python3 scripts/prepare_attack.py      # ATT&CK 추출본(--xlsx <경로>, 기본 저장소 루트)
python3 scripts/prepare_kev.py         # KEV 추출본(--src <경로>, 기본 supplychain/ 사본)
python3 scripts/prepare_lolbas.py      # LOLBAS·LOLDrivers 추출본(--lolbas/--loldrivers, 공개 API)
python3 scripts/prepare_refs.py        # NIST 통제명 복사 + 통합 v4.1 연계 ID
python3 scripts/validate.py --strict   # 데이터·문구·시나리오 검증(오류·경고 0)
```

- ATT&CK 주체(그룹·소프트웨어·캠페인) 절차 수를 '최근빈발' 선정 신호로 참고합니다(D5).
- KEV의 경계·엣지 장비 비중(연도별 14~21%)·같은 해 악용 비중은 '엣지 0-day·빠른 n-day' 근거입니다(작업방향 7.2).
- LOLBAS·LOLDrivers 원문(LOLBin 245·드라이버 706)은 용량이 커 저장소에 원문을 복제하지 않고 공개 API에서 추출합니다.
