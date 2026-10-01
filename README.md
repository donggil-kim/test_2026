# 통합 클라우드 보안위협 매트릭스

MITRE ATT&CK Cloud 킬체인을 뼈대로 AWS·Azure·Kubernetes 벤더 위협 매트릭스, CSA Top
Threats to Cloud Computing 2026, 클라우드 보안사고 사례 DB(680건)를 하나로 통합한
위협 매트릭스입니다. 이전에 구축한 **통합 AI 보안위협 매트릭스 v3.2**의 구조(3계층
분류 → 위험평가 → 실제근거)와 산정 로직을 클라우드 보안에 이식했습니다.

## 산출물

| 경로 | 설명 |
|---|---|
| `output/통합_클라우드보안위협_매트릭스_v3.xlsx` | 최종 통합 매트릭스(v1·v2는 이전 버전) |
| `output/threat_text_template.csv` | 요약설명·참조 문구 입력용 템플릿 |
| `scripts/build_cloud_threat_matrix.py` | 빌드 스크립트(소스→매트릭스 재생성) |
| `scripts/taxonomy_rules.py` | 전술 코드·CSA 연계·심각도 기준·폐기 ID 변환표 |
| `data/` | 입력 데이터(사용자 파생본, ATT&CK techniques 원본) |
| `data/threat_text_override.csv` | (선택) 직접 작성한 세부위협명·요약설명·참조 — 있으면 빌드 시 반영 |
| `docs/methodology.md` | 방법론·매핑 규칙 상세 |

### v3 변경 사항

- 세부위협 열 구조: **세부위협(Lv3) → 요약설명 → 참조**. 참조에는 ATT&CK 원문 보충 목록 · 실제 사례(사고 DB) · ATT&CK 사례 · 통합된 기법을 구분해 정리
- 설명이 '…다음과 같은 것들이 있다:'에서 끊기던 문제 수정: 원본 요약이 ATT&CK 설명 첫 문단만 번역해 콜론 뒤 목록이 빠졌던 것이 원인. ATT&CK 원문에서 목록을 복원해 참조 열에 넣고, 빌드 시 ':'로 끝나는 요약을 검사
- 클라우드 특화 검토: 클라우드 맥락이 없는 일반 엔터프라이즈 기법 11개 삭제, 31개 통합(근거·벤더 항목은 대상 행에 합산). 클라우드 전용·M365/Office·K8s/컨테이너 항목은 유지 (206 → 154행, 사고 근거 손실 0건)
- 문구 입력 통로: `data/threat_text_override.csv`(템플릿 `output/threat_text_template.csv`)에 작성한 세부위협명·요약설명·참조를 빌드 시 우선 적용

### 워크북 시트

- **개요** — 기준 데이터, 분류체계, 결과 요약, 주의사항
- **매트릭스 뷰** — 전술(열)별 세부위협을 위험도 색으로 배치한 한눈 보기
- **통합 매트릭스** — 분류체계 · 교차매핑 · 위험평가 · 실제근거 전체(위협 설명·심각도 근거 포함)
- **통합매트릭스_LITE** — 핵심 열 발췌
- **도메인 요약** — 전술별 위험도·근거수준 분포, 매핑 사고 수, 최고위험 항목
- **CSA 2026 연계** — 11대 위협별 연계 세부위협·사고 수
- **역매핑_사고사례** — 사고 680건과 매핑 기법(근거 추적용)
- **평가 기준** — 산정 규칙

### v2 변경 사항

- 상위기법에 달린 근거(사고 태그·ATT&CK 사례·벤더 항목)가 누락되던 문제 수정 → `.0 (일반·상위기법)` 행으로 보존
  (사고 매핑 반영 118건 → 245건, 세부위협 169 → 206행)
- 실제 사고와 연구·노출 사례 분리 집계, 최근(2025~) 사고 수 추가
- '비클라우드 의심' 사고 집계 제외, 폐기 ATT&CK ID(T1562 등) v19.2로 변환
- 위협 설명·심각도 근거·AI 매트릭스 연계(UT) 열 추가
- 발생가능성 규칙을 AI 매트릭스 v3.2와 통일(코드·문서 일치)
- 매트릭스 뷰·도메인 요약·CSA 2026 연계 시트 추가

## 분류 체계 (ATT&CK 킬체인 기준)

- **Lv1 도메인** = ATT&CK 전술 14개 (`[IA] 초기 침투` … `[IM] 영향`)
- **Lv2 위협분류** = ATT&CK 기법 (`CTC-IA-02` = T1190)
- **Lv3 세부위협** = 하위기법 또는 벤더 특화 항목 (`CTC-IA-07.3` = T1078.004). `.0 (일반·상위기법)`은 하위기법으로 특정되지 않은 상위기법 근거

각 세부위협에 **교차매핑**(ATT&CK ID · AWS TTC · Azure ATRM · K8s · CSA Top Threats
2026 연계), **위험평가**(발생가능성×심각도→위험도), **실제근거**(ATT&CK 클라우드 사례 수
· 사고DB 사례 수 · 근거수준 · 관련 사고 ID · 대표 사례)가 붙습니다.

## 재생성

```bash
pip install openpyxl
python scripts/build_cloud_threat_matrix.py   # output/ 에 매트릭스 생성
```

## 기준 데이터 / 출처

- **MITRE ATT&CK** Enterprise v19.2 (Cloud) © The MITRE Corporation —
  https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- **AWS Threat Technique Catalog**, **Azure ATRM**, **Threat Matrix for Kubernetes**
  — 각 저장소 라이선스
- **CSA Top Threats to Cloud Computing 2026**, **CCM v4.1** © Cloud Security Alliance
  — 개인·비상업적 용도, 재배포 금지. 본 저장소에는 **원문을 수록하지 않고 위협 연계(ID)만
  표시**합니다.
- **클라우드 보안사고 DB** — Wiz, ramimac, SEC, GTI 등 공개 출처 종합

> 배포·외부 공유 전 각 출처의 최신 이용약관 표기 문구와 대조하세요. 위험평가 값은 기준값
> 이므로 조직 맥락에 맞게 검토 후 사용하는 것을 권장합니다.
