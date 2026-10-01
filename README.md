# 통합 클라우드 보안위협 매트릭스

MITRE ATT&CK Cloud 킬체인을 뼈대로 AWS·Azure·Kubernetes 벤더 위협 매트릭스, CSA Top
Threats to Cloud Computing 2026, 클라우드 보안사고 사례 DB(680건)를 하나로 통합한
위협 매트릭스입니다. 이전에 구축한 **통합 AI 보안위협 매트릭스 v3.2**의 구조(3계층
분류 → 위험평가 → 실제근거)와 산정 로직을 클라우드 보안에 이식했습니다.

## 산출물

| 경로 | 설명 |
|---|---|
| `output/통합_클라우드보안위협_매트릭스_v1.xlsx` | 최종 통합 매트릭스 |
| `scripts/build_cloud_threat_matrix.py` | 빌드 스크립트(소스→매트릭스 재생성) |
| `data/` | 입력 데이터(사용자 파생본) |
| `docs/methodology.md` | 방법론·매핑 규칙 상세 |

### 워크북 시트

- **개요** — 기준 데이터, 분류체계, 커버리지, 주의사항
- **통합 매트릭스** — 도메인(전술)→위협분류(기법)→세부위협(하위기법/벤더)별 전체
  (분류체계 · 교차매핑 · 위험평가 · 실제근거)
- **통합매트릭스_LITE** — 핵심 열 발췌(필터·보고용)
- **역매핑_사고사례** — 사고 680건과 매핑된 ATT&CK 기법/전술(근거 추적용)
- **평가 기준** — 발생가능성·심각도·위험도·근거수준 산정 규칙

## 분류 체계 (ATT&CK 킬체인 기준)

- **Lv1 도메인** = ATT&CK 전술 14개 (`[IA] 초기 침투` … `[IM] 영향`)
- **Lv2 위협분류** = ATT&CK 기법 (`CTC-IA-02` = T1190)
- **Lv3 세부위협** = 하위기법 또는 벤더 특화 항목 (`CTC-IA-04.4` = T1078.004)

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
