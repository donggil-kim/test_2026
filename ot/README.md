# 통합 OT/ICS/IoT 보안위협 매트릭스

MITRE ATT&CK for ICS v19.2 킬체인을 뼈대로 하나의 위협 매트릭스로 통합했습니다. 통합 대상은 다음과 같습니다.

- IT/OT 경계에서 쓰이는 Enterprise 기법
- 공개 출처로 새로 구축한 OT 보안사고 DB(85건)
- CISA ICS 권고(3,762건)와 KEV(실제 악용 취약점)
- MITRE EMB3D 임베디드 장치 위협 모델(v3)
- IEC 62443·NIST SP 800-53 요구사항 연계(v4·v5, 명칭 포함)
- OWASP IoT Top 10 교차 매핑·업종별 프로파일(v5)

앞서 만든 **통합 AI 보안위협 매트릭스 v3.2**와 **통합 클라우드 보안위협 매트릭스 v5**의 구조(3계층 분류 → 위험평가 → 실제근거)와 산정 로직을 OT·ICS·IoT에 이식했습니다.

> 위치: 새 저장소를 만들 권한이 없어(GitHub 연동의 저장소 생성 403) `test_2026` 저장소의 `ot/` 폴더에 두었습니다. 모든 경로가 이 폴더 기준의 상대 경로라, 폴더째 새 저장소로 옮겨도 그대로 빌드됩니다.

## 산출물

| 경로 | 설명 |
|---|---|
| `output/통합_OT보안위협_매트릭스_v5.xlsx` | 최신 매트릭스 — v1 골격, v2 문구, v3 EMB3D, v4 표준·시나리오, v5 표준 명칭·OWASP IoT·업종 프로파일 (v1·v2는 이전 버전. v3·v4는 같은 파일명으로 덮어써 따로 남지 않음) |
| `scripts/build_ot_threat_matrix.py` | 빌드 스크립트(원천 자료 → 매트릭스 재생성) |
| `scripts/taxonomy_rules.py` | 전술 코드, OT 특화 검토(편입·통합·제외), 심각도, 자산·Purdue·프로파일, CWE·KEV·EMB3D·키워드 규칙 |
| `scripts/attack_data.py` | ATT&CK for ICS(STIX)·Enterprise(xlsx) 로더 — 완화책의 IEC 62443·NIST 라벨 포함 |
| `scripts/prepare_vuln_evidence.py` | CISA ICS 권고(CSAF 2.0) → `data/ics_advisory_cves.csv` 추출 |
| `scripts/prepare_emb3d.py` | MITRE EMB3D STIX → `data/emb3d.yaml` 최소 추출본(저작권·라이선스 머리말 포함) |
| `scripts/validate.py` | OT 관점 문구 검증(형식·ID 존재·사례 라벨과 근거 일치·EMB3D 정합) |
| `scripts/check_keyword_mapping.py` | 키워드 기반 분석 매핑 누락 점검(검토 보조, 자동 집계 아님) |
| `data/incidents.yaml` | OT 보안사고 DB 85건(공개 출처, 필드 정의는 파일 머리말) |
| `data/text/<전술>.yaml`, `data/text/EMB3D.yaml` | OT 관점 문구 — 요약설명·참조·탐지·대응(작성 규칙은 `IP.yaml` 머리말) |
| `data/emb3d.yaml` | MITRE EMB3D 최소 추출본(`prepare_emb3d.py`로 생성, 직접 수정 금지) |
| `data/scenarios.yaml` | 공격 체인 시나리오(실제 사고 기반 IT→OT 흐름, 단계별 OTC-ID 연결) |
| `data/standards.yaml` | 표준 요구사항 명칭(NIST 800-53 통제명·IEC 62443 SR/CR 제목, 원문 미수록) |
| `data/id_registry.yaml` | OTC-ID 고정 대장(폐지 ID 재사용 안 함) |
| `data/ics_advisory_cves.csv` | CISA ICS 권고 CVE 추출본(CWE·CVSS·공격 경로·KEV 교차) |
| `data/changelog.yaml` | 변경이력(워크북 '변경이력' 시트로 출력) |
| `reference/` | 원천 자료와 구조·문체 참고 양식(`reference/README.md`) |
| `docs/methodology.md` | 방법론·매핑 규칙·한계 상세 |

### 워크북 시트

- **개요**: 기준 데이터, 시트 구성, 분류 체계, 결과 요약, 주의(근거 편중 포함)
- **매트릭스 뷰**: 전술(열)별 세부위협을 위험도 색으로 배치(ATT&CK for ICS Navigator와 같은 배치)
- **통합 매트릭스**: 다섯 열 그룹 전체
  - 분류 체계
  - 교차 매핑(대상 자산·Purdue 계층·적용 프로파일·완화책·클라우드/AI 매트릭스 연계·EMB3D 연계·IEC 62443·NIST 800-53)
  - 위험 평가
  - 실제 근거
  - 탐지·대응
- **통합매트릭스_LITE**: 핵심 열 발췌(필터·보고용)
- **도메인 요약**: 전술별 위험도·근거수준 분포, 매핑 사고 수, 최고위험 항목
- **자산·계층 요약**: ATT&CK ICS 자산 18종·Purdue 계층·적용 프로파일별 위험 분포
- **업종 요약**: 업종(전력·수처리·제조·석유가스·교통·식품·IoT·빌딩)별 실제 사고·영향·대표 세부위협
- **역매핑_사고사례**: 사고 85건과 매핑 기법·매핑 근거(ATT&CK 공식/분석)
- **취약점 근거**: 기법별 공개 취약점·KEV 집계, KEV 판정 내역, CWE 규칙
- **Enterprise 판정**: Enterprise 기법의 편입·통합·제외 판정과 근거
- **EMB3D 판정**: EMB3D 장치 위협 전체의 연계(공식·분석)·신설 판정, 성숙도, CWE·완화책
- **표준 연계**: IEC 62443-3-3·4-2·NIST SP 800-53 요구사항 ↔ 세부위협(요구사항 명칭 포함)
- **OWASP IoT Top10**: OWASP IoT Top 10(2018) 범주 ↔ 세부위협
- **공격 체인 시나리오**: 실제 사고 기반 IT→OT 흐름, 단계별 OTC-ID·탐지 포인트
- **평가 기준**: 산정 규칙, AI·클라우드 매트릭스와의 근거 대응, 사례 라벨
- **변경이력**: 버전별 변경 내역

## 결과 요약 (v3·v4·v5)

- **세부위협**: 141행, 고유 기법 118개, 도메인 13개
  - ICS 기법 111행
  - Enterprise 편입 23행(기법·하위기법 18개)
  - EMB3D 신설 7행(장치 하드웨어 위협)
- **위험도**: 매우 높음 24, 높음 73, 보통 30, 낮음 14
- **근거 수준**: 실제 사고 확인 124, 실사용 기법 포함 5, 실증·공개 취약점 11, 이론·시나리오 1
  - '실제 사고 확인' 비율이 높은 이유와 해석 방법은 `docs/methodology.md` §12를 보세요.
- **EMB3D**: 장치 위협 81개(공식 연계 24·분석 연계 41·신설 16), 110행에 표준 요구사항 연계(명칭 포함)
- **교차 참조**: OWASP IoT Top 10(10개 범주)·업종 프로파일(9개 업종군)
- **OT 관점 문구**: 118/118개 기법 작성, `scripts/validate.py` 통과

## 분류 체계 (ATT&CK for ICS 킬체인 기준)

- **Lv1 도메인**: ATT&CK for ICS 전술 12개에 사전 단계 [RD]를 더한 13개입니다.
  - 순서: `[RD] 자원 개발` → `[IA] 초기 침투` → `[EX] 실행` → `[PE] 지속성` → `[PV] 권한 상승` → `[EV] 회피` → `[DS] 탐색` → `[LM] 횡적 이동` → `[CO] 수집` → `[C2] 명령·제어` → `[IR] 대응 기능 억제` → `[IP] 공정 제어 훼손` → `[IM] 영향`
  - [RD]는 Enterprise TA0042에서 가져왔습니다.
- **Lv2 위협분류**: ATT&CK 기법입니다. 예: `OTC-IP-02` = T0836 운전 파라미터 변조
- **Lv3 세부위협**: 하위기법 또는 기법 자체입니다. 예: `OTC-PE-05.1` = T1694.001 기본 자격증명
  - `.0 (일반·상위기법)` 행은 하위기법으로 특정되지 않은 상위기법 근거를 보존합니다.

각 세부위협에는 다음 열이 붙습니다.

- **교차 매핑**: 대상 자산, Purdue 계층, 적용 프로파일(제어계통·안전계통·원격 필드·감시·운영·IT/OT 경계·IoT·임베디드), 완화책(ATT&CK·EMB3D), 클라우드(CTC)·AI(UT) 매트릭스 연계, OWASP IoT Top10, EMB3D 연계, IEC 62443-3-3·4-2, NIST SP 800-53
- **위험 평가**: 발생가능성 × 심각도 → 위험도
- **실제 근거**: 실제 사고 수, 최근 사고, ATT&CK 사례 수, 공개 취약점, KEV(OT), 실증·연구, 근거 수준, 관련 사례 ID
- **탐지·대응 포인트**

## 재생성

```bash
pip install openpyxl pyyaml
python3 scripts/build_ot_threat_matrix.py    # output/ 에 매트릭스 생성
python3 scripts/validate.py                  # 문구 검증 — 문제가 있으면 종료 코드 1

# (선택) 문구 작성용 근거 정리본: 전술별 ATT&CK 절차·사고·완화책을 마크다운으로 출력
python3 scripts/build_ot_threat_matrix.py --worksheet <출력 폴더>

# (선택) 분석 매핑 누락 점검(검토 보조, 자동 집계 아님)
python3 scripts/check_keyword_mapping.py

# (선택) 취약점 근거 재추출: cisagov/CSAF 저장소의 csaf_files/OT/white를 받은 뒤
python3 scripts/prepare_vuln_evidence.py --csaf <경로>/csaf_files/OT/white

# (선택) EMB3D 추출본 재생성: mitre/emb3d 저장소의 STIX 파일을 받은 뒤
python3 scripts/prepare_emb3d.py --stix <경로>/assets/emb3d-stix-2.x.json
```

## 문구 수정 방법

1. `data/text/<전술 코드>.yaml`에서 기법 ID 키를 고칩니다.
   - 같은 기법이 여러 전술에 나오면 문구 하나를 같이 씁니다.
   - 전술별로 달리 쓰려면 키를 `기법ID@전술코드`로 씁니다.
2. 작성 규칙은 `data/text/IP.yaml` 머리말을 따릅니다.
   - 요약설명은 2줄 개조식입니다.
   - 참조는 `■ OT 관점`과 `■ 실제 사례`로 나눕니다.
   - 탐지·대응은 `■ 탐지`와 `■ 대응`으로 나눕니다.
3. `python3 scripts/validate.py`를 실행합니다. 확인 내용:
   - 사례 라벨이 사고 DB 집계 상태와 맞는지
   - 인용한 사고와 ATT&CK 캠페인·소프트웨어가 해당 기법에 매핑돼 있는지
   - 참조한 ID가 실제로 있는지
4. 빌드를 다시 돌리고 `data/changelog.yaml`에 변경 내역을 남깁니다.

## 로드맵

| 단계 | 내용 | 상태 |
|---|---|---|
| v1 | 골격·근거 집계·위험평가 | 완료 |
| v2 | OT 관점 문구 전 기법, 사례 라벨·검증, 근거 편중 표시 | 완료 |
| v3 | IoT·임베디드 확장: EMB3D 위협 연계·신설, IoT 사고 보강 | 완료 |
| v4 | IEC 62443·NIST 800-53 요구사항 연계(원문 미수록), 키워드 매핑 점검, 공격 체인 시나리오 | 완료 |
| v5 | 표준 요구사항 명칭 보강(NIST OSCAL·IEC 62443), OWASP IoT Top 10 연계, 업종별 프로파일 | 완료 |
| 이후 | NIST SP 800-82r3 대응 지침 연계, IEC 62443 요구사항 한글 번역 다듬기, 업종 가중 위험도 | 자료 확보 시 |

> EMB3D STIX는 `mitre/emb3d`, OWASP IoT Top 10은 `OWASP/www-project-internet-of-things`, NIST 800-53 통제명은 `usnistgov/oscal-content`에서 받아 반영했습니다. NIST SP 800-82r3 원문은 이 환경에서 아직 받지 못했습니다.

## 기준 데이터 / 출처

- **MITRE ATT&CK®** for ICS·Enterprise v19.2 © The MITRE Corporation
  - 이용약관: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- **CISA ICS 권고(CSAF 2.0)·KEV 카탈로그**: 미국 정부 저작물(공공 영역)
  - https://github.com/cisagov/CSAF
  - https://github.com/cisagov/kev-data
- **MITRE EMB3D™** © The MITRE Corporation
  - `data/emb3d.yaml`에 "©2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." 표기와 이용 조건을 포함합니다.
  - 이용 조건: https://emb3d.mitre.org/subtabs/terms-of-use.html — 원본 STIX는 `mitre/emb3d`에서 받습니다.
- **OT 보안사고 DB**: 정부 발표, 보안업체·연구기관 보고서, 언론 등 공개 출처를 종합했습니다. 출처는 각 사고의 `sources`와 '역매핑_사고사례' 시트에 있습니다.
- **IEC 62443·NIST SP 800-53**: 유료·공식 표준이라 원문은 넣지 않고, 완화책에 붙은 요구사항 ID와 공개된 요구사항 제목만 연계합니다(v4·v5). NIST 통제명은 [usnistgov/oscal-content](https://github.com/usnistgov/oscal-content)(공공 영역)에서 추출합니다.
- **OWASP IoT Top 10 (2018)** © OWASP Foundation — [OWASP/www-project-internet-of-things](https://github.com/OWASP/www-project-internet-of-things). 범주명·요약만 연계하고 원문은 수록하지 않습니다.
- **참고 양식**(`reference/style/`): 클라우드 v5·AI v3.2 매트릭스입니다. 구조·문체 참고용이며 데이터를 직접 인용하지 않습니다.

> 이 저장소는 공개 저장소이므로 유료 표준 원문이나 비공개 자료는 올리지 마세요. 위험평가 값은 기준값입니다. 업종·공정·자산 중요도에 맞게 검토한 뒤 사용하세요.
