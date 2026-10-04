# 통합 OT/ICS/IoT 보안위협 매트릭스

MITRE ATT&CK for ICS v19.2 킬체인을 뼈대로 하나의 위협 매트릭스로 통합했습니다. 통합 대상은 다음과 같습니다.

- IT/OT 경계에서 쓰이는 Enterprise 기법
- 공개 출처로 새로 구축한 OT 보안사고 DB(82건)
- CISA ICS 권고(3,762건)와 KEV(실제 악용 취약점)

앞서 만든 **통합 AI 보안위협 매트릭스 v3.2**와 **통합 클라우드 보안위협 매트릭스 v5**의 구조(3계층 분류 → 위험평가 → 실제근거)와 산정 로직을 OT·ICS·IoT에 이식했습니다.

> 위치: 새 저장소를 만들 권한이 없어(GitHub 연동의 저장소 생성 403) `test_2026` 저장소의 `ot/` 폴더에 두었습니다. 모든 경로가 이 폴더 기준의 상대 경로라, 폴더째 새 저장소로 옮겨도 그대로 빌드됩니다.

## 산출물

| 경로 | 설명 |
|---|---|
| `output/통합_OT보안위협_매트릭스_v2.xlsx` | 최신 매트릭스 — OT 관점 문구 전 기법 작성(v1은 골격·근거 집계본) |
| `scripts/build_ot_threat_matrix.py` | 빌드 스크립트(원천 자료 → 매트릭스 재생성) |
| `scripts/taxonomy_rules.py` | 전술 코드, OT 특화 검토(편입·통합·제외), 심각도 기준, 자산·Purdue·프로파일, CWE·KEV 규칙 |
| `scripts/attack_data.py` | ATT&CK for ICS(STIX)·Enterprise(xlsx) 로더 |
| `scripts/prepare_vuln_evidence.py` | CISA ICS 권고(CSAF 2.0) → `data/ics_advisory_cves.csv` 추출 |
| `scripts/validate.py` | OT 관점 문구 검증(형식·ID 존재·사례 라벨과 근거 일치) |
| `data/incidents.yaml` | OT 보안사고 DB 82건(공개 출처, 필드 정의는 파일 머리말) |
| `data/text/<전술>.yaml` | OT 관점 문구 — 요약설명·참조·탐지·대응(작성 규칙은 `IP.yaml` 머리말) |
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
  - 교차 매핑(대상 자산·Purdue 계층·적용 프로파일·완화책·클라우드/AI 매트릭스 연계)
  - 위험 평가
  - 실제 근거
  - 탐지·대응
- **통합매트릭스_LITE**: 핵심 열 발췌(필터·보고용)
- **도메인 요약**: 전술별 위험도·근거수준 분포, 매핑 사고 수, 최고위험 항목
- **자산·계층 요약**: ATT&CK ICS 자산 18종·Purdue 계층·적용 프로파일별 위험 분포
- **역매핑_사고사례**: 사고 82건과 매핑 기법·매핑 근거(ATT&CK 공식/분석)
- **취약점 근거**: 기법별 공개 취약점·KEV 집계, KEV 판정 내역, CWE 규칙
- **Enterprise 판정**: Enterprise 기법의 편입·통합·제외 판정과 근거
- **평가 기준**: 산정 규칙, AI·클라우드 매트릭스와의 근거 대응, 사례 라벨
- **변경이력**: 버전별 변경 내역

## 결과 요약 (v2)

- **세부위협**: 134행, 고유 기법 111개, 도메인 13개
  - ICS 기법 111행
  - Enterprise 편입 23행(기법·하위기법 18개)
- **위험도**: 매우 높음 24, 높음 70, 보통 29, 낮음 11
- **근거 수준**: 실제 사고 확인 121, 실사용 기법 포함 2, 실증·공개 취약점 5, 이론·시나리오 6
  - '실제 사고 확인' 비율이 높은 이유와 해석 방법은 `docs/methodology.md` §9를 보세요.
- **OT 관점 문구**: 111/111개 기법 작성, `scripts/validate.py` 통과

## 분류 체계 (ATT&CK for ICS 킬체인 기준)

- **Lv1 도메인**: ATT&CK for ICS 전술 12개에 사전 단계 [RD]를 더한 13개입니다.
  - 순서: `[RD] 자원 개발` → `[IA] 초기 침투` → `[EX] 실행` → `[PE] 지속성` → `[PV] 권한 상승` → `[EV] 회피` → `[DS] 탐색` → `[LM] 횡적 이동` → `[CO] 수집` → `[C2] 명령·제어` → `[IR] 대응 기능 억제` → `[IP] 공정 제어 훼손` → `[IM] 영향`
  - [RD]는 Enterprise TA0042에서 가져왔습니다.
- **Lv2 위협분류**: ATT&CK 기법입니다. 예: `OTC-IP-02` = T0836 운전 파라미터 변조
- **Lv3 세부위협**: 하위기법 또는 기법 자체입니다. 예: `OTC-PE-05.1` = T1694.001 기본 자격증명
  - `.0 (일반·상위기법)` 행은 하위기법으로 특정되지 않은 상위기법 근거를 보존합니다.

각 세부위협에는 다음 열이 붙습니다.

- **교차 매핑**: 대상 자산, Purdue 계층, 적용 프로파일(제어계통·안전계통·원격 필드·감시·운영·IT/OT 경계·IoT·임베디드), ATT&CK 완화책, 클라우드(CTC)·AI(UT) 매트릭스 연계
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

# (선택) 취약점 근거 재추출: cisagov/CSAF 저장소의 csaf_files/OT/white를 받은 뒤
python3 scripts/prepare_vuln_evidence.py --csaf <경로>/csaf_files/OT/white
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

| 단계 | 내용 | 필요 자료 |
|---|---|---|
| v1 (완료) | 골격·근거 집계·위험평가 | — |
| v2 (완료) | OT 관점 문구 전 기법, 사례 라벨·검증, 근거 편중 표시 | — |
| v3 | IoT·임베디드 확장: EMB3D 위협 매핑, IoT 사고·취약점 근거 보강 | MITRE EMB3D STIX(이 환경에서 접속 차단 — 업로드 필요), OWASP IoT Top 10 |
| v4 | IEC 62443 요구사항 ID 연계(원문 미수록), 키워드 기반 사고 매핑 규칙, 공격 체인 시나리오(IT 침투 → OT 영향) | NIST SP 800-82r3(업로드 필요), IEC 62443 요구사항 ID 목록 |

## 기준 데이터 / 출처

- **MITRE ATT&CK®** for ICS·Enterprise v19.2 © The MITRE Corporation
  - 이용약관: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/
- **CISA ICS 권고(CSAF 2.0)·KEV 카탈로그**: 미국 정부 저작물(공공 영역)
  - https://github.com/cisagov/CSAF
  - https://github.com/cisagov/kev-data
- **OT 보안사고 DB**: 정부 발표, 보안업체·연구기관 보고서, 언론 등 공개 출처를 종합했습니다. 출처는 각 사고의 `sources`와 '역매핑_사고사례' 시트에 있습니다.
- **IEC 62443**: 유료 표준이라 원문은 넣지 않고, 요구사항 ID와 명칭만 연계합니다(v4).
- **참고 양식**(`reference/style/`): 클라우드 v5·AI v3.2 매트릭스입니다. 구조·문체 참고용이며 데이터를 직접 인용하지 않습니다.

> 이 저장소는 공개 저장소이므로 유료 표준 원문이나 비공개 자료는 올리지 마세요. 위험평가 값은 기준값입니다. 업종·공정·자산 중요도에 맞게 검토한 뒤 사용하세요.
