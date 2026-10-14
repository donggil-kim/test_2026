# Phase 5 정정 반영 — 작업자 지침

입력: `<db>_worklist.csv`(원장에서 최종 판정 '경미 수정'·'수정 필요'인 행) + `../new_records/<db>_updates.yaml`(W2 승인 보강안).
결과: 원본 DB·문구 파일을 직접 고치고, 행마다 반영 기록을 `<db>_applied.csv`에 남긴다.

## 고칠 곳 (DB별로 한 작업자만)

| db | 사고 기록 | 원본 매트릭스 문구 | 통합 대표 사례 문안 |
|---|---|---|---|
| ot | `ot/data/incidents.yaml` (원장 키 `OT/INC-001` → id `INC-001`) | `ot/data/text/*.yaml` | `integrated/data/ot/*.yaml` |
| supplychain | `supplychain/data/incidents.yaml` | `supplychain/data/text/*.yaml` | `integrated/data/supplychain/*.yaml` |
| identity | `identity/data/incidents.yaml` | `identity/data/text/*.yaml` | `integrated/data/identity/*.yaml` |
| physical | `physical/data/incidents.yaml` | `physical/data/text/*.yaml` | `integrated/data/physical/*.yaml` |
| cloud | xlsx는 고치지 않음 → `data/incident_corrections.csv`에 행 추가(사건ID·필드·정정값·근거, 필드는 xlsx 열 이름 — 예: 기준일·대표 제목(정제)·사건 요약(국문)·사례유형·출처 구분·행위자(Wiz 요약 추출)). 이미 있는 `중복 삭제` 행의 삭제 대상은 고치지 않고, 그 정정이 남길 행에 필요하면 남길 행에 적용. 사례유형 재분류 값: `연구·노출`(실제 사고 아님) | `data/threat_text_override.csv` '참조(입력)' 열의 실제 사례 줄 | `integrated/data/cloud/*.yaml` |

## 반영 규칙

1. **시점 = 최초 공개월(F2 확정)**. 원장 `공개월`이 있고 현재 시점과 다르면 date를 공개월(YYYY-MM)로. 발생월이 크게 앞서면 요약에 "(발생 YYYY-MM)"처럼 한 번 적는다. DB 머리 주석의 date 정의가 다르면 "최초 공개 시점 YYYY-MM(통합 v4 검증 F2)"으로 고친다.
2. **사실 정정**(C 차이·제안 정정): 근거 URL이 있는 확인된 사실만 반영. "추정·의심·확인 못함"은 반영하지 않고 applied에 '보류'로 남긴다. 수치는 출처 기준으로, 출처끼리 다르면 병기.
3. **사례 구분 재분류**(D 제안): 연구·PoC·스캔 관측 → `kind: 연구·시연`(OT는 DB 머리 주석의 값), 그룹 단위 행은 원장 제안에 따름. 집계 상태가 바뀌면 문구 파일의 라벨([실제 사고]→[실증] 등)도 맞춘다.
4. **출처**(E 보강): 근거 URL 중 1차 출처를 `sources`에 `'출처명(연도) 제목 | URL'` 형식으로 추가. 오류 출처(주장과 무관)는 제거.
5. **묶음 분리**(F 분리 필요, 별개 사건 혼합): 한 기록을 실제 사건 하나로 좁히고 다른 사건은 지우거나(applied에 사유) 새 기록이 꼭 필요하면 '보류'로 남긴다.
6. **문구·대표 사례 문안**: 고친 기록을 인용하는 줄(`(사고 ID)` 또는 사례명으로 검색)의 `사례명(YYYY-MM)`과 사실을 함께 고친다. 원장 `G 메모`도 반영. 통합 yaml의 사례명(시점)은 원본 문구와 같아야 빌드 검증을 통과한다.
7. 매핑 필드(ics/ent/sct/idt/pht/attack_ref)는 updates.yaml이나 재분류가 요구할 때만 바꾼다.
8. YAML 서식·주석을 보존(부분 편집). 끝나면 `python3 <db>/scripts/validate.py`가 오류 0이어야 한다(클라우드는 `python3 scripts/build_cloud_threat_matrix.py`가 오류 없이 돌면 되고, 빌드 뒤 `git checkout output/`으로 산출물 되돌림).

## applied CSV 열

`원장 키, 필드, 현재, 정정, 반영, 사유` — 반영 = 반영 · 보류 · 해당 없음. 문구 파일 수정도 한 줄씩(필드 = 파일:세부위협 ID).

## 금지

빌드 산출물(`*/output/`) 커밋·수정, 원장·다른 DB 파일 수정, git 커밋·푸시.
