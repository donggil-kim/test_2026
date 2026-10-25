# AI 활용 공격 보안위협 매트릭스 (aiattack/)

공격자가 **AI(LLM·에이전트·생성형·적대적 ML)를 무기로 삼아** 취약점을 발굴·악용하고, 침투·사회공학·악성코드·C2를
가속·자동화·대규모화하는 위협을 **공격자 킬체인**으로 정리한 렌즈 매트릭스입니다. 기존 AI 매트릭스(v3.2)가
"우리 AI를 지키는" 관점이라면, 이 매트릭스는 **"공격자의 AI가 (AI든 비-AI든) 대상을 치는" 관점**입니다.

> **현재 상태: ③ v2(관점 문구·공격 체인 시나리오) 완료 — 2026-10-25** (①분류·참조·사고 DB·② v1 빌드 포함)
> 세부위협 35개(도메인 7·위협분류 27), 사고 DB 31건(재인용 27 + 신규 4), 관점 문구 35/35, 공격 체인 시나리오 8개, 검증 오류·경고 0(`--strict`).
> **v2 빌드**: 15시트 워크북·CSV(`output/통합_AI활용공격_보안위협_매트릭스_v2.xlsx`, 문구·시나리오 포함) — 위험도 매우 높음 11·높음 7·보통 16·낮음 1. v1(데이터 빌드)도 함께 둠.
> 방법론·설계 원칙은 [`docs/methodology.md`](docs/methodology.md), 진행·결정 기록은 [`docs/작업방향.md`](docs/작업방향.md)·[`../emerging/작업방향.md`](../emerging/작업방향.md),
> 참조 자료 출처·라이선스는 [`reference/README.md`](reference/README.md)를 보세요.
> 다음 단계는 ④ 통합본(v5) 뷰 Lv0 편입입니다.

## 분류 체계 — 공격자 킬체인 7단계

| 코드 | 도메인 | 세부위협 | 핵심 |
|---|---|---:|---|
| RT | 정찰·표적 분석 | 4 | AI 기반 OSINT·공격면 식별·취약점 정보 수집 |
| RD | 공격 역량 확보 | 5 | 다크·탈옥 LLM, AI 생성 도구, 공세 에이전트 하네스 |
| VE | 취약점 발굴·익스플로잇 생성 | 5 | 자율 버그 헌팅·AI 익스플로잇/악성코드 생성 |
| IA | 초기 침투·사회공학 | 6 | AI 피싱·딥페이크 사칭·생체 우회·ClickFix |
| AO | 자율 실행·확산 | 6 | 자율·다중 에이전트 작전, AI 도구 공세 악용, 워크플로 대량 악용 |
| CC | 은닉·명령제어 | 4 | AI 서비스 C2, 실행 중 명령 동적 생성, AI 방어 회피 |
| IM | 영향·규모화 | 5 | 딥페이크 금전 사기, 데이터 탈취, 크립토재킹·LLMjacking, 규모화 |

- ID: `AIA-<도메인>-NN`(Lv2) · `AIA-<도메인>-NN.m`(Lv3). 고정, 재사용 금지.
- 고유 축: **AI 역할·자율성**(보조·증강·반자율·완전자율) · **AI 고유성**(신규/증폭) · **AI 역량 성숙도**(실사용·실증·연구시연).

## 사고 DB

- 31건 = 통합 v4.1 'AI 활용=확인/추정' 27건 재인용(`origin`) + AI 자율 취약점 발굴·익스플로잇 생성 신규 4건.
- 집계 실제 사고 24·실증·연구 5·위협인텔 2, AI 활용 확인 28·추정 3. 연도별 2023:3→2024:2→2025:9→2026:17(급증).
- 대표: GTG-1002·Hermes·대만 다중 에이전트·OpenAI 평가 에이전트·LAMEHUG·s1ngularity+AI CLI·Amazon Q·Rules File Backdoor·AI ClickFix·AI-in-the-Middle·Arup 딥페이크·Big Sleep·GTIG AI 0-day.

## 구성

```
aiattack/
  README.md · docs/methodology.md
  data/   taxonomy.yaml · incidents.yaml · frameworks.yaml · changelog.yaml · text/*.yaml(관점 문구 35) · scenarios.yaml(시나리오 8)
  scripts/ prepare_atlas.py · prepare_attack.py · prepare_refs.py · validate.py · taxonomy_rules.py · build_aiattack_threat_matrix.py
  reference/ atlas/ · attack/ · nist/ · links/ (reference/README.md)
  output/  통합_AI활용공격_보안위협_매트릭스_v2.xlsx · .csv (문구·시나리오) · v1.xlsx · .csv (데이터 빌드), 각 15시트
```

## 재현

```bash
python3 scripts/prepare_atlas.py && python3 scripts/prepare_attack.py && python3 scripts/prepare_refs.py
python3 scripts/validate.py --strict               # 데이터·문구·시나리오 검증(오류·경고 0)
python3 scripts/build_aiattack_threat_matrix.py --version v2   # 15시트 워크북·CSV(문구·시나리오 포함, 빌드 전 검증 자동 실행)
```

## v1 워크북 시트(15)

개요 · 보고서용 간략 매트릭스 · 매트릭스 뷰 · 통합 매트릭스 · 통합매트릭스_LITE · 도메인 요약 ·
**AI 역할·자율성 요약**(고유 축) · 공격 체인 시나리오(8개) · 역매핑_사고사례 · 교차 매핑 연계 ·
대응 기준 연계 · 참고 문헌 · 다른 매트릭스 연계 · 평가 기준 · 변경이력.

## 경계·연계

렌즈 매트릭스라 기존 6개 매트릭스와 겹칩니다. 재수록하지 않고 **통합 v4.1 요약 ID(AI·CL·OT·SC·ID·PH)로 연계만** 합니다.
AI 도구 자체가 오염·위장되는 공급망 위협은 여기가 아니라 AI 매트릭스 D08·공급망입니다("AI를 써서 공격" vs "AI 공급망이 오염됨").

> 위험평가 값·선별 결과는 기준값이며 조직 맥락에 맞게 검토 후 사용하는 것을 권장합니다. 벤더·2차 수치는 참고치로만 인용하고 사고 DB에는 1차 확인 사례만 편입합니다.
