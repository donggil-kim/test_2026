#!/usr/bin/env bash
# =============================================================================
# 물리·인적 보안위협 매트릭스 — 골격 부트스트랩
# -----------------------------------------------------------------------------
# 목적 : 새 세션에서 "물리적/실세계 공격"(드론·물리 침입·HUMINT·위장취업·내부자)
#        관점의 보안위협 매트릭스를 이어서 작성할 수 있도록 physical/ 폴더의 뼈대를
#        만든다. 디지털/사이버 공격 매트릭스(AI·클라우드·OT·공급망)와 같은 틀
#        (분류 → 위험평가 → 실제근거 → 대응 기준 → 관점 문구)을 쓰되, 공격면이
#        물리·인적 영역이라는 점만 다르다.
#
# 사용 : 저장소 안에서  bash physical/bootstrap.sh         (이미 있는 파일은 건너뜀)
#        덮어쓰려면    FORCE=1 bash physical/bootstrap.sh
#
# 결과 : physical/{README.md,NEXT_SESSION.md,docs/,data/,reference/,scripts/}
#        생성 후, 새 세션은 physical/NEXT_SESSION.md 를 먼저 읽고 작업을 이어간다.
#
# 설계 : 이 스크립트가 만드는 것은 "내용"이 아니라 "형식과 규칙"이다. 실제 위협·
#        사고·수치는 새 세션이 공개 출처로 조사해 채운다(씨앗 행은 형식 예시).
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORCE="${FORCE:-0}"
made=0; skipped=0

w() {  # w <상대경로> ; 본문은 stdin(heredoc). 이미 있으면 FORCE=1 일 때만 덮어씀
  local rel="$1" abs="$ROOT/$1"
  mkdir -p "$(dirname "$abs")"
  if [[ -e "$abs" && "$FORCE" != "1" ]]; then
    printf '  skip  %s\n' "$rel"; skipped=$((skipped+1)); cat >/dev/null; return 0
  fi
  cat > "$abs"; printf '  write %s\n' "$rel"; made=$((made+1))
}

echo "물리·인적 보안위협 매트릭스 골격 생성 → $ROOT"
mkdir -p "$ROOT"/{docs,data/text,reference,scripts}

# ---------------------------------------------------------------------------
# 1) 인수인계 브리프 — 새 세션이 가장 먼저 읽는 문서
# ---------------------------------------------------------------------------
w NEXT_SESSION.md <<'EOF'
# 인수인계 — 물리·인적 보안위협 매트릭스 (새 세션용)

이 폴더는 **물리적/실세계 공격 관점**의 보안위협 매트릭스 작업 공간입니다.
드론 무단촬영·물리 침입·HUMINT(인적 포섭)·위장취업·내부자 정보유출처럼
단말/네트워크 기반 사이버 공격으로 담기 어려운 위협을 다룹니다.

> 같은 저장소의 `supplychain/`(통합 공급망 매트릭스)이 완성형 참고 모델입니다.
> 구조·빌드·검증기·문구 형식·방법론을 그대로 본떠 옵니다. 막히면 `../supplychain/`을 보세요.

## 0. 먼저 지켜야 할 것(가드레일)

- **방어 관점 유지**: 모든 문구는 탐지·대응 중심(■ 탐지 / ■ 대응)으로 씁니다. 침입·도청·촬영·
  포섭의 *실행 방법*을 단계별로 알려 주는 공격 지침서가 아니라, "무엇을 탐지하고 어떻게 막는가"를
  정리하는 방어 자료입니다. 민감 기법은 식별·탐지·완화에 필요한 수준으로만 기술합니다.
- **공개 저장소**: 유료 표준 원문·비공개 자료·개인정보(실명·연락처 등)를 올리지 않습니다.
  프레임워크·표준은 ID·명칭만 연계합니다. 특정 인물·특정 기업 피해자를 식별하는 세부는 피하고
  공개 보도·정부 발표 수준으로만 적습니다.
- **사실 근거**: 수치·사례는 공개 출처에 있는 것만 씁니다. 모르면 비워 두고 TODO로 남깁니다.
  발생가능성 '상'은 실제 사고 2건 이상으로만 판정합니다(디지털 매트릭스와 같은 수식).
- **저장소 아티팩트에 모델 식별자(제품명·버전)를 넣지 않습니다.** 커밋 메시지의 귀속 라인은
  현재 세션의 시스템 안내에 적힌 문구를 그대로 씁니다(세션마다 다를 수 있음).
- **브랜치**: 현재 세션이 지정받은 개발 브랜치를 씁니다(이 저장소 관례는 `claude/loving-pasteur-vcy7h0`).
- **PR은 사용자가 명시적으로 요청할 때만** 만듭니다.

## 1. 범위와 다른 매트릭스와의 관계

- **담는 것**: 정찰·표적선정, 물리 침입·접근, 감시·도청·무단촬영(드론 포함), 인적 포섭·사회공학,
  위장취업·내부자, 물리적 반출·유출, 영향(지식재산·영업비밀 손실·사보타주·안전).
- **담지 않는 것(연계만)**: 순수 디지털 침해. 위장취업의 *신원확인 우회*나 내부자의 *계정 남용*처럼
  디지털 신원 쪽 면은 아이덴티티/클라우드/공급망 매트릭스 ID로 교차 연계합니다(중복 작성 금지).
- **행위자(국가배후: 중국·러시아·북한 등)는 도메인이 아니라** 사고 DB의 `actor` 필드로 다룹니다.
  '국가배후'를 도메인으로 올리지 마세요(행위자 축과 기법 축을 섞지 않음).

## 2. 분류 체계 (data/taxonomy.yaml)

- Lv1 도메인 7개(RC·PA·SV·HU·IN·EX·IM) → Lv2 위협분류 → Lv3 세부위협.
- ID: `PHT-<도메인>-NN`(Lv2) · `PHT-<도메인>-NN.m`(Lv3). 고정, 재사용 금지.
- 각 Lv3: id·name·en·stage(공격 단계)·assets·attack(해당 시 ATT&CK ID)·nist(800-53 PE/PS)·
  iso(ISO 27001 물리 통제, 확인 후)·cross(디지털 매트릭스 연계 ID)·severity·severity_why.
- 씨앗으로 도메인마다 예시 Lv3 1행이 들어 있습니다. 새 세션이 Lv2/Lv3를 확장합니다.

## 3. 사고 DB (data/incidents.yaml)

- 필드: id(PHI-NNN)·title·date(YYYY-MM)·kind·verification·sector·region·actor·vector(도메인 코드)·
  impact·summary·pht(매핑 Lv3)·sources('출처 | URL').
- kind/verification/sector/impact 어휘는 scripts/taxonomy_rules.py 에 정의. 실제 사고만 발생가능성 '상'.
- **씨앗은 형식 예시입니다. 공개 출처(정부 발표·법원 기소문·공신력 있는 보도)로 실제 사례를 조사해
  출처 URL과 함께 채우세요.** 북한 IT 인력 위장취업, 내부자 영업비밀 유출, 핵심시설 드론 출현 등이
  출발점입니다. 근거 밀도가 영역마다 다릅니다(위장취업·내부자는 공개 사례 많음, 드론 기업스파이는
  적음 → 정부 경보·기소문 비중↑). 이 한계를 docs/METHODOLOGY.md 에 명시하세요.

## 4. 교차 매핑·대응 기준 (data/frameworks.yaml)

- 확정: NIST SP 800-53 PE(물리·환경 보호)·PS(인적 보안) 계열, ATT&CK 물리 접점(T1200·T1091·T1052 등 소수).
- 확인 후 추가(새 세션이 1차 출처로 검증): CISA Insider Threat Mitigation, MITRE Insider Threat KB,
  UK NPSA(구 CPNI) 인적·물리 보안, ISO/IEC 27001 Annex A 물리 통제·ISO 22341, CISA Counter-UAS.
- ATT&CK은 물리 커버리지가 약합니다 — '미연계 사유'로 솔직히 표기하세요.
- 라이선스 조건을 reference/README.md 에 적고, 원문은 올리지 않습니다.

## 5. 관점 문구 (data/text/<도메인>.yaml) — supplychain 형식과 동일

- oneline: 50자 이내, 명사형(수단+대상+결과).
- summary: 2줄 개조식(① 공격자는 …할 수 있음 ② 피해·확산 또는 탐지·방어가 어려운 이유).
- reference: ■ 물리 관점(대상·경로·수법·연계 ID) / ■ 실제 사례([실제 사고]·[실증]·[공개 취약점]·[시나리오],
  없으면 '공개 사고 미확인 — 사유').
- detect: ■ 탐지 / ■ 대응(예방 → 차단 → 탐지 순).
- 용어: 자격증명(인증정보·크리덴셜 금지)·반출(행위)/유출(결과). 사례는 그 행에 매핑된 사고만 인용.

## 6. 빌드·검증 (scripts/)

- `taxonomy_rules.py`: 집계·판정 규칙(씨앗 제공, 그대로 확장).
- `validate.py`, `build_physical_threat_matrix.py`: **최소 동작 스텁**이 들어 있습니다.
  `../supplychain/scripts/{validate.py,build_supplychain_threat_matrix.py}`를 참고해 열·시트·검증 항목을
  이식·확장하세요(도메인/프레임워크/필드명만 물리용으로 교체).

## 7. 산출물·버전

- v0: 이 골격(분류 체계 초안·사고 DB 스키마·프레임워크 목록).
- v1: 분류 체계 완성 + 빌드(워크북·CSV) + 근거 집계·위험평가.
- v2: 관점 문구 전 항목 + 검증기 + 공격 체인 시나리오 + 방법론/README.
- 커밋은 단계별로 나누고, 빌드 전 `python3 scripts/validate.py`를 통과시키세요.

## 할 일 체크리스트
- [ ] 도메인·Lv2·Lv3 확정(ID 대장) — taxonomy.yaml
- [ ] 프레임워크 카탈로그 채우기(NIST PE/PS 공식 명칭은 NIST OSCAL에서) — frameworks.yaml
- [ ] 공개 출처로 사고 DB 구축(출처 URL 필수) — incidents.yaml
- [ ] build/validate 를 supplychain 기준으로 이식
- [ ] 도메인별 관점 문구 작성 + 검증 통과
- [ ] 시나리오·방법론·README·변경이력
- [ ] 커밋·푸시(지정 브랜치), 필요 시에만 PR
EOF

# ---------------------------------------------------------------------------
# 2) README (폴더 소개)
# ---------------------------------------------------------------------------
w README.md <<'EOF'
# 물리·인적 보안위협 매트릭스 (작성 중)

드론 무단촬영·물리 침입·HUMINT(인적 포섭)·위장취업·내부자 정보유출 등 **물리적/실세계 공격**
관점의 보안위협을 정리하는 매트릭스입니다. 디지털/사이버 매트릭스(AI·클라우드·OT·공급망)와 같은
틀(분류 → 위험평가 → 실제근거 → 대응 기준 → 관점 문구)을 쓰되 공격면이 물리·인적 영역입니다.

- 분류: 물리·인적 공격면 7개 도메인(RC·PA·SV·HU·IN·EX·IM) → 위협분류 → 세부위협 (`data/taxonomy.yaml`)
- 교차 매핑: NIST SP 800-53 PE·PS · ATT&CK 물리 접점 · (확인 후) CISA·NPSA·ISO·MITRE 내부자 KB
- 실제 근거: 공개 출처 기반 물리·인적 보안사고 DB (`data/incidents.yaml`)
- 연계: 디지털 매트릭스(아이덴티티·클라우드·공급망)와 교차 ID로 연결

> **새 세션에서 이어서 작업합니다.** 먼저 [`NEXT_SESSION.md`](NEXT_SESSION.md)를 읽으세요.
> 완성형 참고 모델은 같은 저장소의 `../supplychain/` 입니다.

## 재생성(골격)
```bash
bash physical/bootstrap.sh          # 뼈대 생성(기존 파일은 건너뜀)
FORCE=1 bash physical/bootstrap.sh  # 뼈대 덮어쓰기
```

## 산출물(예정)
```bash
pip install openpyxl pyyaml
python3 scripts/validate.py
python3 scripts/build_physical_threat_matrix.py   # output/ 에 워크북·CSV
```
EOF

# ---------------------------------------------------------------------------
# 3) 방법론 골격
# ---------------------------------------------------------------------------
w docs/METHODOLOGY.md <<'EOF'
# 방법론 — 물리·인적 보안위협 매트릭스 (초안/TODO)

AI v3.2 · 클라우드 v5 · OT · 공급망 매트릭스와 같은 틀을 물리·인적 공격면에 적용한다.
아래는 골격이며, 새 세션이 내용을 확정하며 채운다.

## 1. 설계 원칙
- 공격면(물리·인적 단계)을 Lv1 도메인으로. 행위자(국가배후)는 사고 DB actor 필드로.
- 산정 로직(발생가능성 수식·위험도 3×3·근거 수준·우선순위)은 디지털 매트릭스와 동일.
- 심각도만 물리·인적 결과 기준으로 재정의(§4).
- 공개 출처의 실제 사고 중심. 방어 관점(탐지·대응) 유지.

## 2. 입력 데이터  (TODO: 확정·출처·라이선스 표)
- NIST SP 800-53 PE/PS, ATT&CK 물리 접점(T1200·T1091·T1052…), CISA/NPSA/ISO/MITRE 내부자 KB(확인 후).
- 물리·인적 보안사고 DB(공개 출처).

## 3. 분류 체계  (data/taxonomy.yaml 참조)
- 도메인 7개(RC·PA·SV·HU·IN·EX·IM), ID 체계 PHT-<도메인>-NN[.m].

## 4. 평가 로직
- 발생가능성: 상=실제 사고 2건 이상 / 중=1건 또는 실증·공개취약점·문헌 / 하=근거 없음.
- 심각도(TODO 확정, 물리·인적 결과 기준): 예) 영업비밀·핵심기술 대량 유출, 인명·안전 위협,
  장기 잠복 내부자 = 상 / 개별 자산·일시적 피해 = 중 / 제한적·복구 용이 = 하.
- 위험도 3×3, 근거 수준(실제 사고 확인 > 실사용·공개취약점 > 실증·문헌 > 이론), 우선순위.

## 5. 교차 매핑·대응 기준  (TODO)
## 6. 관점 문구 규칙  (NEXT_SESSION.md §5와 동일)
## 7. 공격 체인 시나리오  (data/scenarios.yaml)
## 8. 한계
- 공개 사고 편향: 위장취업·내부자는 공개 사례가 많고, 드론·물리 기업스파이는 귀속이 분명한 공개
  사례가 적어 정부 경보·기소문 비중이 큼. 실제 발생은 과소보고일 수 있음.
- 방어 자료로 한정: 공격 실행 세부는 탐지·완화에 필요한 수준까지만.
EOF

# ---------------------------------------------------------------------------
# 4) 분류 체계(씨앗) — 도메인 7개 + 도메인별 예시 Lv3 1행
# ---------------------------------------------------------------------------
w data/taxonomy.yaml <<'EOF'
# 물리·인적 보안위협 매트릭스 — 분류 체계 (씨앗)
# 도메인(Lv1) → 위협분류(Lv2) → 세부위협(Lv3). 아래 Lv3는 "형식 예시"이며 새 세션이 확장한다.
# ID: PHT-<도메인>-NN(.m). severity ∈ {상,중,하}. attack/nist/iso/cross 는 해당 없으면 [].

assessment:
  likelihood_rule: "상 = 실제 사고 2건 이상 / 중 = 실제 사고 1건 또는 실증·공개 취약점·문헌 중 하나 이상 / 하 = 근거 없음"
  severity_rule:   # TODO: 새 세션이 확정
    상: "영업비밀·핵심기술 대량 유출, 인명·안전·핵심시설 위협, 장기 잠복 내부자 등 대규모·회복 불가 피해"
    중: "개별 자산·단일 조직 범위 피해, 또는 다른 위협의 피해를 키우는 조건"
    하: "영향이 제한적·일시적이고 복구가 쉬운 위협"
  stages: [정찰, 접근, 실행, 지속·내부자화, 반출, 영향]   # 공격 단계 어휘

profiles:   # 적용 대상(조직 유형) — TODO 확정
  제조·연구: "반도체·방산·바이오 등 핵심기술 보유 기업·연구소"
  기반시설: "에너지·통신·교통 등 국가기반시설"
  일반기업: "사무·SaaS 중심 조직"

domains:
  - code: RC
    ko: 정찰·표적 선정
    en: Reconnaissance & Targeting
    desc: 공개정보(OSINT)·현장 답사·인물 물색으로 표적 조직·인력·시설을 파악하는 단계
    lv2:
      - id: PHT-RC-01
        name: 공개정보·소셜미디어 기반 인물·조직 정찰
        lv3:
          - id: PHT-RC-01.1
            name: 임직원 신상·근무지 수집(SNS·채용·학회)
            en: Targeting staff via social media, job posts, conferences
            stage: [정찰]
            assets: [임직원, 조직도·인사정보]
            attack: []
            nist: [PS-3]
            iso: []
            cross: []
            severity: 중
            severity_why: 단독 피해는 없으나 포섭·위장취업·사회공학의 표적 선정 토대가 됨
  - code: PA
    ko: 물리 침입·접근
    en: Physical Intrusion & Access
    desc: 시설 경계·출입통제를 우회해 건물·구역·장비에 물리적으로 접근
    lv2:
      - id: PHT-PA-01
        name: 출입통제 우회
        lv3:
          - id: PHT-PA-01.1
            name: 테일게이팅·출입증 위·변조로 통제구역 진입
            en: Tailgating and badge forgery into controlled areas
            stage: [접근]
            assets: [출입통제, 통제구역]
            attack: []
            nist: [PE-3, PE-6]
            iso: []
            cross: []
            severity: 중
            severity_why: 접근 자체는 국지적이나 반출·장비 임플란트·내부망 접점으로 이어질 수 있음
  - code: SV
    ko: 감시·도청·무단촬영
    en: Surveillance & Eavesdropping
    desc: 드론·은닉 카메라·도청·RF로 시설·화면·대화·전자파를 원격 수집
    lv2:
      - id: PHT-SV-01
        name: 드론·무인기 기반 무단 촬영·정찰
        lv3:
          - id: PHT-SV-01.1
            name: 드론으로 시설 내부·화면·동선 무단 촬영
            en: Unauthorized drone surveillance of facilities
            stage: [정찰, 실행]
            assets: [시설 외관·내부, 화면·문서]
            attack: []
            nist: [PE-6, PE-19]
            iso: []
            cross: []
            severity: 중
            severity_why: 비접촉 원거리 수집으로 탐지가 어렵고 반복 가능, 핵심시설 배치·공정 노출
  - code: HU
    ko: 인적 포섭·사회공학
    en: Human Intelligence & Social Engineering
    desc: 금전·협박·관계로 임직원·협력사를 포섭하거나 대면 사회공학으로 정보를 끌어냄
    lv2:
      - id: PHT-HU-01
        name: 임직원 포섭·매수·협박
        lv3:
          - id: PHT-HU-01.1
            name: 금전·협박으로 재직자 포섭(정보제공·반입)
            en: Recruiting or coercing employees for insider access
            stage: [접근, 지속·내부자화]
            assets: [임직원, 영업비밀]
            attack: []
            nist: [PS-3, PS-8]
            iso: []
            cross: []
            severity: 상
            severity_why: 신뢰된 내부 접근을 장기간 제공해 탐지가 어렵고 핵심기술 유출로 직결
  - code: IN
    ko: 위장취업·내부자
    en: Fraudulent Employment & Insider
    desc: 신분을 위장해 입사하거나 재직 내부자가 신뢰 접근을 악용
    lv2:
      - id: PHT-IN-01
        name: 위장취업·신분 위장 입사
        lv3:
          - id: PHT-IN-01.1
            name: 위조·도용 신분으로 입사해 내부 접근 확보
            en: Fraudulent hiring using fake or stolen identity
            stage: [접근, 지속·내부자화]
            assets: [채용 절차, 내부 시스템·문서]
            attack: []
            nist: [PS-3]
            iso: []
            cross: []   # 예) 아이덴티티 매트릭스의 신원증명·온보딩 사기와 연계(ID 확정 후 기입)
            severity: 상
            severity_why: 정상 임직원 권한을 장기 보유, 국가배후 조직적 위장취업 사례로 피해 광범위
  - code: EX
    ko: 자산·정보 반출
    en: Asset & Data Exfiltration (physical)
    desc: 문서·시제품·저장매체를 물리적으로 반출하거나 화면·육안으로 유출
    lv2:
      - id: PHT-EX-01
        name: 물리 매체·문서 반출
        lv3:
          - id: PHT-EX-01.1
            name: 저장매체·출력물·시제품 무단 반출
            en: Removing media, printouts, or prototypes
            stage: [반출]
            assets: [저장매체, 문서·시제품]
            attack: [T1052.001]
            nist: [PE-3, MP-5]
            iso: []
            cross: []   # 예) 공급망/클라우드의 데이터 반출과 연계
            severity: 상
            severity_why: 핵심기술·설계 원본이 통째로 유출되면 회복이 어렵고 경쟁우위 상실
  - code: IM
    ko: 영향·피해
    en: Impact
    desc: 지식재산·영업비밀 손실, 사보타주, 안전·가동 위협 등 공격 결과
    lv2:
      - id: PHT-IM-01
        name: 지식재산·영업비밀 손실
        lv3:
          - id: PHT-IM-01.1
            name: 핵심기술·영업비밀 유출로 인한 경쟁력·안보 피해
            en: Loss of trade secrets and critical technology
            stage: [영향]
            assets: [영업비밀, 국가핵심기술]
            attack: []
            nist: []
            iso: []
            cross: []
            severity: 상
            severity_why: 국가핵심기술 유출은 기업·국가 안보 피해로 이어지고 원상회복 불가
EOF

# ---------------------------------------------------------------------------
# 5) 프레임워크 카탈로그(씨앗)
# ---------------------------------------------------------------------------
w data/frameworks.yaml <<'EOF'
# 교차 매핑·대응 기준 카탈로그 (씨앗) — ID·명칭만. 원문 비수록(공개 저장소).
# 공식 명칭은 새 세션이 1차 출처로 확인해 채운다(특히 NIST 공식 영문 명칭은 NIST OSCAL에서).
meta:
  note: "확정=NIST 800-53 PE/PS·ATT&CK 물리 접점. 확인 후 추가=CISA/NPSA/ISO/MITRE 내부자 KB."
  todo: "각 프레임워크의 공식 명칭·버전·라이선스를 reference/README.md 와 함께 확정"

# NIST SP 800-53 Rev.5 — 물리·환경(PE)·인적 보안(PS) 계열 (영문 명칭은 OSCAL에서 확정)
nist80053:
  PE-2: [TODO-공식명, 물리적 접근 권한 부여]
  PE-3: [TODO-공식명, 물리적 접근 통제]
  PE-6: [TODO-공식명, 물리적 접근 모니터링]
  PE-8: [TODO-공식명, 방문자 접근 기록]
  PE-19: [TODO-공식명, 정보 유출(전자파 등) 방지]
  PS-3: [TODO-공식명, 인사 심사(screening)]
  PS-4: [TODO-공식명, 퇴직 처리]
  PS-5: [TODO-공식명, 인사 이동]
  PS-7: [TODO-공식명, 외부 인력(계약자) 보안]
  PS-8: [TODO-공식명, 인사 제재]
  MP-5: [TODO-공식명, 매체 반출·이송 통제]

# MITRE ATT&CK Enterprise — 물리 접점(소수). 명칭은 ATT&CK에서 확정.
attack_physical:
  T1200: [Hardware Additions, 하드웨어 추가(악성 장치 반입)]
  T1091: [Replication Through Removable Media, 이동식 매체를 통한 전파]
  T1052: [Exfiltration Over Physical Medium, 물리 매체를 통한 반출]
  T1052.001: [Exfiltration over USB, USB를 통한 반출]

# 확인 후 편입할 후보 — 1차 출처 검증 전까지는 근거로 쓰지 않음
candidate_frameworks:
  - "CISA Insider Threat Mitigation (내부자 위협 완화 지침)"
  - "MITRE Insider Threat TTP Knowledge Base"
  - "UK NPSA(구 CPNI) 인적·물리 보안 지침"
  - "ISO/IEC 27001 Annex A 물리 통제 · ISO 22341(보안設計)"
  - "CISA Counter-UAS (대드론) 지침"
EOF

# ---------------------------------------------------------------------------
# 6) 사고 DB(씨앗) — 형식 예시 1 + 템플릿 1 (실데이터는 새 세션이 출처와 함께 채움)
# ---------------------------------------------------------------------------
w data/incidents.yaml <<'EOF'
# 물리·인적 보안사고 DB (씨앗) — 공개 출처만. 아래는 형식 예시이며 새 세션이 조사·검증해 확장한다.
# kind: 사고/캠페인/정부 발표/법원 기소/공시/연구·시연/위협인텔
# verification: 정부·사법 확인/피해기관 확인/보안업체·연구기관 분석/언론 보도/행위자 주장
# sources 는 '출처 | URL' 형식 필수. 확인 전이면 'TODO: 1차 출처 URL' 로 남기고 빈 채로 두지 말 것.

- id: PHI-001
  title: 북한 IT 인력 위장취업(도용 신분·원격근무 악용)
  date: "2024-07"            # TODO: 대표 공개 시점으로 확정
  kind: 정부 발표            # 다수 정부 기소·경보 존재 — 1차 출처로 확정
  verification: 정부·사법 확인
  sector: [IT·소프트웨어]
  region: 글로벌
  actor: 북한 연계(IT 인력 송출 조직)
  vector: [IN, HU]           # 위장취업·인적
  impact: [내부 접근 확보, 자금 유출]
  summary: >-
    위조·도용한 신분과 대리 수취(랩톱 팜)를 이용해 해외 기업에 원격 개발자로 위장취업,
    급여를 제재 회피 자금으로 유용하고 내부 접근을 확보한 조직적 사례군. (세부·수치는 1차 출처로 확정)
  pht: [PHT-IN-01.1]
  sources:
    - "TODO: 미 법무부/FBI 등 1차 발표 URL"

# --- 템플릿(아래 주석을 복사해 새 항목으로 사용) ---------------------------
# - id: PHI-002
#   title: (사례명)
#   date: "YYYY-MM"
#   kind: 사고
#   verification: 언론 보도
#   sector: [제조·연구]
#   region: 한국
#   actor: 미상
#   vector: [SV]
#   impact: [영업비밀 유출]
#   summary: >-
#     (공개 출처에 있는 사실만 2~3문장으로. 공격 실행 세부 대신 경위·피해·탐지 계기 중심.)
#   pht: [PHT-SV-01.1]
#   sources:
#     - "출처명 | https://example.org/..."
EOF

# ---------------------------------------------------------------------------
# 7) 시나리오(씨앗)
# ---------------------------------------------------------------------------
w data/scenarios.yaml <<'EOF'
# 공격 체인 시나리오 — 실제 사고를 물리·인적 단계 흐름으로 재구성(방어 관점).
# 각 단계는 세부위협(PHT-ID)에 연결, 단계별 탐지 포인트와 흐름을 끊는 초크 포인트를 적는다.
# 실제 시나리오는 사고 DB가 쌓인 뒤 새 세션이 작성. 아래 주석 템플릿을 복사해 scenarios 아래에 추가한다.
scenarios: []
# - id: PSN-01
#   title: "위장취업자의 핵심기술 반출(예시)"
#   incidents: [PHI-001]
#   summary: (근거 사고 기반 한두 문장)
#   steps:
#     - { pht: [PHT-RC-01.1], 단계: 정찰, 행위: "(공개 출처 사실)", 탐지: "(탐지 포인트)" }
#     - { pht: [PHT-IN-01.1], 단계: 지속·내부자화, 행위: "(…)", 탐지: "(…)" }
#     - { pht: [PHT-EX-01.1], 단계: 반출, 행위: "(…)", 탐지: "(…)" }
#   chokepoints:
#     - "PHT-IN-01.1 — 채용 시 신원확인·배경조사 강화로 위장취업 차단"
EOF

# ---------------------------------------------------------------------------
# 8) 변경이력(씨앗)
# ---------------------------------------------------------------------------
w data/changelog.yaml <<'EOF'
# 변경이력 — 빌드 시 '변경이력' 시트로 출력(최신이 위). 항목: [버전, 날짜, 구분, 대상, 변경 내용, 사유]
entries:
  - [v0, "TODO", 구조, "골격", "physical/ 분류 체계 초안(도메인 7)·사고 DB 스키마·프레임워크 목록·규칙·스텁 생성", "물리·인적 공격 매트릭스 작업 시작"]
EOF

# ---------------------------------------------------------------------------
# 9) 관점 문구(씨앗) — 형식 예시 1개
# ---------------------------------------------------------------------------
w data/text/SV.yaml <<'EOF'
# [SV] 감시·도청·무단촬영 — 물리 관점 문구 (형식 예시)
# 규칙: NEXT_SESSION.md §5. oneline 50자 이내, summary 2줄, reference(■ 물리 관점/■ 실제 사례),
#       detect(■ 탐지/■ 대응). 사례는 그 행에 매핑된 사고만 인용. 방어 관점 유지.
SCT-SV-EXAMPLE:            # 실제 키는 PHT-SV-01.1 처럼 taxonomy ID 를 사용
  oneline: (예시) 드론 원거리 촬영으로 시설 배치·화면·동선 무단 수집
  summary: |-
    - 공격자는 드론·무인기로 울타리 밖에서 시설 내부·화면·출입 동선을 촬영해 정찰할 수 있음
    - 비접촉·원거리라 기존 출입통제로 막기 어렵고 반복 수집이 가능해 탐지 체계가 없으면 인지가 늦음
  reference: |-
    ■ 물리 관점
    - 대상: 핵심시설 외관·창문 너머 화면·옥외 공정, 출입 동선
    - 연계: (현장 포섭 PHT-HU-01.1 등과 결합 시 표기)
    ■ 실제 사례
    - 공개 사고 미확인 — 귀속이 분명한 공개 사례가 적음(정부 경보·기소문으로 보강 예정)
  detect: |-
    ■ 탐지
    - 드론 탐지 체계(RF·레이더·음향)와 비행금지구역 모니터링, 이상 비행 경보
    ■ 대응
    - 창문 차폐·화면 배치 조정, 민감구역 옥외 노출 최소화, 대드론 대응 절차·법적 신고 체계
EOF

# ---------------------------------------------------------------------------
# 10) 판정 규칙(씨앗)
# ---------------------------------------------------------------------------
w scripts/taxonomy_rules.py <<'EOF'
# -*- coding: utf-8 -*-
"""물리·인적 보안위협 매트릭스 — 판정 규칙(씨앗).
분류/매핑 원천은 data/*.yaml. 이 파일은 근거 집계·위험 산정 규칙만 둔다.
디지털 매트릭스(AI v3.2·클라우드 v5·OT·공급망)와 같은 수식을 쓴다. 새 세션이 어휘를 확정·확장한다."""

REAL_KINDS = {"사고", "캠페인", "정부 발표", "법원 기소", "공시"}
RESEARCH_KINDS = {"연구·시연"}
INTEL_KINDS = {"위협인텔"}
EXCLUDED_VERIFICATION = {"행위자 주장"}
VERIFICATIONS = ["정부·사법 확인", "피해기관 확인", "보안업체·연구기관 분석", "언론 보도", "행위자 주장"]
KINDS = ["사고", "캠페인", "정부 발표", "법원 기소", "공시", "연구·시연", "위협인텔"]

RECENT_FROM = "2025-01"   # 최근 사고 기준
LIKELY_HIGH_REAL = 2      # 발생가능성 '상' = 실제 사고 2건 이상

RISK_MATRIX = {
    ("상", "상"): "매우 높음", ("상", "중"): "높음", ("상", "하"): "보통",
    ("중", "상"): "높음", ("중", "중"): "보통", ("중", "하"): "낮음",
    ("하", "상"): "보통", ("하", "중"): "낮음", ("하", "하"): "낮음",
}
RISK_ORDER = ["매우 높음", "높음", "보통", "낮음"]
LEVELS = ["실제 사고 확인", "실사용 기법 포함", "실증·공개 취약점", "이론·시나리오"]

SECTORS = ["제조·연구", "반도체·방산", "기반시설", "IT·소프트웨어", "공공기관", "일반기업"]  # TODO 확정
REGIONS = ["한국", "미국", "글로벌", "기타"]  # TODO 확정
VECTORS = ["RC", "PA", "SV", "HU", "IN", "EX", "IM"]  # 도메인 코드
IMPACTS = ["영업비밀 유출", "국가핵심기술 유출", "내부 접근 확보", "자금 유출",
           "사보타주·가동 중단", "안전·인명 위협", "평판·법적 피해"]  # TODO 확정


def incident_status(e):
    """사고 DB 항목의 집계 상태 — 실제 사고 / 실증·연구 / 위협인텔 / 제외(검증)."""
    if e.get("kind") in RESEARCH_KINDS:
        return "실증·연구"
    if e.get("kind") in INTEL_KINDS:
        return "위협인텔"
    if e.get("verification") in EXCLUDED_VERIFICATION:
        return "제외(검증)"
    return "실제 사고"
EOF

# ---------------------------------------------------------------------------
# 11) 검증기(최소 스텁) — supplychain/scripts/validate.py 를 참고해 확장
# ---------------------------------------------------------------------------
w scripts/validate.py <<'EOF'
# -*- coding: utf-8 -*-
"""물리·인적 매트릭스 검증기(최소 스텁).
현재: taxonomy/incidents 의 ID 형식·중복·필수 필드·매핑 존재·어휘·출처 형식만 점검.
TODO(새 세션): ../supplychain/scripts/validate.py 를 참고해 문구 형식·사례 라벨↔집계 상태·
      시점(YYYY-MM)·금지 용어(인증정보·크리덴셜)·프레임워크 ID 존재/행 매핑 일치·시나리오 검증을 이식.
실행: python3 scripts/validate.py   (오류가 있으면 종료 코드 1)
"""
import re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import taxonomy_rules as R

ERR = []
def err(where, msg): ERR.append(f"[오류] {where}: {msg}")

def load(p, d=None):
    return yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else d

TAX = load(ROOT / "data/taxonomy.yaml", {})
INC = load(ROOT / "data/incidents.yaml", []) or []

ROWS = {}
for dmn in TAX.get("domains", []):
    for l2 in dmn.get("lv2", []):
        for x in l2.get("lv3", []):
            if x["id"] in ROWS:
                err("taxonomy.yaml", f"세부위협 ID 중복 {x['id']}")
            ROWS[x["id"]] = x
            if x.get("severity") not in ("상", "중", "하"):
                err(f"taxonomy.yaml {x['id']}", f"severity 값 오류 {x.get('severity')}")

for e in INC:
    i = e.get("id", "?")
    where = f"incidents.yaml {i}"
    if not re.fullmatch(r"PHI-\d{3}", str(i)):
        err(where, "ID 형식(PHI-NNN) 오류")
    for f in ("title", "date", "kind", "verification", "summary", "pht", "sources"):
        if not e.get(f):
            err(where, f"필수 필드 '{f}' 없음")
    if e.get("kind") and e["kind"] not in R.KINDS:
        err(where, f"kind 어휘 아님: {e.get('kind')}")
    if e.get("date") and not re.fullmatch(r"\d{4}-\d{2}", str(e["date"])):
        err(where, f"date 형식(YYYY-MM) 오류: {e.get('date')}")
    for k in e.get("pht", []) or []:
        if k not in ROWS:
            err(where, f"매핑 세부위협 {k} 없음")

for m in ERR:
    print(m)
print(f"\n검증: 세부위협 {len(ROWS)}개 · 사고 {len(INC)}건 | 오류 {len(ERR)}건")
print("NOTE: 최소 스텁입니다. ../supplychain/scripts/validate.py 기준으로 문구·사례·프레임워크 검증을 이식하세요.")
sys.exit(1 if ERR else 0)
EOF

# ---------------------------------------------------------------------------
# 12) 빌드(최소 스텁) — supplychain/scripts/build_*.py 를 참고해 확장
# ---------------------------------------------------------------------------
w scripts/build_physical_threat_matrix.py <<'EOF'
# -*- coding: utf-8 -*-
"""물리·인적 매트릭스 빌드(최소 스텁).
현재: taxonomy 를 읽어 세부위협 목록 CSV 만 output/ 에 생성(동작 확인용).
TODO(새 세션): ../supplychain/scripts/build_supplychain_threat_matrix.py 를 참고해
      근거 집계(사고/프레임워크)·위험평가·우선순위·관점 문구·워크북(xlsx) 시트 구성을 이식.
      빌드 전 scripts/validate.py 를 자동 실행(오류 시 중단)하도록 확장.
실행: python3 scripts/build_physical_threat_matrix.py
"""
import csv, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import taxonomy_rules as R  # noqa: F401  (확장 시 사용)

TAX = yaml.safe_load((ROOT / "data/taxonomy.yaml").read_text(encoding="utf-8"))
rows = []
for dmn in TAX.get("domains", []):
    for l2 in dmn.get("lv2", []):
        for x in l2.get("lv3", []):
            rows.append([f"[{dmn['code']}] {dmn['ko']}", l2["id"], l2["name"], x["id"], x["name"],
                         x.get("en", ""), ", ".join(x.get("stage", [])), x.get("severity", "")])

out = ROOT / "output"
out.mkdir(exist_ok=True)
csv_path = out / "물리인적_보안위협_매트릭스_v0.csv"
with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.writer(f)
    w.writerow(["도메인", "위협분류 ID", "위협분류", "세부위협 ID", "세부위협", "영문명", "공격 단계", "심각도"])
    w.writerows(rows)
print(f"세부위협 {len(rows)}개 → {csv_path}")
print("NOTE: 최소 스텁입니다. ../supplychain/scripts/build_supplychain_threat_matrix.py 기준으로 확장하세요.")
EOF

# ---------------------------------------------------------------------------
# 13) 참조 자료 안내
# ---------------------------------------------------------------------------
w reference/README.md <<'EOF'
# 참조 자료 — 물리·인적 보안위협 매트릭스

빌드 입력으로 쓰는 원천 자료 안내. **공개 저장소이므로 유료 표준 원문·비공개 자료·개인정보는 올리지 않는다.**
재배포가 허용된 자료만 최소 추출본을 두고, 나머지는 ID·명칭만 `data/frameworks.yaml` 에 연계한다.

| 자료 | 용도 | 이용 조건 | 상태 |
| --- | --- | --- | --- |
| NIST SP 800-53 Rev.5 (PE·PS·MP) | 물리·인적·매체 통제 매핑 | 공공 영역 — 통제 ID·명칭 | 명칭 OSCAL에서 확정(TODO) |
| MITRE ATT&CK Enterprise | 물리 접점 기법(T1200·T1091·T1052…) | MITRE 이용약관 — 명칭·ID | 소수 매핑 |
| CISA Insider Threat Mitigation / Counter-UAS | 내부자·대드론 대응 기준 | 공공 영역 | 확인 후 편입(TODO) |
| MITRE Insider Threat TTP Knowledge Base | 내부자 기법 매핑 | MITRE 이용약관 | 확인 후 편입(TODO) |
| UK NPSA(구 CPNI) | 인적·물리 보안 지침 | 출처 표기 | 확인 후 편입(TODO) |
| ISO/IEC 27001 Annex A(물리)·ISO 22341 | 물리 통제 대응 | 유료 표준 — **원문 비수록, ID·제목만** | 확인 후 편입(TODO) |

> 사고 DB(`data/incidents.yaml`)의 사례는 정부 발표·법원 기소문·공신력 있는 보도 등 **1차 공개 출처 URL**을
> 반드시 함께 적는다. 개인 식별 세부는 공개 보도 수준으로 제한한다.
EOF

echo
echo "완료: 생성 $made개, 건너뜀 $skipped개"
echo "다음: physical/NEXT_SESSION.md 를 읽고 이어서 작업하세요. (참고 모델: ../supplychain/)"
