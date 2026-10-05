# 통합 소프트웨어 공급망 보안위협 매트릭스

개발 환경·소스·의존성·빌드·게시·배포·소비에 이르는 소프트웨어 공급망 전 단계의 위협을 하나의 매트릭스로 정리했습니다.
앞서 만든 **통합 AI 보안위협 매트릭스 v3.2**, **통합 클라우드 보안위협 매트릭스 v5**, **통합 OT 보안위협 매트릭스**의
구조(분류 → 위험평가 → 실제근거)와 산정 로직을 공급망에 이식했습니다.

- **분류**: 공급망 단계(공격면) 8개 도메인 → 위협분류 32개 → 세부위협 60개(`data/taxonomy.yaml`)
- **교차 매핑**: MITRE ATT&CK v19.2 · SLSA v1.2 위협 모델 · OWASP Top 10 CI/CD · OWASP Top 10 OSS · SAP Risk Explorer 공격 벡터(52개 전부) · CNCF 침해 유형
- **실제 근거**: 공급망 보안사고 DB 167건(2003~2026, 공개 출처) · ATT&CK 공급망 맥락 절차 · CISA KEV 공급망 판정 80건 · OSV 악성 패키지 23.9만 건
- **대응 기준**: OpenSSF S2C2F · NIST SSDF · OpenSSF Scorecard · NIST SP 800-53 · SAP 대응책
- **다른 매트릭스 연계**: 통합 AI·클라우드 매트릭스 v1(AI-·CL-), 통합 OT 매트릭스(OTC-)

> 위치: 앞선 OT 매트릭스와 같이 이 저장소의 `supplychain/` 폴더에 두었습니다. 모든 경로가 이 폴더 기준이라 폴더째 옮겨도 빌드됩니다.

## 산출물

| 경로 | 설명 |
|---|---|
| `output/통합_공급망보안위협_매트릭스_v1.xlsx` | v1 — 분류 체계·교차 매핑·근거 집계·위험평가(공급망 관점 문구는 v2) |
| `output/통합_공급망보안위협_매트릭스_v1.csv` | 세부위협 60행 요약(검토·diff용, UTF-8 BOM) |

## 도메인(Lv1)

| 코드 | 도메인 | 범위 |
|---|---|---|
| DE | 개발 환경 | 개발자 단말·IDE 확장·개발 도구 체인·AI 코딩 도구·MCP·에이전트 스킬 |
| SR | 소스 저장소 | 악의적 기여·메인테이너 악용·리뷰 우회·태그·이력 조작·SCM 플랫폼 침해 |
| DP | 의존성 | 이름 혼동·의존성 혼동·재점유·악성 패키지·설치 시점 실행·취약 구성요소·가변 참조·악성 모델 |
| BD | 빌드·CI/CD | 오염된 파이프라인 실행(PPE)·빌드 주입·캐시 오염·러너 장악·CI/CD 서버·SaaS·서드파티 액션 |
| SC | 비밀·자격증명 | 비밀 노출·러너 비밀 수집·게시 토큰·OIDC 탈취·과다 권한 토큰·메인테이너 계정 탈취 |
| PB | 게시·배포 | 악성 버전 게시·다운로드 사이트·업데이트 채널·전송 경로·서명 키·레지스트리 |
| CS | 소비·서드파티 연계 | 검증 없는 수용·MSP·RMM·내부 배포 도구·공급업체 접근·SaaS 연동 토큰·웹 스크립트·필수 설치 SW |
| IM | 영향·확산 | 다운스트림 대량 침해·연쇄 공급망 침해·자가 전파 웜·비밀·소스 반출·금전 탈취·파괴 |

## 재생성

```bash
pip install openpyxl pyyaml
python3 scripts/build_supplychain_threat_matrix.py   # output/ 에 워크북·CSV 생성

# (선택) ATT&CK 추출본 재생성 — 저장소 루트의 enterprise-attack-v19.2.xlsx 사용
python3 scripts/prepare_attack.py
# (선택) OSV 악성 패키지 집계 재생성
git clone --depth 1 --filter=blob:none --no-checkout https://github.com/ossf/malicious-packages.git /tmp/malpkg
python3 scripts/prepare_osv_counts.py --repo /tmp/malpkg
```

자세한 방법론·문구 작성 기준은 v2에서 `docs/methodology.md`와 함께 정리합니다. 참조 자료와 이용 조건은 [`reference/README.md`](reference/README.md)를 보세요.
