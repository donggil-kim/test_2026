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
