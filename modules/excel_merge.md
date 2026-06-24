# excel_merge.py — 엑셀 취합 모듈

## 개요

다중 엑셀/CSV 파일을 스키마 합집합(UNION ALL) 방식으로 단일 xlsx로 병합한다.
파일마다 컬럼 구성이 달라도 처리 가능하며, 처음 보는 컬럼을 만나면 출력에 신규 컬럼을 추가하면서 데이터를 누적한다.

탐지 모듈(`scan()` 인터페이스)과 무관한 **별도 모드 유틸**이다.

---

## 공개 함수

### `merge_workbooks(sources) -> dict`

```python
sources: List[Tuple[str, bytes]]  # [(파일명, 바이트스트림), ...]
```

반환 dict:

| 키 | 타입 | 설명 |
|----|------|------|
| `columns` | `List[str]` | 최종 컬럼 목록. 0번째는 항상 `"출처파일"` |
| `rows` | `List[Dict[int, Any]]` | 행 리스트 — `{master_col_index: value}` dict |
| `per_file` | `List[dict]` | 파일별 처리 통계 |
| `total_rows` | `int` | 누적 총 행 수 |
| `skipped_files` | `List[str]` | 처리 실패/미지원 파일명 목록 |

`per_file` 항목 구조:

| 키 | 설명 |
|----|------|
| `name` | 파일명 |
| `sheets_read` | 읽은 시트 수 |
| `rows_added` | 누적된 행 수 |
| `new_columns` | 이 파일에서 처음 등장한 신규 컬럼 목록 |
| `skipped` | 처리 실패 여부 |
| `error` | 실패 시 오류 메시지 |

---

### `save_merged(result, output_dir, out_name) -> str`

병합 결과를 `Merged` 시트 단일 xlsx로 저장하고 절대경로를 반환한다.

- 출력 파일명: `merge_{out_name}_{YYYYMMDD_HHMMSS}.xlsx`
- 빠진 컬럼은 빈칸으로 채워 모든 행이 동일한 열 수를 유지한다
- 수식 인젝션 방어: `=`/`+`/`-`/`@`/탭/CR 시작 문자열에 `'` prefix 부착

---

### `iter_sheets(filename, data) -> Generator`

파일명 확장자로 포맷을 판별해 `(시트명, 행 리스트)` 쌍을 yield한다.

| 확장자 | 리더 | 비고 |
|--------|------|------|
| `.xlsx` / `.xlsm` | openpyxl | `read_only=True, data_only=True` — 수식은 계산값 |
| `.xls` | xlrd | 날짜 셀은 `xldate_as_datetime`으로 datetime 변환 |
| `.csv` | stdlib csv | BOM→utf-8-sig→utf-8→cp949 인코딩 폴백 |
| 그 외 | — | `ValueError` raise |

---

## 알고리즘 상세

### 스키마 합집합 (핵심)

```
master_cols = ["출처파일"]          # 0번째 예약 컬럼
col_index   = {"출처파일": 0}       # 컬럼명 → master 위치 O(1) 조회

for (filename, data) in sources:
    for (sheet_label, raw_rows) in iter_sheets(filename, data):
        header = raw_rows[0]
        local_map = []
        for name in header:
            if name not in col_index:   # 처음 보는 컬럼 → 추가
                col_index[name] = len(master_cols)
                master_cols.append(name)
            local_map.append(col_index[name])
        for data_row in raw_rows[1:]:
            rec = {0: filename}         # 출처파일
            for i, val in enumerate(data_row):
                rec[local_map[i]] = val
            rows_out.append(rec)
```

### 엣지 케이스 처리

| 상황 | 처리 |
|------|------|
| 빈 헤더 셀 | `(빈컬럼_N)` 전역 고유명 부여 (N은 전역 단조증가 카운터) |
| 시트 내 중복 헤더 | 두 번째부터 `.1` `.2` ... 접미사 분리 |
| 데이터 컬럼명 = `출처파일` | `출처파일.1`로 rename (예약 컬럼 보호) |
| 완전 빈 헤더 시트 | 스킵 |
| 완전 빈 데이터 행 | 스킵 |
| 미지원 확장자 | `per_file[].skipped = True`, `per_file[].error` 기록 후 다음 파일 진행 |
| 파일 손상·읽기 오류 | 동일하게 skipped 처리 |

---

## 의존성

| 패키지 | 용도 | 설치 |
|--------|------|------|
| `openpyxl` | .xlsx/.xlsm 읽기 + 결과 저장 | `_ensure_merge_deps()` lazy 설치 |
| `xlrd` | .xls 읽기 | `_ensure_merge_deps()` lazy 설치 |
| `csv` (stdlib) | .csv 읽기 | 추가 설치 불필요 |
