# sqli_extract.py

**OWASP:** A03:2021 - Injection (탐지가 아닌 **데이터 추출** 자동화 모듈)
**목적:** SQL Injection이 확인된 파라미터에서 DBMS 자동 식별 → DB / 테이블 / 컬럼 목록 수집 → 행 단위 데이터 dump → 엑셀 저장까지 일관 처리. 사용자가 명시적으로 "추출 모드"를 선택해 진입한다.

탐지 모듈 [sql_injection.py](sql_injection.py)와는 인터페이스를 공유하지 않으며, 별도 진입 함수와 상태 객체(`ExtractCtx`)로 동작한다.

---

## 지원 DBMS

| DBMS | Error | Boolean-blind | UNION | quote |
|------|:-----:|:-------------:|:-----:|:-----:|
| MySQL      | ✓ | ✓ | ✓ | `` `name` `` |
| MariaDB    | ✓ | ✓ | ✓ | `` `name` `` |
| MSSQL      | ✓ | ✓ | ✓ | `[name]` |
| PostgreSQL | ✓ | ✓ | ✓ (`NULL::TEXT` 캐스트) | `"name"` |
| Oracle     | ✓ | ✓ | ✓ | `"name"` |
| SQLite     | ✗ | ✓ | ✓ | `"name"` |

SQLite + Error 조합은 `UnsupportedTechniqueError`를 raise → 호출부(GUI)가 재선택 메뉴를 띄운다.

---

## 추출 기법

세 기법은 사용자가 명시적으로 선택하며 자동 fallback은 하지 않는다 (실패 시 호출부가 재선택 메뉴 제공). `fingerprint(ctx)` 단계는 사용자 delay와 무관하게 **최소 0.3s/요청**(`FINGERPRINT_DELAY_FLOOR`)을 강제한다.

`fingerprint` 1단계에서 `quote_context=None`이면 `CONTEXT_CANDIDATES`(`["'", '"', "')", '")', "'))", ")", ""]`) 우선순위로 컨텍스트를 자동 탐지한다. 후보마다 두 가지 판정을 순서대로 시도한다:
1. **Boolean 판정** — `AND 1=1` / `AND 1=2` 응답 유사도가 0.9 미만이면 채택.
2. **에러 전이 판정** — Boolean이 실패(유사도 ≥ 0.9)하고 후보가 빈 문자열이 아닐 때, 정상 종결 응답에 에러 시그니처가 없고 후보를 단독 주입했을 때 에러 시그니처가 발생하면 채택. error-based 전용 타겟(`'` 하나로 에러가 확인되나 Boolean 차이가 화면에 드러나지 않는 환경)을 커버한다. numeric 후보(빈 문자열)는 단독 주입 페이로드가 없어 이 판정 대상에서 제외된다.
모든 후보가 탈락하면 `None` 반환 → 호출부가 수동 지정 메뉴를 띄운다.

`fingerprint` 마지막 단계에서 선택된 기법의 **실제 추출 가능성 smoke test**를 1패킷 수행한다:
- **Error**: `_error_extract(ctx, "SELECT 1")` → 응답에 마커가 반사되지 않으면 `UnsupportedTechniqueError`
- **Boolean**: `_blind_compare` 1=1(true) vs 1=2(false) 분류 검증 → 동일 결과면 `UnsupportedTechniqueError`
- **UNION**: `_union_extract(ctx, "SELECT 1")` → 마커 반사 없으면 `UnsupportedTechniqueError`

smoke test 실패 시 에러 메시지: `"{기법} 기법으로 추출할 수 없습니다."` (DBMS 식별 성공 여부와 무관하게 추출 불가 확정 시점에 사용자에게 즉시 통보).

### Error-based

DBMS-specific 에러 함수에 데이터 추출 표현식을 주입하여 응답 본문에 노출되는 에러 메시지로 데이터를 회수한다.

| DBMS | 추출 함수 |
|------|----------|
| MySQL / MariaDB | `EXTRACTVALUE(1, CONCAT(0x7e, CHAR(ml), (...), CHAR(mr)))` |
| MSSQL | `CONVERT(int, (...))` |
| PostgreSQL | `CAST((...) AS int)` |
| Oracle | `CTXSYS.DRITHSX.SN(1, (...))` |

각 페이로드는 랜덤 marker pair로 감싸 응답에서 정확히 격리. 마커 리터럴은 `_char_encode_str`로 DBMS별 `CHAR(n,...)`(MySQL/MariaDB/SQLite) / `CAST(0x... AS VARCHAR(N))`(MSSQL, T-SQL CHAR 단일 인수 한계 + GET 요청 IIS maxQueryString 초과 방지를 위해 hex 리터럴 사용) / `CHR(n)||...`(PostgreSQL/Oracle) 형태로 인코딩하여 페이로드 echo 환경에서 마커 평문이 노출되지 않게 함 — 에러 메시지(실제 결과)에만 디코드된 마커가 나타나 regex가 정확히 에러 결과만 매칭.

MySQL/MariaDB 마커는 `g` + `token_hex(1)`(2자) = **3자** 구조로 EXTRACTVALUE 32 byte 한계 내 오버헤드를 최소화한다 (`~`(1) + ml(3) + mr(3) = 7자 오버헤드). 추출 데이터가 hex(0-9a-f)이므로 비 hex 문자 `g` prefix로 마커·데이터 경계 혼동을 방지한다. MSSQL/PostgreSQL/Oracle은 에러 메시지 여유가 충분해 공용 `gen_marker()`(9자)를 그대로 사용한다.

MySQL/MariaDB에는 XPATH 문자열이 알파벳으로 시작하면 MySQL이 유효한 노드 경로로 해석해 에러가 발생하지 않으므로, `0x7e`(`~`, 비 XPATH 문자)를 `CONCAT` 첫 인자로 추가해 강제 에러를 유발한다.

길이가 긴 결과는 `_extract_long_string`이 청크 단위로 분할 추출하며, 청크 hex 길이는 DBMS별 에러 메시지 출력 한계에 맞춰 차등 적용한다 (`ERROR_CHUNK_HEX`):

| DBMS | 청크 hex | 근거 |
|------|:-------:|------|
| MySQL / MariaDB | 20 | `EXTRACTVALUE` 32 byte 한계, 7자 오버헤드 제외 후 가용 25자 → 20으로 안전 마진 확보 |
| MSSQL | 200 | `CONVERT` 에러는 nvarchar(4000) 수준 여유 |
| PostgreSQL | 200 | `CAST` 에러는 8KB+ 여유 |
| Oracle | 200 | `UTL_INADDR`/`CTXSYS` 에러 ~512 byte 한계 내 안전 |
| SQLite | 30 | error-based 사용성 낮음 — 보수적 |

### Boolean-blind

응답 차이만으로 데이터를 추출. multibyte 안전을 위해 모든 문자열은 HEX 변환 후 비트 단위로 비교한다.

- 1행당 약 **421 요청** (`21 bits × 5` + 길이 21 bits, 평균 80자 가정)
- baseline은 quote_context 채택 직후 1회 캡처 (`_capture_baseline`):
  - `baseline_resp_text` (페이로드 없는 원본 2회) + `dynamic_contexts` (응답 변동 마스킹)
  - `true_ref_text` (`AND (1=1)`) + `false_ref_text` (`AND (1=0)`) — **dual baseline 분류용**
- `_blind_compare` 응답 분류:
  1. dual baseline 우선 — 응답을 `true_ref` / `false_ref` 양쪽과 sim 비교, 더 가까운 쪽으로 분류 (sqlmap 방식)
  2. fallback — true/false reference 캡처 실패 시 단일 baseline `_similarity ≥ BLIND_SIM_THRESHOLD(0.95)` 비교
- 응답에 페이로드 결과가 echo되어 byte 단위 변동이 큰 환경(예: VulnShop)에서는 단일 baseline 임계값 비교가 경계에서 흔들리므로 dual baseline이 안정적
- HEX 함수 매핑: MySQL/MariaDB/SQLite=`HEX`, MSSQL=`master.dbo.fn_varbintohexstr` (`0x` prefix strip), PostgreSQL=`ENCODE(::bytea,'hex')`, Oracle=`RAWTOHEX(UTL_RAW.CAST_TO_RAW)`

### UNION-based

사용자가 컬럼 수와 타입을 입력해야 동작한다 (자동 추정 안 함). visible 컬럼은 `fingerprint` 단계에서 자동 탐지하거나 수동 지정할 수 있다.

- 컬럼 타입 값: `int`(또는 `integer`/`numeric`) / `string` / `null`. 단일 타입 하나만 입력하면 컬럼 수만큼 자동 확장 (예: 컬럼 수=3, 타입=`null` → `["null","null","null"]`)
- `null` 타입 컬럼은 visible 탐지 후보에서 자동 제외됨
- **visible 컬럼 수동 지정**: API(`union_visible`) / UI("visible 컬럼 번호")로 수동 지정 가능. 사용자에게는 **1-based**로 노출 (1번 = 첫 번째 컬럼). 내부(`union_visible_manual`, `union_visible_idx`)는 0-based 유지. 수동 지정 시 `_detect_union_visible` 자동 탐지를 스킵하고 `fingerprint` 6단계 smoke test만 수행
- `SecTestS...SecTestE` 마커로 응답에서 데이터 정확 격리. 마커 리터럴은 `_char_encode_str`로 DBMS별 `CHAR(n,...)`(MySQL/MariaDB/SQLite) / `CAST(0x... AS VARCHAR(N))`(MSSQL) / `CHR(n)||...`(PostgreSQL/Oracle) 형태로 인코딩하여 페이로드에 평문이 들어가지 않게 함 — 응답 echo 환경에서도 렌더링 영역과 echo 영역이 자연스럽게 분리됨
- visible probe는 컬럼별 개별 탐지 방식을 사용 — 한 번에 한 컬럼(target_idx)에만 `SecTestS+SecTestC{idx}+SecTestE` sentinel-wrapped 마커를 삽입하고 나머지는 `_placeholder_literal`로 컬럼별 타입 더미를 채운다. 에러 메시지에 값이 평문 노출되어도(`'SecTestC4'을(를) int로 변환하지 못했습니다`) sentinel 쌍이 함께 나타나지 않으므로 DBMS 언어 설정에 무관하게 오탐을 방지한다. sentinel 전체 패턴(`SecTestSSecTestC{idx}SecTestE`)이 응답에 나타난 첫 컬럼을 visible로 채택한다
- 페이로드에 `AND 1=0`을 prefix로 추가해 원본 row를 ResultSet에서 제거 — 단일-row 렌더링 환경에서 UNION row가 첫번째로 오게 하여 visible 컬럼 탐지·추출이 정상 동작함
- `union_hex=True`(기본) — multibyte 안전 (HEX 인코딩 후 디코드)
- **묶음 추출** (`union_row_batch > 1`) — `list_databases` / `list_tables` / `list_columns` / `dump_table` 모두에 적용. DBMS별 집계 함수로 N개를 `ROW_DELIM`(`qROWMTRq`)으로 결합하여 한 요청에 추출한다. 요청 수를 약 1/N으로 줄이나, 집계 함수 길이 한계(MySQL/MariaDB `GROUP_CONCAT` 기본 1024B·Oracle `LISTAGG` 4000B)를 초과하면 None 또는 잘림이 발생한다. **윈도우 단위 폴백**으로 정확성 보장 — 묶음 결과가 None이거나 기대 항목 수보다 적으면 그 윈도우만 재추출. 목록 추출(DB/테이블/컬럼명)은 window=1 집계 폴백, 행 dump는 `_extract_single` 폴백 사용.

  | DBMS | 집계 함수 | 길이 한계 |
  |------|-----------|-----------|
  | MySQL / MariaDB | `GROUP_CONCAT(... SEPARATOR)` | 1024B(기본) — 초과 시 조용히 잘림 → 폴백 탐지 |
  | MSSQL 2017+ | `STRING_AGG(CAST(... NVARCHAR(MAX)), ...)` | 사실상 무제한 |
  | PostgreSQL | `STRING_AGG(r, ...)` | 사실상 무제한(TEXT) |
  | Oracle | `LISTAGG(...) WITHIN GROUP` | 4000B — 초과 시 ORA-01489 에러 → None → 폴백 |
  | SQLite | `GROUP_CONCAT(r, ...)` | 사실상 무제한 |
- 추출 페이로드·visible probe의 placeholder(visible 외 컬럼)는 `_placeholder_literal`이 `union_types` 기반으로 컬럼별 타입 더미를 생성한다. 대상 앱이 결과 컬럼을 정수 등으로 파싱하는 환경에서 NULL(→ 빈 문자열)이 `FormatException` 등을 유발하는 것을 방지한다. 타입별 더미: `int`/`integer`/`numeric` → `1`, `null` → `NULL`, `string` 또는 미지정 → `'a'`. MSSQL/PostgreSQL은 CAST 래퍼로 감싸 UNION 형식 충돌도 함께 방지한다 — MSSQL: `CAST(1 AS INT)` / `CAST(NULL AS VARCHAR(MAX))` / `CAST('a' AS VARCHAR(MAX))`, PostgreSQL: `1::INTEGER` / `NULL::TEXT` / `'a'::TEXT`. 확신 없는 컬럼은 `null`을 지정하면 기존 NULL 동작으로 안전하게 유지된다

---

## 핵심 데이터 구조

### `ExtractCtx` (`@dataclass`)

단일 추출 세션의 모든 상태를 보관한다. `allowed_netloc`은 1회 저장되어 모든 요청의 사전·사후 검증에 사용 (외부 도메인 유출 방어선).

| 필드 | 타입 | 설명 |
|------|------|------|
| `target_url` | `str` | path까지의 URL (query string 자동 분리) |
| `allowed_netloc` | `str` | `urlparse(target_url).netloc` |
| `method` | `str` | `"GET"` / `"POST"` |
| `body_type` | `str` | `"form"` / `"json"` / `"xml"` |
| `body_params` | `dict` | GET=query / POST=body 파라미터 |
| `vuln_param` | `str` | `body_params` 내 취약 파라미터 키 |
| `timeout` | `int` | 요청 timeout(초) |
| `delay` | `float` | 요청 간 딜레이(초) |
| `cookies` | `dict` | 세션 쿠키 |
| `technique` | `str` | `"error"` / `"boolean"` / `"union"` |
| `dbms` | `str` | fingerprint 결과로 채워짐 |
| `quote_context` | `Optional[str]` | `None`=자동 탐지 / `""`=numeric / `"'"` 등=수동 명시 |
| `auth_headers` | `dict` | Authorization 등 영구 부착 헤더 |
| `proxies` | `dict` | 프록시 설정 (BurpSuite 등). `{"http": "http://HOST:PORT", "https": "http://HOST:PORT"}`. 빈 dict이면 미사용 |
| `base64_encode` | `bool` | `True`이면 코드가 생성하는 SQL 페이로드만 Base64 인코딩 후 원본 파라미터 값에 append. 파라미터 값 자체는 변환하지 않음. Fingerprint 단계부터 적용됨 (기본 `False`) |
| `union_hex` | `bool` | UNION HEX 모드 (기본 `True`) |
| `union_columns` | `int` | UNION 컬럼 수 (technique=union 시 필수) |
| `union_types` | `List[str]` | UNION 컬럼 타입 — `int`/`string`/`null` 조합 (예: `["int","string","null"]`). 단일 타입 입력 시 컬럼 수만큼 자동 확장됨 |
| `union_visible_idx` | `int` | UNION visible 컬럼 인덱스 (자동 탐지 또는 수동 지정 결과) |
| `union_visible_manual` | `Optional[int]` | 사용자 수동 지정 visible 컬럼 인덱스 (0-based). `None`이면 `_detect_union_visible` 자동 탐지 |
| `union_row_batch` | `int` | UNION 행 묶음 크기. `1`=기존 1행씩. `N`=N행을 집계 함수로 한 요청에 추출 (기본 `1`; UI 기본 `10`) |
| `baseline_resp_text` | `Optional[str]` | Boolean-blind baseline 캐시 (페이로드 없는 응답) |
| `dynamic_contexts` | `List[Tuple[str,str]]` | Dynamic content masking context 쌍 |
| `waf_baseline_kws` | `List[str]` | baseline 응답에 자연 발생한 WAF 키워드 (오탐 마스킹) |
| `true_ref_text` | `Optional[str]` | dual baseline — `AND (1=1)` reference 응답 |
| `false_ref_text` | `Optional[str]` | dual baseline — `AND (1=0)` reference 응답 |
| `_session` | `requests.Session` | `_build_session()`으로 생성, 종료 시 close 필수 |
| `cancelled` | `bool` | 사용자 취소 플래그 (`_send`에서 체크 → `InterruptedError`) |
| `_throttle_retried` | `bool` | 429/503 자동 감속 1회 한정 플래그 |

### `extracted` dict (누적 결과)

`init_extracted(ctx)`로 초기화한다. 호출부(GUI/save_to_excel)가 동일 구조를 공유한다.

```python
{
    "meta": {
        "target":      str,   # ctx.target_url
        "method":      str,
        "body_type":   str,
        "param":       str,   # ctx.vuln_param
        "dbms":        str,
        "technique":   str,
        "context":     str | None,
        "started_at":  str,   # ISO 8601
        "finished_at": str,   # 종료 시점에 호출부가 채움
    },
    "dbms_info": {"version": str, "user": str, "current_db": str},
    "databases": list[str],                          # ["db1", "db2", ...]
    "tables":    {db: list[str]},                    # {"db1": ["users", ...]}
    "columns":   {"db.tbl": list[str]},              # {"db1.users": ["id","name",...]}
    "dumps":     {"db.tbl": {"columns": list[str], "rows": list[list[str]]}},
}
```

---

## 진입 함수 시그니처

| 함수 | 시그니처 | 용도 |
|------|----------|------|
| `_build_session` | `(cookies, auth_headers, proxies=None) -> requests.Session` | `verify=False` + 쿠키/인증 헤더/프록시 영구 부착 |
| `fingerprint` | `(ctx, progress_cb=None) -> ExtractCtx` | 컨텍스트·DBMS·UNION visible 자동 탐지 + 기법별 smoke test. 추출 불가 시 `UnsupportedTechniqueError` |
| `extract_dbms_info` | `(ctx, progress_cb=None) -> dict` | `{version, user, current_db}` 추출. 모든 값이 빈 문자열이면 `UnsupportedTechniqueError` raise (추출 불가 안전망) |
| `list_databases` | `(ctx, progress_cb=None) -> list[str]` | 페이지네이션으로 DB 목록 1개씩 |
| `list_tables` | `(ctx, db, progress_cb=None) -> list[str]` | 특정 DB의 테이블 목록 |
| `list_columns` | `(ctx, db, table, progress_cb=None) -> list[str]` | 특정 테이블의 컬럼 목록 |
| `count_table` | `(ctx, db, table) -> Optional[int]` | 테이블 전체 행 수 추출 (estimate/dump 공용) |
| `dump_table` | `(ctx, db, table, columns, total=None, progress_cb=None, rows_out=None) -> list[list[str]]` | 처음~끝 전체 행 추출. `total` 전달 시 COUNT 생략. `rows_out` 전달 시 해당 리스트에 행을 append (취소 시 누적 행 보존). 취소 시 `InterruptedError` 전파. `qDLMTRq` 구분자 split |
| `save_to_excel` | `(extracted, target_url, output_dir, excel_name=None) -> list[str]` | 마스터 파일(INFO+DBList) + DB별 파일(INFO+_TableMap+테이블 시트) 생성. 동일 이름이면 항상 덮어쓰기 |
| `init_extracted` | `(ctx) -> dict` | 누적 dict 표준 초기화 |
| `find_existing_extract` | `(excel_name, output_dir) -> dict \| None` | 해당 이름의 마스터 파일 존재 여부 확인 + 요약 반환 (`{dbms, technique, context, union_*, db_count}`) |
| `load_from_excel` | `(excel_name, output_dir) -> (extracted, ctx_meta) \| None` | 엑셀 파일에서 이전 추출 결과 복원. `ctx_meta`는 fingerprint 자동탐지 생략에 사용 |

`progress_cb`는 `(current, total)` 형식으로 호출되며 GUI `action_progress` 매핑에 사용된다.

---

## 메타 쿼리 페이지네이션

DB/테이블/컬럼 목록은 한 번에 가져오지 않고 행 단위 페이지네이션으로 1개씩 추출한다 (응답 길이 제한 회피).

| 추출 대상 | 기본 패턴 (1개씩) | UNION 묶음 패턴 (N개씩) |
|-----------|-------------------|------------------------|
| Database 목록 | `LIMIT 1 OFFSET n` / `OFFSET n FETCH 1` | `_q_base_databases` → `_q_batch_list` → `GROUP_CONCAT`/`STRING_AGG`/`LISTAGG` + `ROW_DELIM` split |
| Table 목록 | `WHERE TABLE_SCHEMA=db ORDER BY TABLE_NAME LIMIT 1 OFFSET n` | 동일 방식 (`_q_base_tables` 기반) |
| Column 목록 | `ORDER BY ORDINAL_POSITION LIMIT 1 OFFSET n` | 동일 방식 (`_q_base_columns` 기반) |
| Row dump (1행씩) | `SELECT col1\|\|DELIM\|\|col2 FROM tbl LIMIT 1 OFFSET n` (NULL-safe + `qDLMTRq`) | — |
| Row dump (UNION 묶음) | — | DBMS 집계 함수로 N행을 `ROW_DELIM`(`qROWMTRq`)으로 결합 후 HEX 추출 |

DBMS별 차이:
- **MySQL/MariaDB**: `LIMIT offset,1`
- **MSSQL**: `ORDER BY ... OFFSET n ROWS FETCH NEXT 1 ROWS ONLY`
- **PostgreSQL**: `LIMIT 1 OFFSET n` + `string_agg`
- **Oracle**: `ROW_NUMBER() OVER` 서브쿼리 또는 `OFFSET n ROWS FETCH NEXT 1 ROWS ONLY`
- **SQLite**: `LIMIT 1 OFFSET n` (`databases` 추출은 `["main"]` 고정)

`dump_table` 컬럼 구분자는 응답 본문 중간 컬럼이 `DUMP_DELIM`(=`qDLMTRq`)을 자연 포함할 가능성이 매우 낮은 q-prefix 마커를 사용한다.

---

## WAF 가드 / 도메인 경계

### WAF 검출 (`_is_waf_response`)
- **status code**: 403 / 406 / 419 / 429 / 503
- **body 키워드**: `access denied` / `blocked` / `forbidden`
- 두 신호의 **결합**으로 판정. baseline에 자연 발생한 키워드는 `ctx.waf_baseline_kws`에 등록되어 오탐 마스킹
- 검출 시 `WAFBlockedError` raise → 호출부가 안전 종료 + 누적 데이터 엑셀 저장

### 자동 감속 (429 / 503)
- 첫 검출 시 `delay × 2` (delay=0이면 1.0초, 최대 5.0초 상한)로 증가 후 1회 재시도 (`_throttle_retried` 플래그)
- 2회째 동일 응답이면 `WAFBlockedError` raise → 추출 중단

### 네트워크 오류 재시도
- timeout / connection 오류 발생 시 1초 대기 후 1회 재시도 (재시도 후에도 실패하면 예외 전파)

### 도메인 경계 (3중)
1. **ExtractCtx 생성 시** — `allowed_netloc = urlparse(target_url).netloc` 1회 저장
2. **`_send` 사전 검증** — 요청 URL의 netloc이 `ctx.allowed_netloc`과 다르면 즉시 차단
3. **`_send` 사후 검증** — 리다이렉트 후 최종 URL의 netloc이 다르면 응답 폐기 (세션 쿠키 유출 방지)

### 인증 헤더
`auth_headers`(예: `{"Authorization": "Bearer xxx", "X-API-Key": "..."}`)는 `_build_session`에서 `Session.headers`에 등록되어 fingerprint·메타 쿼리·dump 모든 요청에 자동 부착.

---

## 엑셀 저장 규칙

`save_to_excel(extracted, target_url, output_dir, excel_name=None)`은 보안·호환성을 위해 sanitize 다층 적용. 동일 `excel_name`으로 호출 시 항상 덮어쓰기.

저장 타이밍:
- **fingerprint 완료 직후** — 마스터 파일(INFO+빈 DBList) 즉시 생성. 이후 액션에서 덮어쓰기로 갱신.
- **액션 단위** — 각 액션(dbms_info / databases / tables / columns) 정상 완료 시 `_save_excel_incremental`이 호출되어 로그(`excel_updates`) 1줄 기록.
- **dump 30초 체크포인트** — dump 진행 중 progress 콜백에서 30초마다 `_save_excel_file`(로그 없는 조용한 flush). 수만 행 추출 시 중간 저장 보장.
- **중단(stop) 시** — `InterruptedError` 핸들러에서 `_save_excel_file` 호출 후 ready 복귀. reset(초기화)이면 저장 없이 폐기.

### 파일 구조

| 파일명 | 시트 | 내용 |
|--------|------|------|
| `extract_<name>_DBfingerprint.xlsx` | INFO | 메타 + Fingerprint 결과 + UNION 정보 (복원용) |
| | DBList | DB 목록 (1행=헤더 "DB명", 2행~=DB이름) |
| `extract_<name>_<db>.xlsx` | INFO | 메타 |
| | _TableMap | 시트명 ↔ 원본 테이블명 매핑 (복원 시 정확성 보장) |
| | 테이블별 | 1행=컬럼 헤더, 2행~=행 데이터 |

### 파일명 sanitize
- `_safe_filename`: `..` / `/` / `\` / Windows 예약어(`CON`/`PRN`/`AUX`/`NUL`/`COM*`/`LPT*`) 차단

### 시트명
- `_safe_sheet_name`: 31자 제한 + 금지문자 `[]:*?/\\` `_` 치환 + `INFO`·`_TABLEMAP` 충돌·중복 dedup
- `tables_index` 순서를 기준으로 전체 테이블을 항상 시트로 보존 — dump된 테이블은 헤더+행 데이터, dump되지 않은 테이블은 컬럼 헤더만(또는 빈 시트). `tables_index`에 없으나 dump에만 존재하는 테이블은 뒤에 추가

### 셀
- `_safe_cell_value`: `=` / `+` / `-` / `@` / `\t` / `\r`로 시작하면 `'` prefix 부착 → **Excel formula injection 차단**
- `_restore_cell_value`: 읽기 시 `'` prefix 제거 (load_from_excel 복원 전용)
- `None`은 빈 문자열로

### INFO 시트 항목
Target / Method / Body Type / Param / DBMS / Technique / Context / Database / Started / Finished / Version / User / Current DB / Union Columns / Union Types / Union Visible

Union 관련 행 3개가 추가됨 — `load_from_excel`이 ctx 재구성에 사용.

### 이전 결과 복원 (`load_from_excel`)
1. 마스터 파일 INFO → ctx 핵심값 (dbms / technique / context / union 정보) 복원 → fingerprint **자동탐지만 생략** (비싼 컨텍스트 7종 × DBMS probe 건너뜀)
2. 마스터 파일 DBList → `extracted["databases"]`
3. DB별 파일 `_TableMap` → 원본 테이블명 복원, 각 시트 헤더 → `columns`, 데이터 → `dumps` (저장된 만큼만, 행 단위 resume 없음)

---

## 사용 예시

### Python 모듈로 직접
```python
from modules import sqli_extract

ctx = sqli_extract.ExtractCtx(
    target_url="https://target.example/post.php",
    allowed_netloc="target.example",
    method="POST",
    body_type="form",
    body_params={"id": "1", "cat": "2"},
    vuln_param="id",
    timeout=10,
    delay=1.5,
    cookies={"SESSIONID": "abc"},
    technique="boolean",
    dbms="",
    quote_context=None,  # 자동 탐지
    auth_headers={"Authorization": "Bearer xyz"},
)
ctx._session = sqli_extract._build_session(ctx.cookies, ctx.auth_headers)
extracted = sqli_extract.init_extracted(ctx)

try:
    sqli_extract.fingerprint(ctx)
    extracted["dbms_info"] = sqli_extract.extract_dbms_info(ctx)
    extracted["databases"] = sqli_extract.list_databases(ctx)
    # ... tables / columns / dump_table 호출 후 extracted dict 누적
finally:
    extracted["meta"]["finished_at"] = "..."
    sqli_extract.save_to_excel(extracted, ctx.target_url, "./reports")
    if ctx._session:
        ctx._session.close()
```

대시보드 사이드바의 **"데이터 추출 (SQLi)"** 탭 → 입력 폼에서 [데이터 엑셀 저장] 체크 후 Fingerprint 시작 → 액션 패널(DBMS 정보 / 데이터 추출 시작) → 액션 완료마다 `./reports/`에 자동 저장되며 Fingerprint 결과 카드 하단에 갱신 내역 표시
