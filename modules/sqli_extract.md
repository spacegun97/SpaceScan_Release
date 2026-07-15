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

SQLite + Error 조합, 그리고 SQLite + `position` in `{where_case, orderby}` 조합은 `UnsupportedTechniqueError`를 raise → 호출부(GUI)가 재선택 메뉴를 띄운다.

---

## 추출 기법

세 기법은 사용자가 명시적으로 선택하며 자동 fallback은 하지 않는다 (실패 시 호출부가 재선택 메뉴 제공). `fingerprint(ctx)` 단계는 사용자 delay와 무관하게 **최소 0.3s/요청**(`FINGERPRINT_DELAY_FLOOR`)을 강제한다.

`fingerprint` 단계는 아래 순서로 진행한다.

**1단계 — DBMS 식별:** CASE WHEN 에러 오라클 페이로드가 DBMS에 따라 달라지므로 컨텍스트 탐지 전에 DBMS를 먼저 식별한다.

**2단계 — 컨텍스트 + 위치 탐지:** `position="custom"`이면 사용자가 `blind_template`에 qc·구조 전부를 포함하므로 컨텍스트 탐지·위치 탐지를 모두 스킵한다. 그 외의 경우 `_detect_context`가 `quote_context`와 `position`을 통합 탐지한다. 두 단계 페이즈로 구성된다.
- **Phase 1 (WHERE AND 위치)**: `quote_context=None`이면 `CONTEXT_CANDIDATES`(`["'", '"', "')", '")', "'))", ")", ""]`) 우선순위로 후보마다 두 가지 판정을 시도한다. ① Boolean 판정 — `AND 1=1` / `AND 1=2` 응답 유사도 0.9 미만이면 채택 (`position="where"` 확정). ② 에러 전이 판정 — Boolean 실패 시 후보 단독 주입으로 에러 시그니처 발생 여부 판정 (error-based 전용 환경 커버, numeric 후보 제외). Phase 1 성공 시 `position="where"`로 확정.
- **Phase 2 (CASE WHEN 에러 오라클 위치)**: technique=`boolean` + `dbms in COND_ERR_SUBQUERY` 조건 하에 Phase 1 실패 후 시도한다. `where_case`(WHERE 절 CASE WHEN 에러 오라클), `orderby`(ORDER BY 절 CASE WHEN 에러 오라클) 순으로 탐지한다. TRUE 조건 응답에 에러 시그니처가 없고 TRUE/FALSE 응답 유사도 0.9 미만이면 채택.

모든 후보가 탈락하면 `None` 반환 → 호출부가 수동 지정 메뉴를 띄운다.

**3단계 — 충돌 검증:** SQLite + Error 또는 SQLite + `{where_case, orderby}` 조합이면 `UnsupportedTechniqueError` raise. `custom`은 사용자 완전 제어이므로 SQLite 제한 비적용.

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

길이가 긴 결과는 `_extract_long_string`이 청크 단위로 분할 추출한다. `use_hex=True`(기본)면 HEX 인코딩 후 청크 분할·디코드로 멀티바이트 안전, `use_hex=False`(raw)면 원문에 `LENGTH`/`SUBSTRING`을 직접 적용 — ASCII/단일바이트 데이터 전용이며 청크당 실 데이터량이 2배가 되어 요청 수가 약 절반으로 준다. 청크 길이는 DBMS별 에러 메시지 출력 한계에 맞춰 차등 적용하며, raw 모드도 같은 문자 수 예산을 그대로 재사용한다(안전 마진 내) (`ERROR_CHUNK_HEX`):

| DBMS | 청크 길이(문자) | 근거 |
|------|:-------:|------|
| MySQL / MariaDB | 20 | `EXTRACTVALUE` 32 byte 한계, 7자 오버헤드 제외 후 가용 25자 → 20으로 안전 마진 확보 |
| MSSQL | 200 | `CONVERT` 에러는 nvarchar(4000) 수준 여유 |
| PostgreSQL | 200 | `CAST` 에러는 8KB+ 여유 |
| Oracle | 200 | `UTL_INADDR`/`CTXSYS` 에러 ~512 byte 한계 내 안전 |
| SQLite | 30 | error-based 사용성 낮음 — 보수적 |

### Boolean-blind

응답 차이만으로 데이터를 추출. `use_hex=True`(기본)면 모든 문자열을 HEX 변환 후 비트 단위로 비교 — 멀티바이트(한글 등) 안전. `use_hex=False`(raw)면 원문 글자를 코드값(0~255) 이분탐색으로 직접 추출 — ASCII/단일바이트 데이터 전용(멀티바이트는 DBMS별 ascii/ord/unicode 함수 반환값이 달라 부정확)이며 HEX 변환이 없어 요청 수가 더 적다.

**주입 위치(position) — 3가지:**

| `position` | 페이로드 형태 | 사용 조건 |
|------------|--------------|-----------|
| `where` (기본) | `{qc} AND ({cond}) --` | WHERE 절 Boolean 차이 관찰 가능 환경 |
| `where_case` | `{qc} AND 1=(CASE WHEN ({cond}) THEN 1 ELSE {err_sub} END) --` | WHERE Boolean은 안 보이나 DBMS 에러 발생 여부로 TRUE/FALSE 구분 가능 환경 |
| `orderby` | `{qc},(CASE WHEN ({cond}) THEN 1 ELSE {err_sub} END) --` | ORDER BY 절 뒤에 위치한 인젝션 포인트 |
| `custom` | `ctx.blind_template`의 `{cond}` 치환 | 자동 탐지가 불가한 비표준 구조 — qc·CASE WRAP·주석 모두 사용자 직접 작성 |

`where_case`·`orderby`는 CASE WHEN TRUE 시 스칼라(정상), FALSE 시 다중 행 서브쿼리(`{err_sub}`)로 에러를 유발하는 에러 오라클 방식이다. `err_sub`는 DBMS별 `COND_ERR_SUBQUERY` 상수에서 조회한다 (Oracle만 `FROM dual` 포함). SQLite는 다중 행 에러 오라클 미지원.

`custom` position은 사용자가 SQL 구조 전체를 제어하므로 qc 탐지·위치 탐지를 모두 스킵하고 SQLite 제한도 적용하지 않는다. `{cond}`를 `.replace("{cond}", condition)` 방식으로 치환한다 (`.format()` 미사용 — 중괄호 충돌 방지).

`_build_blind_compare_payload(ctx, condition)`이 `ctx.position`을 참조해 세 형태 중 하나를 선택하며, binary search(`_blind_string`, `_blind_int`) / baseline 캡처(`_capture_baseline`) / smoke test 모두 이 함수를 거치므로 position 변경 효과가 전 추출 과정에 자동 반영된다.

- 1행당 약 **421 요청** (`21 bits × 5` + 길이 21 bits, 평균 80자 가정, `use_hex=True` 기준). `use_hex=False`면 글자당 비교 횟수가 HEX 10회(2 hex-char×5) → raw 8회(0~255 범위)로 줄어 요청 수가 소폭 감소한다(ASCII/단일바이트 데이터 한정)
- baseline은 quote_context 채택 직후 1회 캡처 (`_capture_baseline`):
  - `baseline_resp_text` (페이로드 없는 원본 2회) + `dynamic_contexts` (응답 변동 마스킹)
  - `true_ref_text` (`AND (1=1)`) + `false_ref_text` (`AND (1=0)`) — **dual baseline 분류용**
- `_blind_compare` 응답 분류:
  1. dual baseline 우선 — 응답을 `true_ref` / `false_ref` 양쪽과 sim 비교, 더 가까운 쪽으로 분류 (sqlmap 방식)
  2. fallback — true/false reference 캡처 실패 시 단일 baseline `_similarity ≥ BLIND_SIM_THRESHOLD(0.95)` 비교
- 응답에 페이로드 결과가 echo되어 byte 단위 변동이 큰 환경(예: VulnShop)에서는 단일 baseline 임계값 비교가 경계에서 흔들리므로 dual baseline이 안정적
- **Boolean-blind 전용 HEX 정규화 (`_blind_hex_expr`)**: `_blind_char_in_range`의 이분탐색 범위는 `[48,70]`(ASCII '0'~'F', 대문자 hex 전용)으로 고정된다. PostgreSQL `ENCODE(::bytea,'hex')`는 소문자 출력, MSSQL `fn_varbintohexstr`는 소문자 + `0x` 접두사를 붙여 이 범위를 벗어난다. Boolean 경로에서만 사용하는 `_blind_hex_expr`가 각각 `UPPER(ENCODE(...))`, `UPPER(SUBSTRING(...,3,MAX))`로 감싸 항상 대문자·접두사 없는 형태로 정규화한다. Error-based/UNION은 정규식+`_decode_hex`로 대소문자·접두사를 모두 처리하므로 이 정규화가 불필요하다.
- HEX 함수 매핑: MySQL/MariaDB/SQLite=`HEX`, MSSQL=`master.dbo.fn_varbintohexstr` (`0x` prefix strip, Boolean에서는 추가로 `UPPER(SUBSTRING(…,3,MAX))`), PostgreSQL=`ENCODE(::bytea,'hex')` (Boolean에서는 `UPPER(ENCODE(…))`), Oracle=`RAWTOHEX(UTL_RAW.CAST_TO_RAW)`

### UNION-based

사용자가 컬럼 수와 타입을 입력해야 동작한다 (자동 추정 안 함). visible 컬럼은 `fingerprint` 단계에서 자동 탐지하거나 수동 지정할 수 있다.

- 컬럼 타입 값: `int`(또는 `integer`/`numeric`) / `string` / `null`. 단일 타입 하나만 입력하면 컬럼 수만큼 자동 확장 (예: 컬럼 수=3, 타입=`null` → `["null","null","null"]`)
- `null` 타입 컬럼은 visible 탐지 후보에서 자동 제외됨
- **visible 컬럼 수동 지정**: API(`union_visible`) / UI("visible 컬럼 번호")로 수동 지정 가능. 사용자에게는 **1-based**로 노출 (1번 = 첫 번째 컬럼). 내부(`union_visible_manual`, `union_visible_idx`)는 0-based 유지. 수동 지정 시 `_detect_union_visible` 자동 탐지를 스킵하고 `fingerprint` 6단계 smoke test만 수행
- `SecTestS...SecTestE` 마커로 응답에서 데이터 정확 격리. 마커 리터럴은 `_char_encode_str`로 DBMS별 `CHAR(n,...)`(MySQL/MariaDB/SQLite) / `CAST(0x... AS VARCHAR(N))`(MSSQL) / `CHR(n)||...`(PostgreSQL/Oracle) 형태로 인코딩하여 페이로드에 평문이 들어가지 않게 함 — 응답 echo 환경에서도 렌더링 영역과 echo 영역이 자연스럽게 분리됨
- visible probe는 컬럼별 개별 탐지 방식을 사용 — 한 번에 한 컬럼(target_idx)에만 `SecTestS+SecTestC{idx}+SecTestE` sentinel-wrapped 마커를 삽입하고 나머지는 `_placeholder_literal`로 컬럼별 타입 더미를 채운다. 에러 메시지에 값이 평문 노출되어도(`'SecTestC4'을(를) int로 변환하지 못했습니다`) sentinel 쌍이 함께 나타나지 않으므로 DBMS 언어 설정에 무관하게 오탐을 방지한다. sentinel 전체 패턴(`SecTestSSecTestC{idx}SecTestE`)이 응답에 나타난 첫 컬럼을 visible로 채택한다
- 페이로드에 `AND 1=0`을 prefix로 추가해 원본 row를 ResultSet에서 제거 — 단일-row 렌더링 환경에서 UNION row가 첫번째로 오게 하여 visible 컬럼 탐지·추출이 정상 동작함
- `use_hex=True`(기본, Error/Boolean과 공유되는 토글) — multibyte 안전 (HEX 인코딩 후 디코드). `use_hex=False`면 원문 그대로 추출 — UNION은 EXTRACTVALUE 같은 응답 출력 길이 제한이 없어 raw 추출도 안전하지만, 대상 앱이 결과를 파싱하는 방식에 따라 제어문자 등이 문제될 수 있다
- **묶음 추출** (`union_row_batch > 1`) — `list_databases` / `list_tables` / `list_columns` / `dump_table` 모두에 적용. DBMS별 집계 함수로 N개를 `ROW_DELIM`(`qROWMTRq`)으로 결합하여 한 요청에 추출한다. 요청 수를 약 1/N으로 줄이나, 집계 함수 길이 한계(MySQL/MariaDB `GROUP_CONCAT` 기본 1024B·Oracle `LISTAGG` 4000B)를 초과하면 None 또는 잘림이 발생한다. **적응형 batch 강등** — 윈도우에서 잘림(`got < window`) 또는 묶음 실패(None) 최초 감지 시 `batch_degraded=True`로 전환하여 해당 테이블/목록의 나머지 항목을 묶음 재시도 없이 바로 1개씩 추출한다. 행이 넓어 매 윈도우가 예측 가능하게 잘리는 환경에서 "버려지는 묶음 요청"이 반복되는 것을 방지하며, 행이 좁은 환경은 잘림이 없어 기존과 동일하게 묶음 이득을 유지한다. 목록 추출(DB/테이블/컬럼명)은 window=1 집계 폴백, 행 dump는 `_extract_single` 폴백 사용.

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
| `position` | `Optional[str]` | `None`=자동 탐지 / `"where"`(기본) / `"where_case"`(WHERE CASE WHEN 에러 오라클) / `"orderby"`(ORDER BY CASE WHEN 에러 오라클) / `"custom"`(사용자 전체 템플릿). technique=`boolean` 전용. `fingerprint` 완료 후 항상 비-None으로 확정됨 |
| `blind_template` | `Optional[str]` | `position="custom"` 전용 — 전체 페이로드 템플릿 문자열. `{cond}` 자리표시자를 이진탐색 조건으로 치환. 예: `"' AND 1=(CASE WHEN ({cond}) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)-- "`. `custom` 외 position이면 미사용 |
| `auth_headers` | `dict` | Authorization 등 영구 부착 헤더 |
| `proxies` | `dict` | 프록시 설정 (BurpSuite 등). `{"http": "http://HOST:PORT", "https": "http://HOST:PORT"}`. 빈 dict이면 미사용 |
| `base64_encode` | `bool` | `True`이면 코드가 생성하는 SQL 페이로드만 Base64 인코딩 후 원본 파라미터 값에 append. 파라미터 값 자체는 변환하지 않음. Fingerprint 단계부터 적용됨 (기본 `False`) |
| `use_hex` | `bool` | HEX 인코딩 모드 — Error/Boolean/UNION 세 기법 공통 (기본 `True`). `False`(raw)면 요청 수가 줄지만 ASCII/단일바이트 데이터 전용 |
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
| `masked_true_ref` | `Optional[str]` | `_capture_baseline`에서 1회 마스킹한 true_ref 캐시 — `_blind_compare`가 매 호출마다 재마스킹하지 않도록 |
| `masked_false_ref` | `Optional[str]` | 동일 목적의 false_ref 마스킹 캐시 |
| `masked_baseline` | `Optional[str]` | 단일 baseline 마스킹 캐시 (dual baseline 사용 불가 시 fallback용) |
| `_session` | `requests.Session` | `_build_session()`으로 생성, 종료 시 close 필수 |
| `cancelled` | `bool` | 사용자 취소 플래그. `_send` 요청 직전 체크 + 요청 간 딜레이를 `_throttle()`이 50ms 간격 폴링 → set 시 진행 중 1건만 마치고 즉시 `InterruptedError` |
| `_throttle_retried` | `bool` | 429/503 자동 감속 1회 한정 플래그 |
| `_mssql_db_names` | `Optional[List[str]]` | MSSQL 전체 DB명 목록 캐시 — `_mssql_all_db_names`가 최초 1회만 추출 후 저장. `count_search`·`_search_mssql_multidb` 이중 순회 제거 |
| `_mssql_search_counts` | `Dict[Tuple, List[Tuple[str,int]]]` | MSSQL per-DB 카운트 캐시 — key=(target, match, keyword), value=`[(db, cnt)]`. `count_search`가 계산 후 저장 → `_search_mssql_multidb`가 재사용해 DB별 COUNT 이중 발사 제거 |

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
        "position":    str,   # "where" / "where_case" / "orderby" / "custom"
        "blind_template": str,  # position="custom" 시 사용자 입력 템플릿, 그 외 빈 문자열
        "started_at":  str,   # ISO 8601
        "finished_at": str,   # 종료 시점에 호출부가 채움
    },
    "dbms_info": {"version": str, "user": str, "current_db": str},
    "databases": list[str],                          # ["db1", "db2", ...]
    "tables":    {db: list[str]},                    # {"db1": ["users", ...]}
    "columns":   {"db.tbl": list[str]},              # {"db1.users": ["id","name",...]}
    "dumps":     {"db.tbl": {"columns": list[str], "rows": list[list[str]]}},
    "totals": {                                       # 리스트별 총개수 — 부분 추출 판정(이어받기 팝업)용
        "databases": int | None,
        "tables":    {db: int},
        "columns":   {"db.tbl": int},
    },
    "search": {                                        # search() 실행 후에만 존재 (특수 검색모드 전용)
        "target":  str,                                 # "database" / "table" / "column"
        "match":   str,                                 # "contains" / "exact"
        "keyword": str,
        "hits":    list[dict],                          # [{"db","table","column","display"}, ...]
    },
}
```

DB/테이블/컬럼 목록은 `total`(COUNT 결과)이 정해진 뒤에만 순번 기반 페이지네이션이 가능하므로, 각 목록은 최초 추출 시 COUNT를 1회 실행해 `totals`에 저장하고 이후에는 재사용한다 (boolean-blind COUNT는 15~20 요청 수준으로 비용이 커 재조회를 피함). 리스트 길이가 `totals`의 값에 못 미치면 부분 추출 상태이며, 이 경우 호출부(대시보드)가 이어받기 여부를 사용자에게 확인한다.

---

## 진입 함수 시그니처

| 함수 | 시그니처 | 용도 |
|------|----------|------|
| `_build_session` | `(cookies, auth_headers, proxies=None) -> requests.Session` | `verify=False` + 쿠키/인증 헤더/프록시 영구 부착 |
| `fingerprint` | `(ctx, progress_cb=None) -> ExtractCtx` | 컨텍스트·DBMS·UNION visible 자동 탐지 + 기법별 smoke test. 추출 불가 시 `UnsupportedTechniqueError` |
| `extract_dbms_info` | `(ctx, progress_cb=None) -> dict` | `{version, user, current_db}` 추출. 모든 값이 빈 문자열이면 `UnsupportedTechniqueError` raise (추출 불가 안전망) |
| `count_databases` | `(ctx) -> Optional[int]` | DB(스키마) 총 개수. `list_databases` 호출 전 `total`로 전달 (SQLite는 쿼리 없이 1 고정) |
| `count_db_tables` | `(ctx, db) -> Optional[int]` | DB 내 테이블 총 개수. `list_tables`의 `total`로 전달 |
| `count_table_columns` | `(ctx, db, table) -> Optional[int]` | 테이블 내 컬럼 총 개수. `list_columns`의 `total`로 전달 |
| `list_databases` | `(ctx, total, items_out=None, progress_cb=None) -> list[str]` | 페이지네이션으로 DB 목록 1개씩. `items_out` 전달 시 해당 리스트에 이어서 append (부분 목록 이어받기), 반환값은 `items_out`과 동일 객체 |
| `list_tables` | `(ctx, db, total, items_out=None, progress_cb=None) -> list[str]` | 특정 DB의 테이블 목록. `items_out`으로 이어받기 |
| `list_columns` | `(ctx, db, table, total, items_out=None, progress_cb=None) -> list[str]` | 특정 테이블의 컬럼 목록. `items_out`으로 이어받기 |
| `count_table` | `(ctx, db, table) -> Optional[int]` | 테이블 전체 행 수 추출 (estimate/dump 공용) |
| `count_search` | `(ctx, target, match, keyword) -> Optional[int]` | 특수 검색모드 결과 총 개수. `target`="database"/"table"/"column", `match`="contains"/"exact". MSSQL의 table/column은 `sys.databases` 전체를 순회해 합산(비용 큼) |
| `search` | `(ctx, target, match, keyword, total=None, items_out=None, progress_cb=None) -> list[str]` | DB명/테이블명/컬럼명 검색 — 위치 목록(raw 문자열, `DUMP_DELIM` 결합)을 반환. target="database"→DB명 그대로, "table"→`db{DELIM}table`, "column"→`db{DELIM}table{DELIM}column`. 기법·주입 컨텍스트·커스텀 페이로드는 세션 시작 시 확정된 `ctx` 값을 그대로 사용(재선택 없음). SQLite database 검색은 `["main"]` 고정 매칭, MSSQL table/column은 `_search_mssql_multidb`로 전체 DB 순회 |
| `dump_table` | `(ctx, db, table, columns, total=None, progress_cb=None, rows_out=None) -> list[list[str]]` | 처음~끝 전체 행 추출. `total` 전달 시 COUNT 생략. `rows_out` 전달 시 해당 리스트에 행을 append (취소 시 누적 행 보존). 취소 시 `InterruptedError` 전파. `qDLMTRq` 구분자 split |
| `save_to_excel` | `(extracted, target_url, output_dir, excel_name=None, file_prefix="extract") -> list[str]` | 마스터 파일(`{file_prefix}_<name>_DBfingerprint.xlsx` — INFO+DBList[+SearchResult]) + DB별 파일(`{file_prefix}_<name>_<db>.xlsx` — INFO+_TableMap+테이블 시트) 생성. 동일 이름이면 항상 덮어쓰기. `extracted["search"]`가 있으면 마스터 파일에 SearchResult 시트(검색대상/매칭방식/키워드/위치) 추가. `file_prefix`로 특수 검색모드 결과를 일반 추출 파일과 격리 저장 |
| `init_extracted` | `(ctx) -> dict` | 누적 dict 표준 초기화 |
| `find_existing_extract` | `(excel_name, output_dir) -> dict \| None` | 해당 이름의 마스터 파일 존재 여부 확인 + 요약 반환 (`{dbms, technique, context, position, blind_template, union_*, db_count}`) |
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
| Row dump (UNION 묶음) | — | DBMS 집계 함수로 N행을 `ROW_DELIM`(`qROWMTRq`)으로 결합 후 추출(`use_hex`에 따라 HEX 디코드 또는 raw) |

DBMS별 차이:
- **MySQL/MariaDB**: `LIMIT offset,1`
- **MSSQL**: `ORDER BY ... OFFSET n ROWS FETCH NEXT 1 ROWS ONLY`. 테이블 목록은 `dbo` 고정이 아닌 전체 스키마 대상이며 `SCHEMA_NAME(schema_id)+'.'+name` 형태의 `schema.table` 식별자를 반환한다. 이후 컬럼 조회·dump는 `_mssql_split_table(tbl)`로 (schema, table)을 분리해 `SCHEMA_NAME(t.schema_id)=schema AND t.name=table` 조건으로 조회한다 — 점이 없는 레거시 저장 데이터는 기본 스키마 `dbo`로 간주해 하위 호환을 유지한다
- **PostgreSQL**: `LIMIT 1 OFFSET n` + `string_agg`
- **Oracle**: `ROW_NUMBER() OVER` 서브쿼리 또는 `OFFSET n ROWS FETCH NEXT 1 ROWS ONLY`
- **SQLite**: `LIMIT 1 OFFSET n` (`databases` 추출은 `["main"]` 고정)

`dump_table` 컬럼 구분자는 응답 본문 중간 컬럼이 `DUMP_DELIM`(=`qDLMTRq`)을 자연 포함할 가능성이 매우 낮은 q-prefix 마커를 사용한다.

---

## 특수 검색모드

DB명 / 테이블명 / 컬럼명이 키워드를 **포함**(`contains`)하거나 **정확히 일치**(`exact`)하는 위치를 찾는 별도 검색 기능. 일반 목록 추출(`list_databases`/`list_tables`/`list_columns`)과 별개로 `count_search`/`search` 함수가 담당하며, 기법(Error/Boolean/UNION)·DBMS·커스텀 페이로드는 **세션 시작 시 fingerprint로 확정된 `ctx` 값을 그대로 사용**한다 (검색 전용 재선택 없음).

- **매칭 방식**: `contains`는 DBMS별 `LIKE '%keyword%'`, `exact`는 `=` 비교. 리터럴 이스케이프는 `_qlit`이 담당하며(따옴표만 이스케이프), 키워드 내 `%`/`_`는 LIKE 와일드카드로 그대로 동작한다(과잉 매칭 허용 — MySQL/MariaDB의 백슬래시 리터럴 재해석 문제를 피하기 위해 와일드카드 이스케이프는 적용하지 않음). WHERE 절 조립은 `_build_search_where`가 담당한다.
- **결과 구조**: `search()`는 `DUMP_DELIM`으로 결합한 raw 문자열 리스트를 반환한다 — `target="database"`→DB명, `"table"`→`db{DELIM}table`, `"column"`→`db{DELIM}table{DELIM}column`. 호출부(`app.py`)는 `items_out`으로 raw 문자열 리스트를 직접 공유받아, 진행률 콜백(`progress_cb`)이 호출될 때마다 새로 늘어난 만큼만 `_parse_search_hit`로 `DUMP_DELIM` 기준 분리해 `{"db","table","column","display"}` 구조 dict로 `search_extracted["search"]["hits"]`에 증분 append한다 (이름에 `.`이 포함돼도 파싱 오류가 나지 않도록 `.` 결합 문자열이 아닌 원본 델리미터로 분리) — 히트가 확인되는 즉시 대시보드 추출 로그에 반영된다.
- **DBMS별 검색 범위**:
  - MySQL / MariaDB / Oracle: `information_schema`/`all_*` 전역 뷰로 전체 DB 대상 검색이 자연 지원됨
  - **MSSQL**: `information_schema`가 DB 스코프이므로 table/column 검색은 `_mssql_all_db_names`(`sys.databases`)로 전체 DB를 순회하며 DB별 쿼리(`_q_search_count_mssql_db`/`_q_search_row_mssql_db`)를 실행 후 합산(`_search_mssql_multidb`) — 요청 수가 DB 개수에 비례해 증가
  - PostgreSQL: 커넥션이 현재 DB로 고정되는 구조적 제약상 **현재 연결된 DB로 범위 제한** (교차 DB 검색 불가). database 목록·검색 모두 `information_schema.schemata` 기준 스키마 단위로 동작하여 `list_tables`(스키마 단위 필터링)와 기준이 통일된다 — database 목록에서 선택한 이름이 항상 이후 테이블 조회에 그대로 사용 가능
  - SQLite: 단일 DB(`"main"`) 고정 — database 검색은 쿼리 없이 `keyword`와 `"main"` 문자열을 직접 비교
- **드릴다운 추출**: 검색 히트에서 이어서 추출할 때도 원래 추출 마법사와 동일한 단계별 순서를 따른다 — DB 히트는 `list_tables`부터, Table 히트는 `list_columns`부터, Column 히트는 해당 컬럼 하나만 `dump_table`로 단일 컬럼 dump. 자동 전체 덤프는 하지 않으며 호출부의 별도 액션 트리거로만 진행된다. Column 히트 드릴다운은 대시보드 UI에서 "행 추출 —" 헤딩을 "테이블: `<table>`" 대신 "경로: `<db>.<table>.<column>`" 전체 경로로 표시하고, 직전 드릴다운 결과 표는 (동일 테이블의 다른 컬럼이어도) 무조건 비워 어떤 이어받기를 선택했는지 항상 명확히 구분되도록 한다.
- **같은 테이블 다중 컬럼 병합**(`app.py` 호출부 처리): 이미 dump된 테이블에서 다른 컬럼을 추가로 dump하면 이미 뽑은 컬럼은 재추출하지 않고 **새 컬럼만** 추출한 뒤 행 인덱스 기준으로 기존 시트에 이어붙인다 — 같은 시트에 컬럼이 누적되며 별도 시트로 분리되지 않는다. 두 컬럼을 각각 독립적으로 페이지네이션 추출하므로 **행 정렬이 100% 보장되지는 않으며**(DBMS별 `dump_table` 페이지네이션에 안정적 `ORDER BY`가 없음), 이는 boolean-blind의 문자 단위 재추출 비용(2컬럼 기준 약 2배)을 피하기 위한 의도적 트레이드오프다. 새 컬럼 추출 진행 상태는 `extracted["_pending_merges"]`(엑셀 미노출)에 보관되어 중단 시 이어받기 가능하며, 끝까지 완료된 경우에만 기존 시트에 병합·반영된다(취소된 시도는 병합하지 않고 pending 상태 유지).
- **엑셀 격리**: 검색 결과(및 드릴다운 데이터)는 `init_extracted(ctx)`로 새로 초기화한 별도 `extracted` dict에 누적되며, `save_to_excel(..., file_prefix="search(<target>-<keyword>)")`로 일반 추출 파일과 완전히 분리된 파일에 저장된다. 자세한 파일명 규칙은 "엑셀 저장 규칙" 참고.

---

## WAF 가드 / 도메인 경계

### WAF 검출 (`_send` 인라인)
- **status code**: 403 / 406 / 419 / 429 / 503 — `success_marker` 유무와 무관하게 항상 판정
- **body 키워드**: `access denied` / `blocked` / `forbidden` — baseline에 자연 발생한 키워드는 `ctx.waf_baseline_kws`에 등록되어 오탐 마스킹. 단, `_union_extract`·`_error_extract`가 전달한 `success_marker`가 응답에 반사된 경우(= 실제 데이터 응답) body 키워드 판정을 스킵하여 추출값에 WAF 키워드가 포함돼도 오탐 중단하지 않음
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

`save_to_excel(extracted, target_url, output_dir, excel_name=None, file_prefix="extract")`은 보안·호환성을 위해 sanitize 다층 적용. 동일 `excel_name`(+`file_prefix`)으로 호출 시 항상 덮어쓰기. 특수 검색모드는 `file_prefix="search(<target>-<keyword>)"`로 호출해 일반 추출 파일(`extract_...`)과 완전히 별개의 파일에 저장된다.

저장 타이밍:
- **fingerprint 완료 직후** — 마스터 파일(INFO+빈 DBList) 즉시 생성. 이후 액션에서 덮어쓰기로 갱신.
- **액션 단위** — 각 액션(dbms_info / databases / tables / columns / dump) 정상 완료 시 `_save_excel_incremental`이 호출되어 로그(`excel_updates`) 1줄 기록.
- **30초 체크포인트** — databases / tables / columns / dump 진행 중 progress 콜백(`_make_flush_cb`)에서 30초마다 `_save_excel_file`(`log_label="중간저장"`) 호출. 대량 목록·행 추출 시 중간 저장 보장 — 중단·초기화 후에도 저장된 만큼부터 이어받기 가능. 저장 성공 시 로그(`excel_updates`)에 `[중간저장] 진행 N/M` 1줄 기록(실패는 30초마다 반복 도배 방지를 위해 로그 없이 무시).
- **중단(stop) 시** — `_finalize_cancelled`에서 `_save_excel_file`(`log_label="중단", log_errors=True`) 호출 후 ready 복귀. 로그(`excel_updates`)에 `[중단] 진행 N/M` 1줄 기록(재저장 없는 최종 저장이라 실패도 로그에 남김). reset(초기화)이면 저장 없이 폐기(단, 30초 체크포인트로 저장된 부분 결과는 파일에 이미 반영되어 있을 수 있음).

### 파일 구조

| 파일명 | 시트 | 내용 |
|--------|------|------|
| `{file_prefix}_<name>_DBfingerprint.xlsx` | INFO | 메타 + Fingerprint 결과 + UNION 정보 + Total Databases(복원용) |
| | DBList | DB 목록 (1행=헤더 "DB명", 2행~=DB이름) |
| | SearchResult | `extracted["search"]`가 있을 때만 추가 — 검색대상/매칭방식/키워드/위치(`hit.display`) |
| `{file_prefix}_<name>_<db>.xlsx` | INFO | 메타 + Total Tables(해당 DB의 테이블 총개수, 복원용) |
| | _TableMap | 시트명 ↔ 원본 테이블명 ↔ 총 컬럼수 매핑 (복원 시 정확성 + 이어받기 판정 보장) |
| | 테이블별 | 1행=컬럼 헤더, 2행~=행 데이터 |

`file_prefix` 기본값은 `"extract"`. 특수 검색모드는 `"search(<target>-<keyword>)"`를 사용해 파일명 자체로 일반 추출과 구분되며(예: `search(column-passw)_shop_DBfingerprint.xlsx`), 드릴다운 추출 결과도 검색 히트 위치부터 이어서 같은 `{file_prefix}_<name>_<db>.xlsx` 규칙으로 저장된다.

### 파일명 sanitize
- `_safe_filename`: `..` / `/` / `\` / Windows 예약어(`CON`/`PRN`/`AUX`/`NUL`/`COM*`/`LPT*`) 차단

### 시트명
- `_safe_sheet_name`: 31자 제한 + 금지문자 `[]:*?/\\` `_` 치환 + `INFO`·`_TABLEMAP` 충돌·중복 dedup
- `tables_index` 순서를 기준으로 전체 테이블을 항상 시트로 보존 — dump된 테이블은 헤더+행 데이터, dump되지 않은 테이블은 컬럼 헤더만(또는 빈 시트). `tables_index`에 없으나 `dumps` 또는 `columns`에만 존재하는 테이블은 뒤에 추가된다 — 검색모드에서 테이블 히트 → 컬럼 목록만 드릴다운한 경우(`tables`/`dumps`는 비어있고 `columns`만 채워짐)에도 DB별 파일이 생성되고 컬럼 헤더가 시트에 기록된다

### 셀
- `_safe_cell_value`: `=` / `+` / `-` / `@` / `\t` / `\r`로 시작하면 `'` prefix 부착 → **Excel formula injection 차단**
- `_restore_cell_value`: 읽기 시 `'` prefix 제거 (load_from_excel 복원 전용)
- `None`은 빈 문자열로

### INFO 시트 항목
Target / Method / Body Type / Param / DBMS / Technique / Context / Position / Blind Template / Database / Started / Finished / Version / User / Current DB / Total Databases / Total Tables / Union Columns / Union Types / Union Visible

Union 관련 행 3개, Total Databases(마스터 파일 전용) / Total Tables(DB별 파일 전용) 행이 추가됨 — `load_from_excel`이 ctx 재구성 및 `totals` 복원에 사용.

### 이전 결과 복원 (`load_from_excel`)
1. 마스터 파일 INFO → ctx 핵심값 (dbms / technique / context / position / blind_template / union 정보) 복원 → fingerprint **자동탐지만 생략** (비싼 컨텍스트 7종 × DBMS probe 건너뜀). 같은 INFO의 Total Databases → `extracted["totals"]["databases"]`
2. 마스터 파일 DBList → `extracted["databases"]`
3. DB별 파일 INFO의 Total Tables → `extracted["totals"]["tables"][db]`. `_TableMap` → 원본 테이블명 복원 + 3번째 컬럼(총 컬럼수) → `extracted["totals"]["columns"]["db.tbl"]`. 각 시트 헤더 → `columns`, 데이터 → `dumps` (저장된 만큼만)
4. 리스트(databases/tables/columns)는 복원된 `totals`와 현재 길이를 비교해 부분 추출 여부를 판정 — 호출부가 액션 재호출 시 `items_out`으로 이어서 추출한다. 행 dump는 기존과 동일하게 `rows` 길이를 offset으로 이어받는다(별도 total 저장 없음)

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
    total_dbs = sqli_extract.count_databases(ctx) or 0
    extracted["totals"]["databases"] = total_dbs
    extracted["databases"] = sqli_extract.list_databases(ctx, total_dbs)
    # ... tables / columns / dump_table 호출 후 extracted dict 누적
finally:
    extracted["meta"]["finished_at"] = "..."
    sqli_extract.save_to_excel(extracted, ctx.target_url, "./reports")
    if ctx._session:
        ctx._session.close()
```

대시보드 사이드바의 **"데이터 추출 (SQLi)"** 탭 → 입력 폼에서 [데이터 엑셀 저장] 체크 후 Fingerprint 시작 → 액션 패널(DBMS 정보 / 데이터 추출 시작) → 액션 완료마다 `./reports/`에 자동 저장되며 Fingerprint 결과 카드 하단에 갱신 내역 표시. 액션 패널의 **추출 로그**는 엑셀 저장 여부와 무관하게 항상 노출되며, DB/테이블/컬럼명 및 행 데이터가 확인되는 즉시 한 줄씩 기록된다 — 행은 `db.table  col1값 | col2값 | ...` 형태로 한 행당 한 줄(폴링으로 전달되는 `extracted.databases`/`tables`/`columns`/`dumps`를 프론트엔드가 감시 — 백엔드 변경 없음). 액션 패널의 **[특수 검색모드]** 토글 → 검색 대상(DB명/테이블명/컬럼명)·매칭 방식(포함/정확히 일치)·검색어 입력 후 [검색] → 실행 직전 엑셀 저장이 켜져 있으면 `/api/extract/search-check-existing`으로 동일 (검색대상/매칭방식/검색어) 조합의 기존 결과를 조회한다 — 이미 완료된 결과면 재요청 없이 조용히 이어받고, 부분 결과면 "전체 N건 중 M건 검색됨" 모달로 이어서/새로 검색을 확인받는다(둘 다 불일치·파일 없음이면 신규 검색). 검색 히트는 확인되는 즉시 추출 로그에 `HIT` 항목으로 함께 기록되며(`app.py`가 `search()`의 `progress_cb`에서 증분 파싱해 `search_extracted.search.hits`를 채우고, 프론트엔드가 이를 폴링으로 감시), 결과 목록의 **[이어서 추출]** 버튼으로 해당 위치부터 원래 추출 마법사 순서(테이블→컬럼→dump)를 이어서 진행할 수 있다. 드릴다운으로 추출되는 테이블/컬럼/행 데이터도 `S-TBL`/`S-COL`/`S-ROW` 항목으로 추출 로그에 함께 기록되며, 일반 추출(`DB`/`TBL`/`COL`/`ROW`)과 dedup 키 접두사(`S:`)로 분리되어 같은 이름이 양쪽에 있어도 서로 로그를 가리지 않는다. 이 결과 목록·버튼 패널은 상시 폴러가 `search_extracted.search.hits`의 (대상·매칭·검색어·히트 수) 시그니처 변화를 감지해 자동으로 다시 그리므로, 검색이 오래 걸리거나 페이지를 새로고침해도 버튼이 누락되지 않는다. 검색·드릴다운 결과는 일반 추출 결과와 완전히 격리되어 `search(<대상>-<검색어>)_<name>...xlsx`로 별도 저장된다.
