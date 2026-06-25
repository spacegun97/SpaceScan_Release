# sql_injection.py

**OWASP:** A03:2021 - Injection
**목적:** Error-based(Generic + DBMS-specific 2단계) / Boolean-based / Inline Query 세 가지 기법으로 GET 파라미터와 POST 폼 필드를 스캔하여 SQL Injection 취약점 탐지

---

## 스캔 대상

- **URL 쿼리 파라미터**: 크롤링 중 방문한 URL에서 `urllib.parse.parse_qs`로 추출
- **`<a href>` 쿼리 파라미터**: 크롤러가 `max_pages` 도달로 미방문한 링크에서도 파라미터 수집 (같은 도메인만, HTML 페이지)
- **POST 폼 필드**: `<form method="POST">` 파싱 → `<input>`, `<select>`, `<textarea>` 수집 (hidden 포함, HTML 페이지). `</form>` 닫힘 태그가 없는 폼도 다음 `<form` 시작 또는 문서 끝을 경계로 처리한다. HTML5 `form=` 속성으로 폼 외부에 선언된 필드도 해당 폼에 귀속시킨다.
- **GET 폼 필드**: `<form method="GET">` 또는 method 미지정 폼 → 쿼리 파라미터로 변환 (HTML 페이지)
- **`data-url/href/action/src` 속성**: DOM 요소의 data 속성에 포함된 URL에서 쿼리 파라미터 추출 (같은 도메인만, HTML 페이지). 속성값에 `html.unescape()`를 적용해 `&amp;` 등 엔티티를 복원한 뒤 파싱한다.
- **URI path 숫자 세그먼트**: `/view/1/detail` 등 `^\d+$`에 매칭되는 path 세그먼트를 주입 포인트로 등록 (UUID/slug는 오탐 방지를 위해 제외). 파라미터명은 내부 식별자 `__path_<idx>` 형식이며, 주입 시 해당 세그먼트만 치환된다 (`/`·공백은 `%2F`·`%20`으로 인코딩, SQL 특수문자는 원본 유지)
- **JSON body 폼**: `<form enctype="application/json">` — `body_type="json"`으로 분류되어 `requests`의 `json` kwarg 자동 직렬화 + `application/json` 헤더로 전송
- **XML body 폼**: `<form enctype="application/xml">` 또는 `text/xml` — `body_type="xml"`로 분류되어 `<root><k>v</k>...</root>` 평면 트리로 조립 후 `application/xml` 헤더로 전송. payload 내 `<`/`>`/`&`는 의도적으로 이스케이프하지 않음 (XML 파싱 에러가 Error-based 탐지에 유리)
- **JavaScript GET URL 파라미터**: `<script>` 블록, 인라인 이벤트 핸들러(`onclick` 등), `.js` 파일 본문에서 `fetch`, `XMLHttpRequest.open`, `$.get`/`$.post`/`$.ajax`, `axios.*`, `window.open`, `location.href/replace/assign` 호출의 URL 쿼리스트링 파라미터 추출. 백틱(`) 템플릿 리터럴은 동적 치환값의 모호성·외부 도메인 유출 리스크로 인해 의도적으로 제외
- **JavaScript POST 바디 파라미터**: `fetch(url, {body: JSON.stringify({...})})` / `axios.post/put/patch/delete(url, {...})` / `$.post(url, {...})` / `$.ajax({url, data:{...}})` / `navigator.sendBeacon(url, JSON.stringify({...}))` / `XMLHttpRequest .open('POST', url)` + `.send(JSON.stringify({...}))` 패턴에서 요청 바디 객체의 키를 POST 파라미터로 수집 (`body_type="json"`). 객체 본문 추출 시 중괄호 균형 탐색(`_extract_brace_content`)을 사용하므로 `{a:{b:1}, c:2}` 형태의 중첩 객체에서도 최상위 키를 정확히 추출한다. HTML `<script>` 블록·인라인 핸들러·`.js` 파일 본문 모두 대상
- `enctype="multipart/form-data"` 폼은 스킵

**hidden 필드 처리:**  
hidden 필드는 수집하되, CSRF/보안 토큰 성격 필드는 제외한다.  
제외 대상: `csrf`, `token`, `nonce`, `_token`, `authenticity_token`, `__requestverificationtoken`, `csrfmiddlewaretoken`, `__viewstate`, `__viewstategenerator`, `javax.faces.viewstate`, `hp_field`, `honeypot`

**도메인 경계 (3중 방어):**  
공격 요청이 대상 외 도메인으로 전송되지 않도록 세 단계로 검증한다.
1. **수집 단계** — `<a href>`, `<form action>`, `data-*` 속성, JS 호출 URL(`fetch` 등)에서 추출한 URL에 `netloc == base_netloc` 검증 적용 후 등록. URI path 주입 포인트는 크롤링된 페이지의 URL을 그대로 사용하므로 크롤러 단계의 netloc 검증이 적용된 상태
2. **공격 루프 진입 전 (Phase 2.5)** — 수집이 끝난 `input_points` 전체를 `netloc == base_netloc` 기준으로 재필터링
3. **요청 직전 (`_request()` 사전 검증)** — 요청 URL의 netloc이 `base_netloc`과 다르면 `ValueError`를 발생시켜 요청 자체를 중단. 호출부의 `except`가 해당 요청을 조용히 스킵한다
4. **요청 직후 (`_request()` 사후 검증)** — 리다이렉트로 외부 도메인으로 이탈한 경우 차단하여 세션 쿠키 유출 방지

**로그아웃 경로 제외:**  
세션 파기 방지를 위해 다음 두 단계에서 로그아웃 성격 경로(`logout`/`log-out`/`signout`/`sign-out`)를 자동 제외한다.
1. 크롤러 큐 추가 단계 — `modules/_crawl.py`가 처리 (`directory_listing`과 공유)
2. 입력 포인트 파싱 단계 — `<a href>`, `<form action>`, `data-*` 속성, JS 호출 URL에서 추출한 URL의 path를 동일 패턴으로 검사하여 스캔 대상에서 제외

매칭 규칙 상세는 [design.md](../design.md) 참고.

## 탐지 기법

### Error-based (Generic → DBMS-specific 2단계)

각 파라미터에 에러 유발 페이로드를 주입하고 응답에서 DB 에러 시그니처를 매칭한다.
Phase 1(Generic)에서 DBMS가 식별되면 Phase 2(DBMS-specific)에서 해당 DBMS 전용 벡터를 추가로 시도한다.

**Phase 1 — Generic 페이로드 (`ERROR_PAYLOADS`, 총 11종):**
```
'   "   ' OR '1'='1   1' ORDER BY 1--   1' ORDER BY 1#   1' ORDER BY 1/**/
1 AND 1=CONVERT(int,@@version)--
')--    ")--    )--    '))--                 (괄호·큰따옴표 컨텍스트 커버)
```
마지막 4종은 `WHERE (id=$p)`, `LIKE '%$p%'` 등 괄호·큰따옴표로 감싸진 파라미터 자리 커버용이다.

**Phase 2 — DBMS-specific 벡터 (`DBMS_ERROR_VECTORS`):**
Phase 1에서 식별된 DBMS를 기준으로 해당 DBMS 전용 에러 유발 함수를 추가 주입한다. `__MARKER__` 토큰은 런타임에 랜덤 마커로 치환되며, 응답 본문에 마커가 그대로 반사되면 데이터 유출 가능성이 확증된다(가장 강한 증거). 마커가 반사되지 않아도 에러 시그니처가 매칭되면 finding으로 기록한다.

| DBMS | 벡터 |
|------|------|
| MySQL / MariaDB | `AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e))`<br>`AND UPDATEXML(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e),1)` |
| MSSQL | `AND 1=CONVERT(int,(SELECT '__MARKER__'))`<br>`AND 1=CAST('__MARKER__' AS int)` |
| PostgreSQL | `AND 1=CAST((SELECT '__MARKER__') AS int)` |
| Oracle | `AND 1=CTXSYS.DRITHSX.SN(1,(SELECT '__MARKER__' FROM dual))` |
| SQLite | `AND 1=LIKELIHOOD((SELECT 1),1) AND '__MARKER__'='__MARKER__'` |

**WAF 사전 체크:** 입력 포인트 진입 시 첫 번째 파라미터에 `'`를 주입하여 응답을 확인한다.
- hidden이 아닌 가시 필드를 우선 사용 — CSRF 검증 실패로 인한 오판 방지
- 응답 본문에 `access denied` / `blocked` / `forbidden` 감지 시 해당 입력 포인트 전체 스킵
- 403 단독으로는 WAF로 판정하지 않음 (CSRF 검증 실패 응답과 구별)
- 차단이 아닌 경우, 이 응답을 첫 번째 페이로드 결과로 재사용 (추가 요청 없음)

**지원 DBMS:** MySQL, MariaDB, MSSQL, PostgreSQL, Oracle, SQLite, IBM DB2, Informix, General

> **참고:** IBM DB2·Informix·General은 탐지(error-based 시그니처 매칭)만 지원한다. SQLi 데이터 추출(`sqli_extract`)은 MySQL·MariaDB·MSSQL·PostgreSQL·Oracle·SQLite만 지원한다.

### Boolean-based

참/거짓 조건을 주입하여 응답 차이를 비교한다. Dynamic Content Marking으로 세션 ID·타임스탬프·nonce 등 동적 콘텐츠를 마스킹하여 자연 변동으로 인한 오탐을 감소시킨다.

**페이로드 쌍 (원본값 + 페이로드 형태로 주입, 총 5쌍):**
```
' AND '1'='1' --       /  ' AND '1'='2' --           (문자열 컨텍스트, -- 주석)
' AND '1'='1'#         /  ' AND '1'='2'#             (문자열 컨텍스트, # 주석)
  AND 1=1 --           /    AND 1=2 --               (숫자 컨텍스트)
) AND (1=1) --         /  ) AND (1=2) --             (괄호 컨텍스트)
') AND ('1'='1') --    /  ') AND ('1'='2') --        (문자열+괄호 컨텍스트)
```

**Dynamic Content Marking (sqlmap 스타일):**
1. 원본 요청 2회 전송 → `difflib.SequenceMatcher.get_opcodes()`로 두 응답의 불일치 블록 탐지
2. 각 불일치 블록의 앞뒤 `equal` 블록에서 10자(`_DYNAMIC_CONTEXT_LEN`) context 추출 → `(prefix, suffix)` 쌍 수집 (최대 20쌍, `_MAX_DYNAMIC_CONTEXTS`)
3. 이후 baseline·true·false 모든 응답에 동일 context 쌍으로 regex 치환 — `(prefix + <가변 내용> + suffix)` → `(prefix + __DYN__ + suffix)` (DOTALL, 비탐욕)
4. 마스킹된 응답 간 유사도로 판정 수행

**baseline 안정성 검증:** 마스킹 후 두 원본 응답의 유사도(`natural_ratio`). `natural_ratio < 0.7`이면 동적 페이지로 판정하고 해당 입력 포인트 스킵. (기존 0.85 → 0.7: 마스킹이 동적 변동폭을 흡수하므로 임계값 완화.)

**판정:**
- `similarity(baseline, true_resp) > natural_ratio - 0.05`
- `similarity(baseline, false_resp) < natural_ratio - 0.15`
- `similarity(true_resp, false_resp) < natural_ratio - 0.1`

Error-based에서 이미 취약으로 확인된 파라미터는 중복 finding 방지를 위해 건너뛴다.

### Inline Query (반사 기반)

서브쿼리 결과가 응답 본문에 그대로 반사되는지 확인하여 SQL 실행을 확증하는 기법.

**페이로드 (value 전체 치환, `_inject_and_request(..., where="replace")`):**
```
(SELECT '__MARKER__')
(SELECT '__MARKER__' FROM dual)
```

**판정:** `__MARKER__`를 런타임 랜덤 마커(예: `SecTesta3`)로 치환 주입 → 응답 본문에 해당 마커 문자열이 그대로 나타나면 서브쿼리가 실행되어 결과가 반사된 것으로 판정 → HIGH finding 생성.

**중복 제거:** Error/Boolean-based에서 이미 취약으로 확인된 파라미터는 건너뛴다.

### DELIMITER / 마커 시스템

`gen_marker()`는 `SecTest + 2자 hex` 형식(예: `SecTesta3`)의 9자 마커를 생성한다. sqlmap의 `[DELIMITER_START]/[DELIMITER_STOP]`과 유사한 용도이며, 응답 디버깅 시 도구 흔적임을 즉시 식별 가능하도록 `SecTest` prefix를 사용하고, 동일 세션 내 마커 충돌 회피용으로 짧은 hex suffix(1/65K)를 부여한다. 사용처:
- **DBMS-specific Error 벡터**의 `__MARKER__` 치환 → 응답 반사 확인 시 데이터 유출 확증
- **Inline Query 벡터**의 `__MARKER__` 치환 → 서브쿼리 결과 반사 탐지

## 주입 실행 경로

입력 포인트 dict의 `param_types`(파라미터 단위)와 `body_type`(입력 포인트 단위), 그리고 `_inject_and_request()`의 `where` 인자에 따라 주입 방식이 분기된다.

**`where` 모드 (test_value 결정):**
- `"append"` (기본): `test_value = original_value + payload` — Error-based, Boolean-based
- `"replace"`: `test_value = payload` — Inline Query (value 전체 치환으로 서브쿼리 반사 확인)

**주입 경로:**
- `param_types[param] == "path"` → `_build_path_url()`로 해당 URL path 세그먼트만 `test_value`로 치환하여 GET 전송. 쿼리 파라미터는 함께 보내지 않는다.
- 그 외 파라미터 → `params` 복사본의 해당 키 값을 `test_value`로 바꾼 뒤 `body_type`에 따라 전송:
  - `body_type == "form"` (기본): `data=params` — `application/x-www-form-urlencoded`
  - `body_type == "json"`: `json=params` — `requests`가 자동 직렬화, `application/json` 헤더
  - `body_type == "xml"`: `_dict_to_xml()`이 `<root><k>v</k>...</root>` 평면 트리 생성, `application/xml` 헤더
- Boolean-based의 baseline 요청(`_baseline_request()`)도 동일 경로를 공유하되, path 주입 포인트인 경우 URL을 그대로 사용하고 빈 params로 전송한다.

## finding 구조

```python
{
    "severity":     "HIGH",
    "url":          str,
    "method":       "GET" | "POST",
    "param":        str,              # 취약 파라미터명
    "type":         "error_based" | "boolean_based" | "inline_query",
    "dbms":         str | None,       # 식별된 DBMS (error_based만 값 / boolean·inline은 None)
    "payload":      str,
    "description":  str,              # "[Error-based / MySQL] 'param' 파라미터에서 ..." 형식
    "evidence":     str,              # 에러 메시지 발췌 / 유사도 수치 / 마커 반사 확인
    "response_url": str,              # 실제 에러/차이/반사가 관측된 응답의 최종 URL (리다이렉트 후, GET은 payload 포함)
}
```

`response_url`: `requests.Response.url` 값으로, 리다이렉트가 발생한 경우 최종 URL이며 GET 요청에서는 페이로드가 반영된 쿼리스트링 포함 URL이다. Boolean-based는 true 페이로드 응답의 URL을 기록한다. 대시보드 HTML 리포트는 요청 URL(`url`)을 "URL" 라인으로 항상 표시하고, `response_url`이 `url`과 다를 때에 한해 "응답 URL" 라인을 추가로 표시한다 (카드 헤더에는 method만 노출되므로 POST 케이스의 URL 누락 방지).

## 반환 구조

```python
{
    "module":       "SQL Injection",
    "target":       str,
    "findings":     list,
    "crawl_events": list[tuple[str, str]],       # [(iso_ts, url)] — BFS 방문 타임스탬프
    "debug_events": list[tuple[str, str, str]],  # [(iso_ts, scope, msg)] — 핵심 흐름 이벤트
}
```

## 심각도

| 기법 | 심각도 | 근거 |
|------|--------|------|
| Error-based (Generic) | HIGH | DB 에러 메시지가 직접 노출됨 — SQL 주입 가능성 확인 |
| Error-based (DBMS-specific) | HIGH | DBMS 식별 후 마커 반사 또는 에러 재현 — 데이터 유출 가능성 확증 |
| Boolean-based | HIGH | 응답 차이로 SQL 주입 가능성이 확인됨 (Dynamic Content Marking 적용) |
| Inline Query | HIGH | 서브쿼리 결과가 응답 본문에 반사 — SQL 실행 확정 |

## 의도적 미구현 사항

아래 항목은 설계 결정으로 구현하지 않은 것이며, 미탐 검토 시 제외한다.

| 항목 | 사유 |
|------|------|
| 문자열 URI path 세그먼트 주입 (`/users/admin` 등) | 숫자 세그먼트(`^\d+$`)만 REST 파라미터로 간주. 문자열 slug는 오탐 비용 대비 실효성 낮음 |
| Time-based blind SQLi (`SLEEP`, `WAITFOR`) | 응답 지연 기반 탐지는 네트워크 변동에 민감하여 신뢰도 낮음. 미구현 결정 |
| HTTP 헤더 주입 (`User-Agent`, `Referer`, `X-Forwarded-For` 등) | 헤더 파라미터는 수집 대상에서 제외. 헤더 기반 SQLi는 현재 스캔 범위 밖 |

## scan() 파라미터

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `target_url` | str | — | 스캔 대상 URL |
| `timeout` | int | 10 | 요청 타임아웃(초) |
| `delay` | float | 0.7 | 요청 간 딜레이(초) |
| `max_pages` | int | 100 | 크롤링 최대 방문 페이지 수 (10~30000, `directory_listing`·`path_traversal`과 공용) |
| `cookies` | dict \| None | None | 요청에 첨부할 쿠키 (인증 스캔 시 사용) |
| `proxies` | dict \| None | None | `{"http": ..., "https": ...}` 형식의 프록시 설정 |
| `progress_cb` | callable \| None | None | 하위 진행률 보고 콜백 `(current, total)`. 크롤링 0~40%, 입력 포인트 스캔 40~100% 범위로 보고 |
| `auth_headers` | dict \| None | None | 모든 HTTP 요청 헤더에 영구 부착 (Authorization 등). `requests.Session.headers`에 등록 |
| `render` | bool | False | JS 렌더링 활성화. Playwright Chromium으로 DOM 렌더링 + 네트워크 인터셉션 + JSON 응답 채굴. 최초 ON 시 `_ensure_render_deps()`가 playwright·Chromium을 lazy 설치. 실패 시 정적 크롤 폴백 |
| `stop_event` | Event \| None | None | [중단] 신호. set 시 크롤·입력 포인트 스캔의 요청 직전·딜레이 대기에서 `wait_or_cancel()`이 `ScanCancelled`를 던져 즉시 중단. `_run_scan()`이 주입 |

**리다이렉트 도메인 검증:**  
`_request` 내부에서 응답의 최종 URL(`resp.url`)을 `base_netloc`과 비교한다. 외부 도메인으로 리다이렉트된 경우 `ValueError`를 발생시켜 해당 요청 결과를 무시한다. 세션 쿠키가 외부 도메인으로 전송되는 것을 방지한다.
