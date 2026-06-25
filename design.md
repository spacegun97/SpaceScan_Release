# OWASP Web Vulnerability Scanner — 프로젝트 설계 문서

---

## 1. 프로젝트 개요

OWASP Top 10 기반의 웹 취약점 자동 스캐너.
Flask 웹 대시보드(`app.py` + `dashboard/dashboard.html`) 인터페이스를 제공하며,
스캔 모듈은 독립적으로 동작하고 공통 인터페이스를 통해 결과를 반환한다.

---

## 2. 전체 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                    인터페이스 레이어                      │
│  app.py (Flask Web API)   │  dashboard/dashboard.html   │
│  ├─ "스캔" 탭             │                             │
│  ├─ "스캔 히스토리"       │                             │
│  ├─ "데이터 추출 (SQLi)"  │                             │
│  └─ "엑셀 취합"           │                             │
└──────────────┬────────────┴──────────────────────────────┘
               │ 공유 유틸: _core.py
               │   ├── normalize_url / calculate_risk
               │   ├── generate_html_report / save_crawl_log
               │   ├── parse_cookie_string / SPEED_DELAY / EXTRACT_SPEED_DELAY
               │   ├── _ensure_extract_deps / _estimate_dump
               │   ├── _ensure_merge_deps
               │   └── _ensure_render_deps  (Playwright lazy 설치)
               │ 공용 헬퍼: _runner.py
               │   ├── build_module_extra() — 모듈별 추가 파라미터 dict 구성
               │   └── run_single_module()  — scan() 호출 + elapsed/error 처리
┌──────────────▼──────────────────────────────────────────┐
│                    모듈 레이어                            │
│   modules/                                               │
│   ├── _crawl.py             BFS 크롤러 공통 유틸          │
│   ├── _cancel.py            협조적 중단 헬퍼 (utility)    │
│   ├── directory_listing.py  디렉터리 리스팅 탐지         │
│   ├── default_pages.py      WEB/WAS/Application 기본·샘플 페이지 탐지│
│   ├── sql_injection.py      SQL 인젝션 탐지              │
│   ├── _sqli_util.py         SQLi 공통 상수·헬퍼 (utility)│
│   ├── path_traversal.py     Path Traversal 탐지          │
│   ├── sqli_extract.py       SQLi 데이터 추출 (별도 모드) │
│   └── excel_merge.py        엑셀 취합 (별도 모드)         │
└──────────────┬──────────────────────────────────────────┘
               │
┌──────────────▼──────────────────────────────────────────┐
│                    출력 레이어                            │
│   reports/report_<domain>_<timestamp>.html               │
│   reports/crawl_path_<domain>_<timestamp>.log            │
│         (크롤링 미선택 시에도 생성됨)                     │
│   reports/extract_<name>_DBfingerprint.xlsx              │
│   reports/extract_<name>_<db>.xlsx                       │
│         (SQLi 추출 모드 — 고정 이름, 동일 이름 덮어쓰기)  │
│   reports/merge_<name>_<timestamp>.xlsx                  │
│         (엑셀 취합 모드에서만 생성)                       │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 핵심 컴포넌트

### 3-1. `_core.py` — 공유 유틸리티

`app.py`가 공용으로 사용하는 함수/상수 모음.

주요 함수:
- `normalize_url()` — https:// 자동 보완, 후행 슬래시 제거
- `calculate_risk()` — 심각도별 카운트 + 총 취약점 개수 산출
- `generate_html_report()` — 인라인 CSS 포함 HTML 리포트 생성. 내부적으로 `_render_finding_rows()` / `_render_url_block()` / `_render_exposed_files()` 헬퍼로 분리되어 있다
- `save_crawl_log()` — 모든 모듈 결과의 `crawl_events` + `debug_events` 필드를 수집, 타임스탬프 기준으로 정렬 후 `crawl_path_<domain>_<timestamp>.log`에 1-b 인터리브 형식으로 저장. 두 필드가 모두 없는 결과만 있으면 파일을 생성하지 않고 `None` 반환
- `parse_cookie_string()` — `"key=val; key2=val2"` 형식 문자열을 `{키: 값}` 딕셔너리로 파싱
- `_estimate_dump()` — SQLi dump 예상 요청 수 / 소요시간 계산. estimate 단계에서 COUNT로 얻은 `total_rows`를 인자로 받음 (순수 함수). UNION: `ceil(total / union_row_batch)` 요청; Error: 행당 2요청; Boolean: 행당 21 + 평균글자 × 5요청
- `_ensure_render_deps()` — 렌더링 모드 진입 시 `playwright` 패키지와 Chromium 바이너리를 lazy 설치. 프로세스 내 1회만 설치 시도(전역 캐시). 성공 `True` / 실패 `False` 반환(정적 크롤 폴백 신호). 최초 설치 시 pip playwright(수 MB) + Chromium 바이너리(~150MB)를 내려받는다.

### 3-1-1. 속도 조절 옵션

스캔 전 요청 간 딜레이(초)를 1~6 레벨로 제어한다 (`_core.SPEED_DELAY`).

| 레벨 | 이름 | 딜레이 |
|------|------|--------|
| 1 | 최저속 | 5.0초 |
| 2 | 저속 | 4.0초 |
| 3 | 느림 | 3.0초 |
| 4 | 보통 | 2.0초 |
| 5 | 빠름 (기본값) | 1.0초 |
| 6 | 최고속 | 0.0초 |

- **대시보드**: 스캔 설정 UI의 셀렉트 박스로 선택. `POST /api/scan` 요청에 `speed` 필드 포함.
- **모듈**: `scan()` 함수에 `delay: float = 0.7` 매개변수 추가. 각 HTTP 요청 전 `time.sleep(delay)` 실행.

### 3-2. `app.py` — Flask 웹 대시보드 백엔드

REST API 엔드포인트:
- `POST /api/scan` — 스캔 시작, `job_id` 반환. 요청 필드:
  - `target`: 스캔 대상 URL
  - `modules`: 실행할 모듈 키 배열
  - `timeout`: 요청 타임아웃 (초)
  - `speed`: 속도 레벨 (1~6)
  - `max_pages`: 크롤링 최대 페이지 수 (기본값 1000, 10~30000 범위로 보정, directory_listing·sql_injection·path_traversal 모듈에 전달)
  - `cookies`: 쿠키 문자열 (`"key=val; key2=val2"` 형식, 선택값). 서버가 `{키: 값}` 딕셔너리로 파싱하여 모든 모듈의 `scan()`에 전달
  - `auth_headers`: 인증 헤더 dict (`{"Authorization": "Bearer xxx"}` 형식, 선택값). 모든 모듈의 HTTP 요청에 헤더로 첨부. 대시보드에서 `"Header: value"` 형식 텍스트를 `_parseAuthHeaders()`로 파싱하여 전달
  - `proxy_host`: 프록시 호스트 문자열 (선택, 미지정 시 미사용)
  - `proxy_port`: 프록시 포트 정수 (선택. 지정 시 `proxy_host` 기본값 `127.0.0.1`로 프록시 활성화)
  - `default_pages_stacks`: Default Pages 추가 점검 스택 배열 (선택, 기본값 `[]`). `TECH_REGISTRY`에 정의된 유효 스택명만 허용되며, 자동 탐지 결과와 합집합으로 최종 점검 대상 구성
  - `render`: JS 렌더링 활성화 boolean (선택, 기본값 `false`). `true`이면 크롤링 모듈이 Playwright Chromium으로 렌더링 + 네트워크 인터셉션을 수행한다. `default_pages`에는 전달되지 않는다.
- `GET /api/scan/<id>/status` — 진행 상태 폴링 (0~100%). 하위 진행률은 `directory_listing` / `sql_injection` / `default_pages` / `path_traversal` 모듈에서 `progress_cb`를 통해 세밀하게 갱신된다
- `GET /api/scans` — 히스토리 목록
- `POST /api/scan/<id>/cancel` — 실행 중인 스캔 취소 (pending/running 상태에서만 가능). `cancelled` 플래그(다음 모듈 진입 차단)와 `job["stop_event"]`(threading.Event) `set()`을 함께 수행한다. stop_event는 각 모듈 요청 루프가 요청 직전·딜레이 대기 중 검사하므로, 진행 중인 1건만 마치고 즉시 중단된다 (모듈 단위가 아닌 요청 단위 반응)
- `GET /api/scan/<id>/report/html` — HTML 리포트 다운로드
- `POST /api/merge` — 다중 엑셀 파일 취합 (multipart/form-data). 요청 필드: `files` (여러 파일), `out_name` (출력 이름). 응답: `{columns, total_rows, per_file, skipped_files, download_name}`
- `GET /api/merge/download?name=<파일명>` — 취합 결과 xlsx 다운로드. `merge_` 접두사·`.xlsx` 확장자 검증 후 `reports/` 에서 서빙

스캔 작업은 `scan_jobs` dict에 인메모리 저장 (재시작 시 초기화). 장시간 스캔은 백그라운드 스레드로 처리.

`_run_scan()` 내부 스캔 루프 진입 전, `default_pages` 모듈이 포함된 경우 `_detect_stacks()`를 사전 호출한다. 탐지 결과와 `default_pages_stacks`로 전달된 사용자 선택 스택을 합집합으로 구성하여 `stacks` 파라미터로 전달한다. `TECH_REGISTRY`에 없는 스택명은 합산 시 필터링된다.

`_run_scan()`은 모듈 실행 시 `_runner.build_module_extra()` / `_runner.run_single_module()`을 사용한다. 다만 취소 체크와 진행률 콜백 주입은 대시보드 전용 책임이므로 `_run_scan()` 측에서 처리한다.

**즉시 중단(협조적 중단):** `_run_scan()`은 잡마다 `threading.Event`(`job["stop_event"]`)를 생성하여 `build_module_extra(stop_event=...)`로 4개 스캔 모듈 전체에 전달한다. 각 모듈은 요청 직전·딜레이 대기 지점에서 `modules/_cancel.py`의 `wait_or_cancel(stop_event, secs)`를 호출하며, `cancel_scan()`이 `stop_event.set()`을 호출하면 즉시 `ScanCancelled`(BaseException 상속 — 요청 루프의 `except Exception`을 통과)를 던져 호출부까지 전파한다. `run_single_module()`이 이를 catch하여 `{cancelled: True}` 표식을 반환하고, `_run_scan()`은 `cancelled` 플래그를 보고 보고서 생성 없이 종료한다. 진행 중인 1건(블로킹 requests 호출)만 마치고 곧바로 멈춘다.

**하위 진행률 매핑:** `_run_scan()`은 각 모듈 인덱스에 대해 `_make_progress_cb(job, base, span)`로 콜백을 생성하여 `progress_cb`를 지원하는 모듈에 전달한다. 지원 모듈 식별은 `_runner.MODULES_WITH_PROGRESS_CB` 상수로 일원화되어 있다. 하위 모듈이 보고하는 `(current, total)` 값은 `base + current/total * span`으로 전체 진행률에 합산되며, 하위 진행률에는 99% 상한을 걸어 모듈 완료 시점에 정확한 정수 % 값으로 덮어쓴다.

**job_dict 구조**
```python
{
    "job_id":         str,         # scan_YYYYMMDD_HHMMSS_XXXX
    "target":         str,
    "modules":        list[str],
    "status":         str,         # pending / running / completed / cancelled
    "progress":       int,         # 0~100
    "current_module": str | None,
    "cancelled":      bool,         # 취소 플래그 — 다음 모듈 진입 차단 (cancel_scan에서 set)
    "stop_event":     "Event",      # threading.Event — 모듈 요청 루프 즉시 탈출 신호 (cancel_scan에서 set())
    "results":        list,
    "risk":           dict | None,
    "html_report":    str | None,  # 절대 경로 (클라이언트 미노출)
    "created_at":     str,
    "completed_at":   str | None,
}
```

### 3-3. `dashboard/dashboard.html` — 프론트엔드 SPA

- 다크 테마, CSS 변수 시스템
- 사이드바 4개 페이지: 스캔 실행 / 스캔 히스토리 / 데이터 추출 (SQLi) / 엑셀 취합
- 스캔 실행 페이지: URL / Timeout / 모듈 토글, 진행률 800ms 폴링, findings 아코디언
- 히스토리 페이지: 과거 스캔 목록 테이블
- 데이터 추출 (SQLi) 페이지: 입력 폼 + fingerprint + 추출 마법사 (별도 모드, §5 참고)
- 엑셀 취합 페이지: 다중 파일 업로드 + 스키마 합집합 병합 (별도 모드, §6 참고)

---

## 4. 스캔 모듈 공통 인터페이스

```python
def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         cookies: dict = None,
         proxies: dict = None,
         auth_headers: dict = None) -> Dict[str, Any]:
    return {
        "module":   str,          # 모듈 표시명
        "target":   str,
        "findings": list[dict],
        "error":    str | None,   # 에러 발생 시 메시지 (정상 시 키 없음)
    }
```
- `cookies`: `{키: 값}` 형식의 딕셔너리. 모든 모듈의 요청에 쿠키로 첨부된다. 인증이 필요한 대상 스캔 시 사용 (선택값).
- `proxies`: `{"http": "http://HOST:PORT", "https": "http://HOST:PORT"}` 형식의 딕셔너리. BurpSuite 등 인터셉트 프록시 연동 시 사용 (선택값). `None`이면 미사용.
- `auth_headers`: `{"Authorization": "Bearer xxx", "X-API-Key": "..."}` 형식의 딕셔너리. 모든 모듈의 HTTP 요청 헤더에 영구 첨부된다 (선택값). `sql_injection`은 `requests.Session.headers`에 등록하고, 나머지 모듈은 `requests.get/request(..., headers=...)` 인자로 전달한다.

`directory_listing`, `sql_injection`, `path_traversal` 모듈은 추가 파라미터를 받는다:
```python
def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         max_pages: int = 1000, cookies: dict = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: dict = None,
         auth_headers: dict = None) -> Dict[str, Any]:
```
- `max_pages`: BFS 크롤링 시 방문할 최대 페이지 수 (기본값 1000, 범위 10~30000). 세 모듈이 공용 값을 사용한다.
- `progress_cb`: 하위 진행률 보고 콜백. `(current, total)` 형식으로 호출되며 대시보드 진행률 계산에 사용된다.

`default_pages` 모듈은 `stacks` 파라미터와 `progress_cb`를 추가로 받는다:
```python
def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         stacks: List[str] = None, cookies: dict = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: dict = None,
         auth_headers: dict = None) -> Dict[str, Any]:
```
- `stacks`: 사전 탐지된 기술 스택 목록. 값이 전달되면 내부 `_detect_stacks()` 호출을 건너뛴다.
- `stop_event` (4개 스캔 모듈 공통, 선택): `threading.Event`. `_run_scan()`이 `build_module_extra()`로 주입하며, set되면 각 모듈의 요청 직전·딜레이 대기 지점에서 `wait_or_cancel()`이 `ScanCancelled`를 던져 즉시 중단된다. 자세한 흐름은 섹션 3-1 '즉시 중단' 참조.

**공통 크롤러(`modules/_crawl.py`) 동작:**
- BFS 시작 전 `robots.txt`와 `sitemap.xml`을 조회하여 같은 도메인 URL을 추가 시드로 큐에 선투입한다. `robots.txt`의 Disallow/Allow/Sitemap 지시자는 발견 힌트로만 활용하며 차단 규칙을 따르지 않는다. `sitemap.xml`은 `<sitemapindex>`가 감지되면 하위 sitemap URL을 재귀 조회한다(깊이 3, 자식 20개 상한).
- 응답을 `html` / `script` / `other` 세 종류로 분류한다. `text/html` 또는 `application/xhtml+xml` CT이면 `html`, `javascript`/`ecmascript` CT 또는 `.js` URL이면 `script`, CT가 없거나 `text/plain`이면 응답 본문 첫 500자를 스니핑(`<!doctype html`·`<html`·`<?xml` 접두어)하여 `html`로 승격, 그 외는 `other`. 분류는 HTTP 상태 코드와 무관하게 적용되어 403·404 등 비200 응답도 분류 결과에 따라 본문이 파싱된다. `html`·`script`는 본문을 보관하고 링크·입력 포인트 추출 대상이 된다. `other`는 경로 수집용으로만 기록한다.
- HTML 본문에서 링크를 추출하는 소스: 따옴표·미따옴표 `href`/`src`/`action` 속성, `data-url`/`data-href`/`data-action`/`data-src` 속성, `srcset` 속성(쉼표 분리 첫 토큰), `<meta http-equiv="refresh">` url= 값, `<base href>` 기준 상대 URL 해석. 스크립트 본문(`<script>` 블록·인라인 이벤트 핸들러·`.js` 파일)에서는 `fetch`/`XMLHttpRequest`/`$.ajax`/`axios`/`window.open`/`location.href` 등 JS 호출 URL을 추출하여 큐에 추가한다. HTML 속성에서 추출된 URL에는 `html.unescape()`를 적용해 `&amp;` 등 엔티티를 복원한 뒤 파싱한다.
- 동일 서명(path + 쿼리 파라미터명 집합)의 URL은 최대 3회까지만 방문하여 페이지네이션 트랩으로 인한 `max_pages` 예산 낭비를 방지한다.
- 요청 실패 시 `Timeout`·`ChunkedEncodingError`에 한해 최대 2회 재시도(0.5 s → 1.0 s 백오프)한다. `ConnectionError`·`SSLError` 등 영구적 오류는 즉시 중단한다.
- `stop_event`가 전달되면 매 페이지 진입·재시도 백오프·요청 간 딜레이 지점에서 `wait_or_cancel()`로 [중단] 여부를 검사하여, set 시 진행 중인 1건만 마치고 즉시 `ScanCancelled`로 크롤을 종료한다.
- 인증 세션 파기 방지를 위해 경로의 마지막 segment가 `logout` / `log-out` / `signout` / `sign-out`에 해당하는 링크는 큐 추가 단계에서 제외한다.
- 매칭 예시: `/logout`, `/auth/logout`, `/sqli/logout.jsp` 차단 / `/logout-help` 같은 확장 문자열은 차단 대상 아님.
- **도메인 경계 (보수적 정책):** 스캔 대상은 진입 URL과 동일한 `host:port`(netloc)로 엄격히 제한된다. 서브도메인(`api.site.com` 등)은 같은 자산으로 보이더라도 별도 netloc이므로 스코프에서 제외된다. robots.txt·sitemap·JS에서 추출한 URL도 이 경계로 필터된다. 이는 진단 범위 이탈을 방지하기 위한 의도적·보수적 설계이다.
- **JS 렌더링 모드 (render=True, 기본 OFF)**: Playwright Chromium 헤드리스로 각 페이지를 렌더링하여 SPA·REST API 엔드포인트를 포착한다. 탐색 단계에만 사용하며 공격(주입) 요청은 계속 `requests`를 사용한다. 세 가지 수집 경로: ① 렌더 후 DOM(`page.content()`)에서 링크·입력 포인트 추출 — 기존 정적 추출 로직 그대로 재사용. ② 네트워크 인터셉션 — 브라우저가 실제 발생시키는 GET(쿼리 파라미터) / POST(바디) 트래픽을 입력 포인트로 기록, `kind="xhr"` 합성 엔트리로 반환. ③ `application/json` 응답은 `kind="json"` 분류 후 본문을 재귀 탐색하여 같은 도메인 URL 쿼리 파라미터를 수집(HATEOAS 커버, 렌더 OFF 정적 크롤에도 적용). C2 강제: 비-GET·GET 로그아웃은 라우트 단계에서 abort(전송 차단). 의존성 최초 설치 시 `_core._ensure_render_deps()`가 playwright 패키지 + Chromium 바이너리를 lazy 설치. 의존성·브라우저 기동 실패 시 정적 크롤로 자동 폴백.
- 크롤러 반환 dict 필드: `url`(최종 URL) / `path`(경로) / `body`(html·script·json 종류의 응답 본문, other·xhr는 None) / `kind`("html" \| "script" \| "json" \| "other" \| "xhr") / `visited_at`(방문 타임스탬프) / `points`(kind="xhr" 전용, 네트워크 인터셉션 입력 포인트 list).

크롤링 모듈(`directory_listing`, `sql_injection`, `path_traversal`)의 반환 dict 추가 필드:
```python
"crawl_events": list[tuple[str, str]]            # [(iso_ts, url)] — BFS 방문 타임스탬프 포함
"debug_events": list[tuple[str, str, str]]       # [(iso_ts, scope, msg)] — 핵심 흐름 이벤트
```

비크롤링 모듈(`default_pages`)도 `debug_events` 필드를 반환한다. `save_crawl_log()`가 두 필드를 머지하여 1-b 인터리브 형식으로 기록한다:
```
2026-05-28 10:30:00.123 [crawl] https://example.com/login
2026-05-28 10:30:01.456 [sql_injection] 입력 포인트 수집: 12개
```

**finding dict 공통 필드**
```python
{
    "severity":    str,   # HIGH / MEDIUM / LOW / INFO
    "description": str,   # default_pages: CATEGORIES[category] 값으로 채워짐
    "evidence":    str,   # HTML 이스케이프 처리 후 렌더링
    # 모듈별 식별자
    "method":   str | None,   # sql_injection
    "path":     str | None,   # directory_listing / default_pages
    "url":      str | None,   # directory_listing / default_pages / sql_injection
    "param":    str | None,   # sql_injection 전용 — 취약 파라미터명
    "category": str | None,   # default_pages 전용 — modules/data/*.json의 category 키
    "response_url": str | None,  # sql_injection / path_traversal — 관측된 응답의 최종 URL
    # 모듈별 부가 필드 (HTML 리포트 렌더링에 사용)
    "type":          str | None,   # sql_injection — error_based / boolean_based / inline_query
    "payload":       str | None,   # sql_injection — 주입 페이로드
    "dbms":          str | None,   # sql_injection(error_based) — 식별된 DBMS
    "tech_stack":    str | None,   # default_pages — 탐지된 기술 스택명
    "status_code":   int | None,   # default_pages / directory_listing — HTTP 응답 코드
    "exposed_files": list | None,  # directory_listing — 노출 파일 목록 (최대 20)
    "total_files":   int | None,   # directory_listing — 전체 노출 파일 수
}
```

**심각도 체계**

| 수준 | 현재 사용 모듈 | 의미 |
|------|--------------|------|
| HIGH | sql_injection | SQL 인젝션을 통한 데이터 탈취·조작 가능 |
| HIGH | path_traversal | 파라미터 값에서 경로·IP·URL 패턴 탐지 — LFI·SSRF·오픈리다이렉트·파일 다운로드 등 수동 검증 단서 |
| MEDIUM | directory_listing, default_pages(관리 콘솔·실행 경로) | 단일 취약점으로 서버 내 직접 탐색/악용 가능 |
| LOW | default_pages(샘플·문서 페이지) | 버전·내부 정보 노출 |

각 모듈 상세는 [modules/directory_listing.md](modules/directory_listing.md), [modules/default_pages.md](modules/default_pages.md), [modules/sql_injection.md](modules/sql_injection.md), [modules/sqli_extract.md](modules/sqli_extract.md), [modules/path_traversal.md](modules/path_traversal.md) 참고.

---

## 5. SQLi 데이터 추출 (별도 모드)

본 섹션은 SpaceScan의 별도 추출 모드를 설명한다. 탐지 모듈(§4)과 인터페이스를 공유하지 않으며, 사용자가 명시적으로 모드를 선택해 진입한다. 구현체는 [modules/sqli_extract.py](modules/sqli_extract.py)이며 모듈 상세는 [modules/sqli_extract.md](modules/sqli_extract.md)를 참고한다.

### 5-1. 추출 기법

세 가지 기법을 사용자가 명시적으로 선택한다 (자동 fallback 없음 — 실패 시 호출부가 재선택 메뉴 제공).

| 기법 | 속도 | 적용 조건 | 1행당 요청 수 |
|------|------|-----------|---------------|
| **Error-based** | 빠름 | DBMS 에러 메시지를 응답 본문에 노출하는 환경 | 2 (length + content) |
| **Boolean-blind** | 매우 느림 | 응답 차이만 관찰 가능한 환경 (HEX × 5비트 이진 탐색) | 421 (`21 + 80×5`) |
| **UNION-based** | 빠름 | 컬럼 수·타입을 사전 입력 가능한 환경 | 2 |

지원 DBMS: **MySQL / MariaDB / MSSQL / PostgreSQL / Oracle / SQLite** (SQLite + Error는 미지원, 호출부가 재선택 모달 트리거).

### 5-2. 페이로드 빌더

- **랜덤 마커 시스템** — `qDLMTRq`(컬럼 구분자) / `qROWMTRq`(UNION 묶음 행 구분자) / `SecTestS...SecTestE`(UNION 격리) / `SecTest`+2자 hex 9자 마커(Error/Inline 격리)로 응답에서 추출 데이터를 정확히 분리
- **CHAR/CHR echo-immune 마커** — UNION 페이로드의 모든 마커 리터럴(`SecTestS`/`SecTestE`/`SecTestC{i}` visible probe)은 DBMS의 `CHAR(n,...)`(MySQL/MariaDB/MSSQL/SQLite) 또는 `CHR(n)||CHR(n)||...`(PostgreSQL/Oracle) 함수로 인코딩하여 페이로드에 평문 마커가 들어가지 않게 함. 응답 echo 환경(예: `<input value="...">`로 입력이 그대로 반사되는 페이지)에서도 echo 영역엔 SQL 함수 표현만 노출되고 실제 SQL 실행 결과로만 디코드된 마커가 나타나, 렌더링 영역과 echo 영역이 자연스럽게 분리됨
- **컨텍스트 자동 탐지** — `quote_context=None`일 때 진입 시 `'`/`"`/`')`/`'))`/numeric 등을 자동 식별. 수동 지정값(`""`=numeric 포함)은 자동 탐지 스킵
- **HEX 인코딩** — Boolean-blind는 `LENGTH(HEX(expr))` 기반 5비트 이진 탐색으로 multibyte 안전. UNION은 `union_hex=True`(기본) 시 동일 방식. 모든 DBMS에서 HEX 함수 인수를 문자열로 강제 캐스팅(`MySQL`/`MariaDB` → `CAST(... AS CHAR)`, `PostgreSQL` → `::TEXT::bytea`, `Oracle` → `TO_CHAR(...)`, `MSSQL` → `CONVERT(NVARCHAR(MAX),...) AS varbinary(MAX)`)해 정수 입력 시 odd-length hex 오류를 방지. 디코드는 MSSQL만 UTF-16 LE(`utf-16-le`), 나머지는 UTF-8. MSSQL `fn_varbintohexstr` 결과의 `0x` prefix는 자동 strip
- **DBMS별 식별자 quoting** — MySQL/MariaDB는 백틱, MSSQL은 대괄호, PostgreSQL/Oracle/SQLite는 큰따옴표
- **PostgreSQL UNION 캐스트** — `NULL::TEXT` / `(CHR(n)||...)::TEXT`로 명시 캐스트하여 타입 매칭 에러 회피

### 5-3. 메타 쿼리 — 페이지네이션 방식

DB/테이블/컬럼 목록은 한 번에 가져오지 않고 행 단위 페이지네이션으로 1개씩 추출한다 (대용량 결과의 길이 제한 회피).

| 추출 대상 | 페이지네이션 방법 |
|-----------|-------------------|
| Database 목록 | DBMS별 information_schema/sys/all_users 등에서 `LIMIT n,1` / `OFFSET n FETCH 1` |
| Table 목록 | `WHERE TABLE_SCHEMA=db ORDER BY TABLE_NAME LIMIT n,1` |
| Column 목록 | `WHERE TABLE_SCHEMA=db AND TABLE_NAME=tbl ORDER BY ORDINAL_POSITION LIMIT n,1` |
| Row dump (1행씩) | `SELECT col1\|\|DELIM\|\|col2... FROM tbl LIMIT n,1` (NULL-safe + `qDLMTRq` 구분자) |
| Row dump (UNION 묶음) | DBMS 집계 함수로 N행을 `qROWMTRq`로 결합 후 HEX 추출. 집계 한계 초과·잘림 시 윈도우 단위 1행씩 폴백 |
| 목록 추출 (UNION 묶음) | `_q_base_*` base SELECT → `_q_batch_list` 집계 → `qROWMTRq` split. 실패·잘림 시 window=1 집계 폴백 |

진입 함수 시그니처는 [modules/sqli_extract.md](modules/sqli_extract.md) 참고.

### 5-4. 결과 저장

`save_to_excel(extracted, target_url, output_dir, excel_name=None)` — 추출 결과를 엑셀 파일로 저장. 동일 이름으로 호출 시 항상 덮어쓰기.

- **마스터 파일** `extract_<name>_DBfingerprint.xlsx`: INFO(메타+Fingerprint 결과+UNION 정보) + DBList(DB 목록) — fingerprint 완료 직후 즉시 생성
- **DB별 파일** `extract_<name>_<db>.xlsx`: INFO + `_TableMap`(시트명↔원본 테이블명 매핑) + 테이블별 시트
- **시트명 sanitize**: 31자 제한 + 금지문자 `[]:*?/\\` 치환 + `INFO`·`_TABLEMAP` 충돌·dedup 처리
- **셀 sanitize**: `=`/`+`/`-`/`@`/탭/CR로 시작하는 값에 `'` prefix 부착 (Excel formula injection 차단). 읽기 시 `_restore_cell_value`로 제거
- **이전 결과 복원**: `load_from_excel(name, dir)` — 마스터 INFO에서 ctx 핵심값(DBMS/기법/컨텍스트/UNION) 복원 → fingerprint 자동탐지 생략. DBList + DB별 파일에서 databases/tables/columns/dumps 복원

### 5-5. API 사용법

**REST API** (`app.py`, 6개 엔드포인트):

요청 간 딜레이는 `speed` 필드로 1~6 레벨 제어 (5.0s ~ 0.0s, 1초 간격). fingerprint 단계는 사용자 delay와 무관하게 최소 0.3s/요청 강제 (`FINGERPRINT_DELAY_FLOOR`).

| 메서드 | 경로 | 용도 |
|--------|------|------|
| GET | `/api/extract/check-existing` | `?name=<excel_name>`으로 기존 파일 존재 확인. `{exists, summary?}` 반환 |
| POST | `/api/extract/start` | job 생성 + fingerprint 백그라운드 시작 |
| GET | `/api/extract/<id>/status` | 진행 상태 폴링 (ctx/절대경로 미노출) |
| POST | `/api/extract/<id>/action` | 액션 트리거 (`dbms_info`/`databases`/`tables`/`columns`/`dump`) — 동시 호출 시 409 Conflict. `dump` + `confirm:false` 응답: `{ok, estimate:{rows,requests,seconds}, resume_from}` — `resume_from` &gt; 0이면 같은 컬럼의 부분 데이터가 있어 이어받기 가능, `estimate.rows`는 **남은** 행 수 |
| POST | `/api/extract/<id>/retechnique` | 기법 또는 DBMS 변경 후 fingerprint 재실행. Body `{technique?, dbms?}` — 둘 중 하나 필수. DBMS 자동 식별 실패 시 `dbms`만 지정 가능 (SQLite+Error 조합은 400) |
| POST | `/api/extract/<id>/cancel` | `ctx.cancelled=True` 동기화로 안전 중단. `_send`의 요청 간 딜레이는 `_throttle()`이 `ctx.cancelled`를 50ms 간격 폴링하므로, 긴 delay 도중에도 진행 중인 1건만 마치고 즉시 `InterruptedError`로 빠져나온다. Body `{reset: bool}` — `false`(기본): 현재 액션만 취소 후 ready 복귀 (누적 데이터 유지), `true`: 완전 종료 후 GC 대상 편입. 진행 중 액션 없으면 상태 무관하게 즉시 cancelled 마킹 |

`extract_jobs` dict는 인메모리 저장이며 완료/취소 후 1시간 경과 job은 다음 start 호출 시 TTL GC 정리. 외부 도메인 차단은 ExtractCtx 생성 시 `allowed_netloc` 1회 저장 후 `_send` 사전·사후 검증으로 강제된다.

`/api/extract/start` 추가 필드: `proxy_host` / `proxy_port` (선택) — 프록시 설정. `base64_encode` (bool, 기본 false) — SQL 페이로드만 Base64 인코딩. `save_excel` (bool, 기본 false) — `true` 시 `excel_name` 필수. `excel_name` (문자열) — 저장 이름 (예: `test` → `extract_test_DBfingerprint.xlsx`, `extract_test_<db>.xlsx`). `reuse` (bool, 기본 false) — `true` 시 기존 파일에서 extracted 복원 + fingerprint 자동탐지 생략. `dbms` (문자열, 선택) — 지정 시 DBMS 자동 탐지 스킵. `union_visible` (정수, 1-based, 선택) — 지정 시 UNION visible 자동 탐지 스킵. `union_row_batch` (정수, 기본 1) — UNION dump 시 한 요청으로 추출할 행 수. 1이면 기존 1행씩 동작, N이면 DBMS 집계 함수로 묶음 추출 후 한계 초과·잘림 시 윈도우 단위 폴백.

`/api/extract/<id>/status` 응답의 `fingerprint` 객체: `failure_reason` 필드 추가 — `"dbms_detection"` (DBMS 자동 식별 실패, 수동 선택 모달 트리거) / `"technique"` (기법 미지원, 기법 재선택 모달 트리거). `unsupported_techniques`는 `failure_reason === "technique"`일 때만 `[ctx.technique]`으로 채워짐.

---

## 6. 엑셀 취합 (별도 모드)

본 섹션은 SpaceScan의 엑셀 취합 모드를 설명한다. 탐지 모듈(§4)·SQLi 추출(§5)과 인터페이스를 공유하지 않으며, 사용자가 대시보드 "엑셀 취합" 탭에서 직접 진입한다. 구현체는 [modules/excel_merge.py](modules/excel_merge.py)이며 모듈 상세는 [modules/excel_merge.md](modules/excel_merge.md)를 참고한다.

### 6-1. 알고리즘 — 스키마 합집합 UNION ALL

여러 엑셀 파일을 하나로 취합한다. 파일마다 컬럼 구성이 달라도 처리 가능하다.

- 각 파일의 **1행 = 컬럼 헤더**로 인식
- 컬럼 매칭 기준: **정확히 일치** (대소문자·공백 포함)
- 처음 보는 컬럼명 → `master_cols`에 추가 (이전 행들은 해당 칸 빈칸)
- 동일 컬럼명 → 동일 마스터 위치에 값 채움
- 결과 **맨 왼쪽** 고정 컬럼 `출처파일` — 각 행이 온 파일명 기록
- 시트: 각 파일의 **모든 시트** 순회
- 완전히 빈 행·빈 헤더 시트는 자동 스킵
- 행 중복 제거 없이 순수 누적 (UNION ALL)

**엣지 케이스 처리:**
- 빈 헤더 셀 → `(빈컬럼_N)` 전역 고유명 부여
- 시트 내 중복 헤더 → `.1` `.2` ... 접미사 분리
- 데이터 컬럼명이 예약 컬럼 `출처파일`과 충돌 → `출처파일.1`로 변환

### 6-2. 지원 입력 형식

| 형식 | 확장자 | 리더 | 비고 |
|------|--------|------|------|
| Excel 2007+ | `.xlsx` / `.xlsm` | openpyxl (`read_only=True, data_only=True`) | 수식 셀은 계산된 값으로 읽음 |
| Excel 97-2003 | `.xls` | xlrd | 날짜 셀은 `xldate_as_datetime`으로 변환 |
| CSV | `.csv` | stdlib `csv` | BOM→utf-8-sig→utf-8→cp949 인코딩 폴백, 시트 1개 |

### 6-3. 결과 저장

`save_merged(result, output_dir, out_name)` — 단일 `Merged` 시트 xlsx로 저장.

- 출력: `reports/merge_<name>_<YYYYMMDD_HHMMSS>.xlsx`
- 헤더 1행 + 데이터 행. 빠진 컬럼은 빈칸
- 셀 sanitize: `=`/`+`/`-`/`@`/탭/CR로 시작하는 문자열에 `'` prefix (Excel formula injection 차단)

### 6-4. API

| 메서드 | 경로 | 용도 |
|--------|------|------|
| POST | `/api/merge` | multipart/form-data: `files[]` + `out_name`. 동기 처리 후 즉시 JSON 반환 |
| GET | `/api/merge/download?name=<파일명>` | 결과 xlsx 다운로드. `merge_` 접두사·`.xlsx` 확장자 검증 |

`/api/merge` 응답: `{columns, total_rows, per_file:[{name, sheets_read, rows_added, new_columns, skipped, error}], skipped_files, download_name}`

엑셀 취합은 네트워크 없는 로컬 배치 연산으로 보통 수초 내 완료되므로 **동기 처리** (잡 폴링 불필요).
