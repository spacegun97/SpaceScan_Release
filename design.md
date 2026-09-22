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
│  ├─ "엑셀 취합"           │                             │
│  ├─ "정보수집 (OSINT)"    │                             │
│  └─ "JS 데이터플로우 분석"│                             │
└──────────────┬────────────┴──────────────────────────────┘
               │ 공유 유틸: _core.py
               │   ├── normalize_url / calculate_risk
               │   ├── generate_html_report / save_crawl_log
               │   ├── parse_cookie_string / SPEED_DELAY / EXTRACT_SPEED_DELAY
               │   ├── _ensure_extract_deps / _estimate_dump
               │   ├── _ensure_merge_deps
               │   ├── _ensure_recon_deps  (dnspython + openpyxl lazy 설치)
               │   ├── _ensure_render_deps  (Playwright lazy 설치)
               │   └── _ensure_jsanalysis_deps  (esprima + tree-sitter/tree-sitter-javascript lazy 설치)
               │ 공용 헬퍼: _runner.py
               │   ├── build_module_extra() — 모듈별 추가 파라미터 dict 구성
               │   └── run_single_module()  — scan() 호출 + elapsed/error 처리
┌──────────────▼──────────────────────────────────────────┐
│                    모듈 레이어                            │
│   modules/                                               │
│   ├── _crawl.py             BFS 크롤러 공통 유틸          │
│   ├── _cancel.py            협조적 중단 헬퍼 (utility)    │
│   ├── _endpoint_extract.py  js_analysis AST 엔드포인트를 크롤러/SQLi에 연결하는 게이트 (utility)│
│   ├── directory_listing.py  디렉터리 리스팅 탐지         │
│   ├── default_pages.py      WEB/WAS/Application/Framework 기본·샘플 페이지 탐지│
│   ├── sql_injection.py      SQL 인젝션 탐지              │
│   ├── _sqli_util.py         SQLi 공통 상수·헬퍼 (utility)│
│   ├── path_traversal.py     Path Traversal 탐지          │
│   ├── sqli_extract.py       SQLi 데이터 추출 (별도 모드) │
│   ├── excel_merge.py        엑셀 취합 (별도 모드)         │
│   ├── recon.py              정보수집 OSINT (별도 모드, 순수 패시브)│
│   ├── js_analysis.py        JS/HTML/XFDL/XADL/XJS/XML 데이터플로우 분석 (별도 모드, 완전 오프라인)│
│   └── _js_ts_adapter.py     tree-sitter CST → esprima 호환 ESTree 어댑터 (utility)│
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
│   reports/search(<대상>-<검색어>)_<name>_DBfingerprint.xlsx│
│   reports/search(<대상>-<검색어>)_<name>_<db>.xlsx       │
│         (특수 검색모드 — 일반 추출과 완전히 격리된 파일)  │
│   reports/merge_<name>_<timestamp>.xlsx                  │
│         (엑셀 취합 모드에서만 생성)                       │
│   reports/recon_<domain>_<timestamp>.html                │
│   reports/recon_<domain>_<timestamp>.xlsx                │
│         (정보수집 OSINT 모드에서만 생성)                  │
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
- `_ensure_jsanalysis_deps()` — JS 데이터플로우 분석 모드 진입 시 파싱 백엔드 의존성을 lazy 설치: `esprima`(1차, 순수 파이썬, import명·pip 패키지명 동일) + `tree-sitter`/`tree-sitter-javascript`(2차, 네이티브 바이너리, import명은 밑줄·pip 패키지명은 하이픈). 반환값 없음(설치 실패 시 예외 그대로 전파).

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
- **모듈**: `scan()` 함수에 `delay: float = 0.7` 매개변수 추가. 각 HTTP 요청 전 `wait_or_cancel(stop_event, delay)`(내부적으로 `time.sleep(delay)` 상당) 실행. BFS 크롤이 발생시키는 모든 타깃 서버 요청 — 페이지 방문, robots.txt/sitemap.xml 시드 수집(재귀 포함), JS 렌더링 모드의 같은 도메인 서브리소스 — 이 예외 없이 이 딜레이를 적용받는다(섹션 3-2 공통 크롤러 동작 참조). 요청 전송 자체도 `run_cancellable()`로 감싸 응답 대기 중 [중단]에 즉시 반응한다(상세: 섹션 3-1 '즉시 중단').

### 3-2. `app.py` — Flask 웹 대시보드 백엔드

REST API 엔드포인트:
- `GET /api/deps/status?feature=<key>` — 기능별 lazy 설치 의존성 조회(설치 시도 없이 확인만). `key`: `extract`/`merge`/`recon`/`jsanalysis`/`render`. 응답 `{ready, missing}` — `missing`은 미설치 pip 패키지명 배열
- `POST /api/deps/install` — 위 의존성을 실제로 설치(`_core.py`의 해당 `_ensure_*` 함수 실행 + `importlib.invalidate_caches()`로 동일 프로세스 내 즉시 import 가능하게 캐시 무효화). Body `{feature}`. 응답 `{ok, ready, fallback, error}` — `render`는 설치 실패해도 정적 크롤 폴백이 있어 `fallback:true`로 구분(치명적 아님)
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
  - `backend_filter`: 백엔드 확장자 필터 boolean (선택, 기본값 `true`). `default_pages` 모듈 전용. 감지된 스택 ∪ `default_pages_backends`로 선택한 언어와 다른 백엔드 실행 확장자(`.jsp`/`.php`/`.aspx` 등) 경로를 점검에서 제외한다. 언어 패밀리가 하나도 확정되지 않으면(예: Apache만 감지 + 사용자 선택 없음) 자동으로 전량 프로빙
  - `default_pages_backends`: Default Pages 백엔드 확장자 필터용 사용자 선택 언어 패밀리 배열 (선택, 기본값 `[]`). `BACKEND_FAMILIES`(`java`/`dotnet`/`php`)에 정의된 값만 허용되며, 감지된 스택의 언어 패밀리와 합집합으로 필터 허용셋을 구성한다. Apache/Nginx/에디터류 등 언어를 확정하지 못하는 스택만 감지된 경우에도 사용자가 직접 지정해 필터를 강제 활성화할 수 있다
  - `flag_auth_blocked`: 401/403 응답을 `default_pages` 취약점으로 표시할지 여부 boolean (선택, API 기본값 `true` — 대시보드 체크박스는 기본 OFF로 `false`를 명시 전송). `false`면 401/403 응답은 노출 판정에서 제외되어 finding이 생성되지 않는다. `true`면 노출로 판정하되 severity는 항상 `INFO`로 강등한다(상세: `modules/default_pages.md` 심각도 기준)
  - `render`: JS 렌더링 활성화 boolean (선택, 기본값 `false`). `true`이면 크롤링 모듈이 Playwright Chromium으로 렌더링 + 네트워크 인터셉션을 수행한다. `default_pages`에는 전달되지 않는다.
- `GET /api/scan/<id>/status` — 진행 상태 폴링 (0~100%). 하위 진행률은 `directory_listing` / `sql_injection` / `default_pages` / `path_traversal` 모듈에서 `progress_cb`를 통해 세밀하게 갱신된다
- `GET /api/scans` — 히스토리 목록
- `POST /api/scan/<id>/cancel` — 스캔 중단 또는 초기화. body `{reset: bool}` (기본 false). `reset=false`(중단): `paused` 플래그 + `stop_event.set()` → `_run_scan`이 완료 모듈 결과를 보존한 채 `paused` 상태로 전환. `reset=true`(초기화): `cancelled` 플래그 + `stop_event.set()` → 결과 폐기 후 `cancelled`로 전환. `paused` 상태에서 `reset=true`이면 스레드 없이 직접 `cancelled`로 전환. 진행 중인 요청(응답 대기 중인 경우 포함)도 최대 0.1초 내 즉시 중단된다(요청 단위가 아닌 즉시 반응 — 상세: 섹션 3-1).
- `POST /api/scan/<id>/resume` — 일시정지(`paused`) 상태의 스캔을 완료 모듈 다음부터 재개. `job["completed_count"]`를 `start_idx`로 `_run_scan`을 새 스레드로 재시작한다. 응답: `{ok, resumed_from}`.
- `GET /api/scan/<id>/report/html` — HTML 리포트 다운로드
- `POST /api/merge` — 다중 엑셀 파일 취합 (multipart/form-data). 요청 필드: `files` (여러 파일), `out_name` (출력 이름). 응답: `{columns, total_rows, per_file, skipped_files, download_name}`
- `GET /api/merge/download?name=<파일명>` — 취합 결과 xlsx 다운로드. `merge_` 접두사·`.xlsx` 확장자 검증 후 `reports/` 에서 서빙

**lazy 설치 게이트 UX:** 대시보드는 lazy 설치가 필요한 6개 실행 지점(스캔의 JS 렌더링 토글, 스캔 실행 시 AST 엔드포인트 탐지 보강, 데이터 추출의 엑셀 저장 옵션, 엑셀 취합, 정보수집, JS 데이터플로우 분석) 실행 버튼 클릭 시 `_ensureDeps()` 공통 헬퍼로 먼저 `/api/deps/status`를 조회한다. 이미 설치돼 있으면 조용히 원래 로직을 진행하고, 미설치면 "필요 모듈 설치 중입니다" 안내를 표시한 뒤 `/api/deps/install`을 호출 — 완료되면 "설치 완료, 실행을 계속합니다" 안내와 함께 재클릭 없이 원래 요청을 자동으로 이어서 전송한다. 상태·설치 요청 자체가 실패하면 게이트를 건너뛰고 기존 로직에 위임한다.

스캔 작업은 `scan_jobs` dict에 인메모리 저장 (재시작 시 초기화). 장시간 스캔은 백그라운드 스레드로 처리.

`_run_scan()` 내부 스캔 루프 진입 전, `default_pages` 모듈이 포함된 경우 `_detect_stacks()`를 사전 호출한다. 탐지 결과와 `default_pages_stacks`로 전달된 사용자 선택 스택을 합집합으로 구성하여 `stacks` 파라미터로 전달한다. `TECH_REGISTRY`에 없는 스택명은 합산 시 필터링된다. `default_pages_backends`로 전달된 사용자 선택 언어도 `BACKEND_FAMILIES`에 없는 값은 필터링되어 `backends` 파라미터로 전달된다. `flag_auth_blocked`는 별도 가공 없이 요청값 그대로 `build_module_extra()`를 통해 `default_pages.scan()`에 전달된다.

`_run_scan()`은 모듈 실행 시 `_runner.build_module_extra()` / `_runner.run_single_module()`을 사용한다. 다만 취소 체크와 진행률 콜백 주입은 대시보드 전용 책임이므로 `_run_scan()` 측에서 처리한다.

**크롤 결과 공유 캐시(`crawl_cache`):** `directory_listing` / `sql_injection` / `path_traversal` 세 모듈은 이번 `_run_scan()` 호출 범위에서 동일한 target·delay·max_pages·render·cookies로 BFS 크롤을 수행하므로, `_run_scan()`이 잡 단위로 빈 `crawl_cache: dict = {}`를 만들어 `build_module_extra(crawl_cache=...)`로 세 모듈에 전달한다. 세 모듈 중 먼저 실행되는 모듈이 크롤을 수행해 `crawl_cache["pages"]`에 결과를 채우면, 이후 실행되는 모듈은 `_crawl.crawl()`을 다시 호출하지 않고 캐시된 pages를 재사용한다(타깃 서버로의 중복 크롤 요청 제거). 캐시 재사용 시 해당 모듈의 `crawl_events`는 빈 리스트를 반환해 `save_crawl_log()`의 크롤 로그 중복 기록을 막고, `debug_events`에 "BFS 크롤링 재사용" 이벤트를 남긴다. `crawl_cache`는 이 함수 호출 로컬 변수이므로(일시정지/재개도 매번 새 호출) 잡에 영속되지 않으며 다른 스캔과 공유되지 않는다.

**즉시 중단(협조적 중단) / 재개:** `_run_scan()`은 잡마다 `threading.Event`(`job["stop_event"]`)를 생성하여 `build_module_extra(stop_event=...)`로 4개 스캔 모듈 전체에 전달한다. 각 모듈은 요청 직전·딜레이 대기 지점에서 `modules/_cancel.py`의 `wait_or_cancel(stop_event, secs)`를 호출하며, `cancel_scan()`이 `stop_event.set()`을 호출하면 즉시 `ScanCancelled`(BaseException 상속 — 요청 루프의 `except Exception`을 통과)를 던져 호출부까지 전파한다. `run_single_module()`이 이를 catch하여 `{cancelled: True}` 표식을 반환한다. 중단(`reset=false`)이면 `paused` 플래그가 set되어 `_run_scan()`이 완료 모듈 결과를 보존한 채 `paused` 상태로 전환(`completed_count` 저장)하고, 초기화(`reset=true`)이면 `cancelled` 플래그로 결과 폐기 후 종료한다. `resume_scan()`은 `completed_count`를 `start_idx`로 `_run_scan()`을 새 스레드로 재시작하여 완료 모듈을 skip하고 미완료 모듈부터 이어간다.

**in-flight 요청 즉시 취소(`run_cancellable`):** `wait_or_cancel()`은 요청 사이(딜레이 대기 중)의 중단만 즉시 처리하므로, 이미 전송되어 응답을 기다리는 요청 1건은 그 자체로는 중단할 수 없다(소켓 recv를 도중에 깨울 수 없음 — 최악의 경우 `timeout`초까지 반응 지연). `modules/_cancel.py`의 `run_cancellable(fn, stop_event, poll_interval=0.1)`이 이 공백을 메운다: 실제 요청(`requests.get/post`)을 데몬 워커 스레드 1개에서 동기 실행하고, 호출 스레드는 `poll_interval`(기본 0.1초)마다 `stop_event`를 검사하며 대기한다. set되면 워커는 그대로 버려두고(요청은 응답 도착 또는 자체 `timeout`으로 스스로 자연 종료 — 추가 요청·재전송 없이 서버 부하 그대로) 호출 스레드는 즉시 `ScanCancelled`를 던진다. `stop_event=None`이면 오버헤드 없이 `fn()`을 동기 호출해 중단 미지원 호출과 100% 동일하게 동작하고, `fn()` 내부 예외는 원본 타입 그대로 재발생시켜 기존 `except Timeout`(재시도)·`except ConnectionError`(조기 종료) 등의 분기를 그대로 보존한다. 4개 스캔 모듈과 공용 크롤러(`_crawl.py`)의 모든 `requests`/`session` 호출이 이를 통해 전송된다. 예외적으로 `default_pages._detect_stacks()`(모듈 루프 진입 전, 스캔 시작 직후 1회 호출)는 `ScanCancelled`를 내부에서 흡수해 빈 리스트를 반환한다 — `_run_scan()`을 감싸는 예외 처리가 없어 그대로 전파되면 스레드가 죽어 잡이 `running`에 멈추므로, 실제 중단 판정은 뒤이은 모듈 루프의 `job["cancelled"]`/`job["paused"]` 플래그 검사(cancel_scan이 stop_event.set()보다 먼저 세팅)에 맡긴다. JS 렌더링 모드의 `page.goto()`는 Playwright 객체가 생성 스레드에 고정되어 워커로 옮길 수 없어 이 대상에서 제외되며, 대신 라우트 훅이 서브리소스마다 [중단]을 검사해 대부분 즉시 반응한다(섹션 3-2 참조).

**하위 진행률 매핑:** `_run_scan()`은 각 모듈 인덱스에 대해 `_make_progress_cb(job, base, span)`로 콜백을 생성하여 `progress_cb`를 지원하는 모듈에 전달한다. 지원 모듈 식별은 `_runner.MODULES_WITH_PROGRESS_CB` 상수로 일원화되어 있다. 하위 모듈이 보고하는 `(current, total)` 값은 `base + current/total * span`으로 전체 진행률에 합산되며, 하위 진행률에는 99% 상한을 걸어 모듈 완료 시점에 정확한 정수 % 값으로 덮어쓴다.

**job_dict 구조**
```python
{
    "job_id":         str,         # scan_YYYYMMDD_HHMMSS_<6자리 hex>(secrets.token_hex(3), 불투명 랜덤 식별자)
    "target":         str,
    "modules":        list[str],
    "status":          str,          # pending / running / paused / completed / cancelled
    "progress":        int,          # 0~100
    "current_module":  str | None,
    "cancelled":       bool,         # 초기화(reset) 플래그 — _run_scan 폐기 경로 진입
    "paused":          bool,         # 중단 플래그 — _run_scan 일시정지 경로 진입
    "completed_count": int,          # 완료된 모듈 수 — resume 시 start_idx로 사용
    "stop_event":      "Event",      # threading.Event — 요청 루프 즉시 탈출 신호 (클라이언트 미노출)
    "results":         list,         # 완료된 모듈 결과만 포함 (취소된 모듈은 제외)
    "risk":            dict | None,
    "html_report":     str | None,  # 절대 경로 (클라이언트 미노출)
    "scan_params":     dict,         # 재개용 파라미터 보존 (클라이언트 미노출)
    "created_at":      str,
    "completed_at":    str | None,
}
```

### 3-3. `dashboard/dashboard.html` — 프론트엔드 SPA

- 다크 테마, CSS 변수 시스템
- 사이드바 6개 페이지 (3개 그룹): SCAN(정보수집 OSINT / 스캔 실행 / 스캔 히스토리) · EXPLOIT(데이터 추출 SQLi) · UTILITY(엑셀 취합 / JS 데이터플로우 분석)
- 스캔 실행 페이지: URL / Timeout / 모듈 토글, 진행률 800ms 폴링, findings 아코디언
- 히스토리 페이지: 과거 스캔 목록 테이블
- 데이터 추출 (SQLi) 페이지: 입력 폼 + fingerprint + 추출 마법사 (별도 모드, §5 참고)
- 엑셀 취합 페이지: 다중 파일 업로드 + 스키마 합집합 병합 (별도 모드, §6 참고)
- 정보수집 (OSINT) 페이지: 도메인 입력 + 소스 토글 + URL 수집 옵션(정적 리소스 확장자 제외 토글) + 진행률 800ms 폴링 + 결과 테이블/리포트 다운로드 (별도 모드, §7 참고)
- JS 데이터플로우 분석 페이지: 다중 파일 업로드(.js/.axd/.html/.xfdl/.xadl/.xjs/.xml) + 결과 탭 3종(엔드포인트 / 함수 / 파일 별 분기 흐름) — 엔드포인트 탭(확정+추정 목록), 함수 탭(검색 + 상세 표/mermaid 그래프 뷰 토글), 파일 별 분기 흐름 탭(파일 선택 → 그 파일 함수의 CFG를 함수별로 이어붙인 mermaid 그래프, 함수 80개씩 페이지네이션 + 함수명 검색으로 해당 페이지·위치 이동, 원본 크기 표시 + 배율 조절/드래그 팬/Ctrl+휠 줌) (별도 모드, §8 참고)

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
- `crawl_cache` (선택, 기본 `None`): `{"pages": [...]}` 형식의 dict. `_run_scan()`이 잡 단위로 생성해 세 모듈에 공유 전달한다. `crawl_cache`에 `"pages"` 키가 있으면 `_crawl.crawl()`을 재호출하지 않고 그 값을 재사용하며(중복 크롤 방지), 없으면 직접 크롤한 뒤 `crawl_cache["pages"]`에 채워 넣어 다음 모듈이 재사용하게 한다. `None`(직접 `scan()` 호출·테스트 등)이면 항상 크롤을 수행한다.

`default_pages` 모듈은 `stacks` 파라미터와 `progress_cb`를 추가로 받는다:
```python
def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         stacks: List[str] = None, cookies: dict = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: dict = None,
         auth_headers: dict = None,
         backend_filter: bool = True,
         backends: List[str] = None,
         flag_auth_blocked: bool = True) -> Dict[str, Any]:
```
- `stacks`: 사전 탐지된 기술 스택 목록. 값이 전달되면 내부 `_detect_stacks()` 호출을 건너뛴다.
- `backend_filter`: 백엔드 확장자 필터 (기본 `True`). 감지된 스택의 언어 패밀리(`STACK_BACKEND`: Tomcat 등 → `java` / IIS·ASPNET → `dotnet` / PHP·WordPress 등 → `php`) ∪ `backends`로 전달된 사용자 선택 언어와 다른 백엔드 실행 확장자(`BACKEND_EXT`: `.jsp`/`.php`/`.aspx` 등) 경로를 제외한다. 정적·스택 무관 확장자는 항상 프로빙되며, 허용 언어 집합이 하나도 확정되지 않으면 필터를 적용하지 않고 전량 프로빙한다(recall 우선 안전장치).
- `backends`: 사용자가 직접 선택한 백엔드 언어 패밀리 목록 (`BACKEND_FAMILIES = {"java", "dotnet", "php"}`에 없는 값은 무시). 자동 탐지가 언어를 확정하지 못하는 스택(Apache/Nginx/에디터류 등)만 감지된 경우에도, 사용자가 언어를 지정하면 그 언어 기준으로 `backend_filter`가 강제 활성화된다.
- `flag_auth_blocked`: 401/403 응답을 노출로 판정할지 여부 (기본 `True` — 대시보드 체크박스는 기본 OFF로 `False`를 명시 전송). `False`면 401/403 응답은 노출 판정 자체에서 제외되어 finding이 생성되지 않는다. `True`면 노출로 판정하되 severity는 json 정의 등급(MEDIUM/LOW)과 무관하게 항상 `INFO`로 강등한다(301/302 강등과 동일 방식).
- `stop_event` (4개 스캔 모듈 공통, 선택): `threading.Event`. `_run_scan()`이 `build_module_extra()`로 주입하며, set되면 각 모듈의 요청 직전·딜레이 대기 지점에서 `wait_or_cancel()`이 `ScanCancelled`를 던져 즉시 중단된다. 자세한 흐름은 섹션 3-1 '즉시 중단' 참조.

**공통 크롤러(`modules/_crawl.py`) 동작:**
- BFS 시작 전 `robots.txt`와 `sitemap.xml`을 조회하여 같은 도메인 URL을 추가 시드로 큐에 선투입한다. `robots.txt`의 Disallow/Allow/Sitemap 지시자는 발견 힌트로만 활용하며 차단 규칙을 따르지 않는다. `sitemap.xml`은 `<sitemapindex>`가 감지되면 하위 sitemap URL을 재귀 조회한다(깊이 3, 자식 20개 상한). 이 시드 수집 요청들(robots.txt·sitemap.xml·재귀 자식 sitemap 전체)도 BFS 본 루프와 동일하게 매 요청 직전 `wait_or_cancel(stop_event, delay)`을 거쳐 딜레이를 지키고 [중단]에 즉시 반응한다.
- 응답을 `html` / `script` / `json` / `other` 네 종류로 분류한다. `text/html` 또는 `application/xhtml+xml` CT이면 `html`, `javascript`/`ecmascript` CT 또는 `.js` URL이면 `script`, `application/json` CT이면 `json`. 위 CT로 특정되지 않는 모든 경우(CT 누락·`text/plain`·`application/xml`·`application/octet-stream` 등)에는 응답 본문 앞 500자를 스니핑하여 `<!doctype html`·`<html`·`<?xml` 등 흔한 HTML 태그로 시작하면 `html`로, `{`/`[`로 시작하고 `json.loads` 파싱에 성공하면 `json`으로 승격, 둘 다 아니면 `other`. 분류는 HTTP 상태 코드와 무관하게 적용되어 403·404 등 비200 응답도 분류 결과에 따라 본문이 파싱된다. `html`·`script`·`json`은 본문을 보관하고 링크·입력 포인트 추출 대상이 된다. `other`는 경로 수집용으로만 기록한다.
- HTML 본문에서 링크를 추출하는 소스: 따옴표·미따옴표 `href`/`src`/`action` 속성(등호 앞뒤 공백 허용, 값 내부에 반대 따옴표가 있어도 여는 따옴표와 짝이 맞는 지점까지 캡처), `data-url`/`data-href`/`data-action`/`data-src` 속성, `srcset` 속성(쉼표 분리 첫 토큰), `<meta http-equiv="refresh">` url= 값, `<base href>` 기준 상대 URL 해석, GET `<form>`(action + 필드명을 조합한 쿼리 URL로 큐 추가, POST 폼은 제외). 스크립트 본문(`<script>` 블록·인라인 이벤트 핸들러·`.js` 파일)에서는 `fetch`/`XMLHttpRequest`/`$.ajax`/`axios`/`window.open`/`location.href` 등 JS 호출 URL을 백틱(`` ` ``) 템플릿 리터럴 포함하여 추출해 큐에 추가한다(`${...}` 보간이 포함된 URL은 실제 경로가 아니므로 큐잉 제외). HTML 속성에서 추출된 URL에는 `html.unescape()`를 적용해 `&amp;` 등 엔티티를 복원한 뒤 파싱한다.
- **AST 기반 엔드포인트 탐지 보강(`modules/_endpoint_extract.py`):** 위 정규식이 놓치는 동적 조립 URL(변수 결합·`axios.create({baseURL})` 인스턴스·게이트웨이형 action 분기의 N-hop 파라미터 전파 등)을 esprima/tree-sitter AST 기반(`js_analysis.extract_endpoints()` 재사용)으로 보강한다. `html`/`script` 종류에 적용되며(`json`은 기존 URL 재귀 추출로 커버), 정규식 결과와 병합(union)만 하고 대체하지 않는다 — AST 파싱 실패(TS/JSX 등 미지원 문법)·백엔드 미설치 시 조용히 빈 결과로 폴백한다. 탐지된 엔드포인트는 게이트(`_endpoint_extract.gate()`)를 거쳐 ① 경로/호스트에 미해소 "{name}" 플레이스홀더가 남으면 드롭, ② 동일 사이트가 아니면 드롭(`_same_site()` 재사용), ③ 로그아웃 경로면 드롭(`_is_logout_path()` 재사용)한 것만 절대 URL로 큐에 추가한다. 쿼리 파라미터 값은 "리터럴처럼 생긴" 값(숫자 또는 점·괄호·공백 없는 단순 토큰)만 그대로 쓰고, N-hop 전파가 호출자의 비-리터럴 인자 표현식을 그대로 남긴 경우(예: `row.uid`)까지 포함해 그 외는 빈 문자열로 비운다(기존 `<form>` 필드 큐잉의 blank-value 관례와 동일). 드롭 사유는 각 스캔 모듈의 `debug_events`에 남아 `crawl_path.log`에서 확인할 수 있다. 같은 게이트가 `_sqli_util.parse_input_points()`의 입력 포인트 수집도 보강한다(섹션 아래 SQLi/경로순회 문서 및 `modules/sql_injection.md`/`modules/path_traversal.md` 참고) — "탐지"(js_analysis)와 "게이트"(`_endpoint_extract`) 둘 다 크롤러·SQLi·경로순회·디렉터리 리스팅이 공유하는 단일 출처이므로, 이후 경로 미탐 대응은 이 두 곳에 넣으면 네 모듈에 동시 적용된다. JS 분석 모드(`js_analysis.analyze()`) 자체는 이 게이트를 거치지 않는다 — 미해소 엔드포인트·저신뢰 `candidate_endpoints`까지 보여주는 것이 목적이라 의도적으로 분리되어 있다. 스캔 시작 시 대시보드가 `_ensureDeps('jsanalysis', ...)`로 의존성을 게이트하며(render 토글과 무관하게 항상), 미설치·설치 실패 시에도 정규식 폴백으로 스캔은 그대로 진행된다.
- 동일 서명(path + 쿼리 파라미터명 집합)의 URL은 최대 3회까지만 방문하여 값만 변하는 URL의 반복 트랩으로 인한 `max_pages` 예산 낭비를 방지한다. 단, 파라미터명이 페이지네이션 성격(`page`/`p`/`pg`/`pageno`/`page_no`/`pagenum`/`offset`/`start`/`skip`/`from`/`idx`)이면 이 상한을 적용하지 않아, `?page=1..N`처럼 이어지는 링크는 `max_pages` 한도 내에서 계속 발견될 수 있다.
- 요청 실패 시 `Timeout`·`ChunkedEncodingError`에 한해 최대 2회 재시도(0.5 s → 1.0 s 백오프)한다. `ConnectionError`·`SSLError` 등 영구적 오류는 즉시 중단한다.
- `stop_event`가 전달되면 매 페이지 진입·재시도 백오프·요청 간 딜레이 지점(시드 수집 요청·JS 렌더링 모드의 라우트 훅 포함)에서 `wait_or_cancel()`로 [중단] 여부를 검사한다. 정적 경로의 실제 요청 전송(robots.txt·sitemap.xml·페이지 방문 모두)은 `run_cancellable()`로 감싸져 있어, 이미 전송되어 응답을 기다리는 요청 도중에도 [중단]이 최대 0.1초 내 즉시 반응해 크롤을 `ScanCancelled`로 종료한다(상세: 섹션 3-1 'in-flight 요청 즉시 취소'). 시드 수집은 브라우저 초기화(render=True) 이후·try 블록 안에서 실행되므로, 시드 수집 중 중단되어도 Playwright 리소스 정리(finally)가 보장된다.
- 인증 세션 파기 방지를 위해 경로의 마지막 segment가 `logout` / `log-out` / `signout` / `sign-out`에 해당하는 링크는 큐 추가 단계에서 제외한다.
- 매칭 예시: `/logout`, `/auth/logout`, `/sqli/logout.jsp` 차단 / `/logout-help` 같은 확장 문자열은 차단 대상 아님.
- **도메인 경계 (보수적 정책):** 스캔 대상은 진입 URL과 동일 사이트로 제한된다(`_same_site()`). 호스트명 대소문자는 무시하며, 선행 `www.` 유무 한 단계 차이(`example.com` ↔ `www.example.com`)만 동일 사이트로 취급한다. 포트가 다르거나 그 외 서브도메인(`api.site.com` 등)은 같은 자산으로 보이더라도 별도 netloc이므로 스코프에서 제외된다. robots.txt·sitemap·JS에서 추출한 URL도 이 경계로 필터된다. 이는 진단 범위 이탈을 방지하기 위한 의도적·보수적 설계이다.
- **JS 렌더링 모드 (render=True, 기본 OFF)**: Playwright Chromium 헤드리스로 각 페이지를 렌더링하여 SPA·REST API 엔드포인트를 포착한다. 탐색 단계에만 사용하며 공격(주입) 요청은 계속 `requests`를 사용한다. 세 가지 수집 경로: ① 렌더 후 DOM(`page.content()`)에서 링크·입력 포인트 추출 — 기존 정적 추출 로직 그대로 재사용. ② 네트워크 인터셉션 — 브라우저가 실제 발생시키는 GET(쿼리 파라미터) / POST(바디) 트래픽을 입력 포인트로 기록, `kind="xhr"` 합성 엔트리로 반환. ③ `application/json` 응답은 `kind="json"` 분류 후 본문을 재귀 탐색하여 같은 도메인 URL 쿼리 파라미터를 수집(HATEOAS 커버, 렌더 OFF 정적 크롤에도 적용). C2 강제: 비-GET·GET 로그아웃은 라우트 단계에서 abort(전송 차단). 의존성 최초 설치 시 `_core._ensure_render_deps()`가 playwright 패키지 + Chromium 바이너리를 lazy 설치. 의존성·브라우저 기동 실패 시 정적 크롤로 자동 폴백.
  - **같은 도메인 delay throttle**: 라우트 훅(`_make_route_handler`)이 `base_netloc`과 같은 도메인으로 실제 전송(`route.continue_()`)되는 요청(문서 자신 + 모든 서브리소스 — JS/CSS/이미지/XHR 등)마다 전송 직전 `wait_or_cancel(stop_event, delay)`을 적용해, 타깃 서버가 받는 요청 속도를 정적 크롤과 동일하게 제한한다. 다른 도메인(CDN·폰트 등)은 타깃 서버 부하가 아니므로 대상에서 제외되어 즉시 통과한다. `stop_event`가 set되면 해당 요청만 즉시 `route.abort()`로 정리하고 반환한다(Playwright 콜백 스레드 밖으로 예외를 던지지 않고 훅 내부에서 직접 처리 — 콜백 스레드 예외 전파는 신뢰할 수 없으므로 회피). 이어지는 BFS 본 루프의 `wait_or_cancel(stop_event, 0)` 검사가 곧바로 크롤 전체를 `ScanCancelled`로 종료한다.
  - **탐색(goto) 시간 상한 없음**: 같은 도메인 서브리소스 수 × delay가 고정 `timeout`을 쉽게 초과할 수 있으므로 `page.goto(timeout=0)`으로 Playwright 자체 탐색 타임아웃을 비활성화한다. 대신 [중단] 버튼(라우트 훅의 즉시 abort)이 유일한 탈출 경로다.
  - **연쇄 XHR 드레인 대기**: `load` 이벤트 이후, 라우트 훅이 같은 도메인 요청을 관측할 때마다 활동 시각을 갱신하는 `activity` dict를 두고, 이 시각이 `(delay + 1.0)`초(delay=0이면 1.0초 고정) 이상 갱신되지 않을 때까지 최대 `settle_cap = max(10.0, delay * 6)`초 동안 폴링 대기한다. 페이지 로드 후 발생하는 연쇄 XHR 호출(A 응답 → B 호출 → C 호출)이 스로틀로 지연되어도 놓치지 않고 포착하되, 폴링형 SPA(주기적 알림 체크 등)로 인한 무한 대기는 `settle_cap` 절대 상한으로 방지한다. (구 버전의 고정 2초 `networkidle` 대기를 대체 — 요청이 라우트 훅에서 전송 전 대기하므로 Playwright의 networkidle 판정이 이 스로틀을 정확히 반영하지 못했다.)
- 크롤러 반환 dict 필드: `url`(최종 URL) / `path`(경로) / `body`(html·script·json 종류의 응답 본문, other·xhr는 None) / `kind`("html" \| "script" \| "json" \| "other" \| "xhr") / `visited_at`(방문 타임스탬프) / `points`(kind="xhr" 전용, 네트워크 인터셉션 입력 포인트 list).

크롤링 모듈(`directory_listing`, `sql_injection`, `path_traversal`)의 반환 dict 추가 필드:
```python
"crawl_events": list[tuple[str, str]]            # [(iso_ts, url)] — BFS 방문 타임스탬프 포함
"debug_events": list[tuple[str, str, str]]       # [(iso_ts, scope, msg)] — 핵심 흐름 이벤트
```
`crawl_cache` 재사용으로 실제 크롤을 수행하지 않은 모듈은 `crawl_events`를 빈 리스트로 반환한다 — 크롤을 수행한 모듈이 이미 같은 방문 기록을 남겼으므로 `save_crawl_log()` 로그에 중복 출력되지 않도록 한다.

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
    "tech_stack":    str | None,   # default_pages — 탐지된 기술 스택명. 스택 무관 공통 점검(modules/data/common.json)은 "Common"
    "status_code":   int | None,   # default_pages / directory_listing — HTTP 응답 코드
    "exposed_files": list | None,  # directory_listing — 노출 파일 목록 (최대 20)
    "total_files":   int | None,   # directory_listing — 전체 노출 파일 수
}
```

**심각도 체계**

| 수준 | 현재 사용 모듈 | 의미 |
|------|--------------|------|
| HIGH | sql_injection | SQL 인젝션을 통한 데이터 탈취·조작 가능 |
| HIGH | path_traversal(traversal/wrapper_scheme/windows_abs/unc_path/unix_system) | 구체적인 트래버설·프로토콜 래퍼·시스템 경로 패턴(고신뢰) — LFI·SSRF·파일 다운로드 등 수동 검증 단서 |
| MEDIUM | directory_listing, default_pages(관리 콘솔·실행 경로), path_traversal(ssrf_url/ip_addr/path_value/filename) | 단일 취약점으로 서버 내 직접 탐색/악용 가능(directory_listing/default_pages) 또는 슬래시·IP·확장자 등 값 형태만으로 매칭되는 광범위 패턴(저신뢰, path_traversal) |
| LOW | default_pages(샘플·문서 페이지) | 버전·내부 정보 노출 |
| INFO | default_pages(301/302 리다이렉트, 401/403 응답, BurpSuite 프록시 에러 응답) | 301/302는 없는 경로도 에러·안내 페이지로 리다이렉트하는 구현이 흔해 존재 근거 신뢰도가 낮아 강등, 401/403은 접근 제어가 정상 동작 중임을 보여주는 응답이라 리소스 존재만 확인되고 그 자체로는 심각한 위험이 아니므로 강등(`flag_auth_blocked` 옵션으로 노출 판정 포함 여부 자체를 제어 가능, 기본은 판정 제외), BurpSuite는 응답 본문에 `Burp Suite` 포함 시 판정 신뢰 불가로 강등 — 셋 다 재검증 필요 |

각 모듈 상세는 [modules/directory_listing.md](modules/directory_listing.md), [modules/default_pages.md](modules/default_pages.md), [modules/sql_injection.md](modules/sql_injection.md), [modules/sqli_extract.md](modules/sqli_extract.md), [modules/path_traversal.md](modules/path_traversal.md) 참고.

---

## 5. SQLi 데이터 추출 (별도 모드)

본 섹션은 SpaceScan의 별도 추출 모드를 설명한다. 탐지 모듈(§4)과 인터페이스를 공유하지 않으며, 사용자가 명시적으로 모드를 선택해 진입한다. 구현체는 [modules/sqli_extract.py](modules/sqli_extract.py)이며 모듈 상세는 [modules/sqli_extract.md](modules/sqli_extract.md)를 참고한다.

### 5-1. 추출 기법

세 가지 기법을 사용자가 명시적으로 선택한다 (자동 fallback 없음 — 실패 시 호출부가 재선택 메뉴 제공).

| 기법 | 속도 | 적용 조건 | 1행당 요청 수 |
|------|------|-----------|---------------|
| **Error-based** | 빠름 | DBMS 에러 메시지를 응답 본문에 노출하는 환경 | 2 (length + content) |
| **Boolean-blind** | 매우 느림 | 응답 차이만 관찰 가능한 환경 (`use_hex` 토글: HEX 5비트 또는 raw 8비트 이진 탐색) | 421 (`21 + 80×5`, `use_hex=True` 기준 — `False`(raw)면 글자당 비교 8회로 소폭 감소, ASCII/단일바이트 전용) |
| **UNION-based** | 빠름 | 컬럼 수·타입을 사전 입력 가능한 환경 | 2 |

지원 DBMS: **MySQL / MariaDB / MSSQL / PostgreSQL / Oracle / SQLite** (SQLite + Error는 미지원, 호출부가 재선택 모달 트리거).

### 5-2. 페이로드 빌더

- **랜덤 마커 시스템** — `qDLMTRq`(컬럼 구분자) / `qROWMTRq`(UNION 묶음 행 구분자) / `SecTestS...SecTestE`(UNION 격리) / `SecTest`+2자 hex 9자 마커(Error/Inline 격리)로 응답에서 추출 데이터를 정확히 분리
- **CHAR/CHR echo-immune 마커** — UNION 페이로드의 모든 마커 리터럴(`SecTestS`/`SecTestE`/`SecTestC{i}` visible probe)은 DBMS의 `CHAR(n,...)`(MySQL/MariaDB/MSSQL/SQLite) 또는 `CHR(n)||CHR(n)||...`(PostgreSQL/Oracle) 함수로 인코딩하여 페이로드에 평문 마커가 들어가지 않게 함. 응답 echo 환경(예: `<input value="...">`로 입력이 그대로 반사되는 페이지)에서도 echo 영역엔 SQL 함수 표현만 노출되고 실제 SQL 실행 결과로만 디코드된 마커가 나타나, 렌더링 영역과 echo 영역이 자연스럽게 분리됨
- **컨텍스트 자동 탐지** — `quote_context=None`일 때 진입 시 `'`/`"`/`')`/`'))`/numeric 등을 자동 식별. 수동 지정값(`""`=numeric 포함)은 자동 탐지 스킵
- **HEX 인코딩(`use_hex`, 기본 `True`, Error/Boolean/UNION 3기법 공통 토글)** — `True`면 Boolean은 `LENGTH(HEX(expr))` 기반 5비트 이진 탐색, Error는 청크 SUBSTRING 결과를 HEX로 감싸 디코드, UNION은 `HEX_FUNCS`로 감싼 값을 디코드 — 세 기법 모두 multibyte 안전. `False`(raw)면 원문에 직접 연산해 요청 수가 줄지만 ASCII/단일바이트 데이터 전용(DBMS별 ascii/ord/unicode 함수 반환값이 달라 멀티바이트는 부정확). 모든 DBMS에서 HEX 함수 인수를 문자열로 강제 캐스팅(`MySQL`/`MariaDB` → `CAST(... AS CHAR)`, `PostgreSQL` → `::TEXT::bytea`, `Oracle` → `TO_CHAR(...)`, `MSSQL` → `CONVERT(NVARCHAR(MAX),...) AS varbinary(MAX)`)해 정수 입력 시 odd-length hex 오류를 방지. 디코드는 MSSQL만 UTF-16 LE(`utf-16-le`), 나머지는 UTF-8. MSSQL `fn_varbintohexstr` 결과의 `0x` prefix는 자동 strip. **Boolean 모드 HEX 정규화(`_blind_hex_expr`)**: Boolean 이진 탐색의 비교 범위는 `[48,70]`(ASCII `'0'`–`'F'`, 대문자)로 고정되므로 소문자를 출력하는 PostgreSQL(`ENCODE(...,'hex')`)과 `0x` prefix를 붙이는 MSSQL(`fn_varbintohexstr`)은 SQL 레벨에서 정규화가 필요함. `_blind_hex_expr`이 PG는 `UPPER(ENCODE(::bytea,'hex'))`, MSSQL은 `UPPER(SUBSTRING(fn_varbintohexstr(...),3,...))` 형태로 변환해 추가 요청 없이 대문자·no-prefix HEX를 보장
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
| Row dump (UNION 묶음) | DBMS 집계 함수로 N행을 `qROWMTRq`로 결합 후 추출(`use_hex`에 따라 HEX 디코드 또는 raw). 집계 한계 초과·잘림 시 윈도우 단위 1행씩 폴백 |
| 목록 추출 (UNION 묶음) | `_q_base_*` base SELECT → `_q_batch_list` 집계 → `qROWMTRq` split. 실패·잘림 시 window=1 집계 폴백 |

진입 함수 시그니처는 [modules/sqli_extract.md](modules/sqli_extract.md) 참고.

### 5-4. 결과 저장

`save_to_excel(extracted, target_url, output_dir, excel_name=None, file_prefix="extract")` — 추출 결과를 엑셀 파일로 저장. 동일 이름으로 호출 시 항상 덮어쓰기.

- **마스터 파일** `{file_prefix}_<name>_DBfingerprint.xlsx`: INFO(메타+Fingerprint 결과+UNION 정보+Total Databases) + DBList(DB 목록) [+ SearchResult] — fingerprint 완료 직후 즉시 생성
- **DB별 파일** `{file_prefix}_<name>_<db>.xlsx`: INFO(+Total Tables) + `_TableMap`(시트명↔원본 테이블명↔총 컬럼수↔총 행수 매핑, 총 행수는 구버전 3컬럼 파일과 하위호환) + 테이블별 시트
- **시트명 sanitize**: 31자 제한 + 금지문자 `[]:*?/\\` 치환 + `INFO`·`_TABLEMAP` 충돌·dedup 처리
- **셀 sanitize**: `=`/`+`/`-`/`@`/탭/CR로 시작하는 값에 `'` prefix 부착 (Excel formula injection 차단). 읽기 시 `_restore_cell_value`로 제거
- **이전 결과 복원**: `load_from_excel(name, dir)` — 마스터 INFO에서 ctx 핵심값(DBMS/기법/컨텍스트/위치(position)/blind_template/UNION) 복원 → fingerprint 자동탐지 생략. DBList + DB별 파일에서 databases/tables/columns/dumps 복원. Total Databases/Total Tables/총 컬럼수/총 행수도 `extracted["totals"]`(databases/tables/columns/rows)로 함께 복원되어, 저장 당시 목록·행이 부분 추출 상태였으면 이어받기 가능(행 총개수는 COUNT 재조회 없이 즉시 재사용)
- **특수 검색모드 격리**: `file_prefix="search(<대상>-<검색어>)"`로 호출하여 일반 추출 파일과 완전히 분리된 파일에 저장. `extracted["search"]`(`{target, match, keyword, total, hits}`)가 있으면 마스터 파일에 **SearchResult** 시트(검색대상/매칭방식/키워드/위치/DB/테이블/컬럼)와 **INFO 시트의 Search 메타 4행**(Search Target/Match/Keyword/Total)이 추가된다. 드릴다운 결과도 동일 `file_prefix` 규칙으로 DB별 파일에 저장된다
- **검색 결과 복원**: `load_search_from_excel(excel_name, search_prefix, dir)` — INFO 시트에 "Search Total" 키가 있으면 신규 포맷으로 판단, Search 메타(target/match/keyword/total)와 SearchResult 시트의 DB/테이블/컬럼 컬럼에서 `hits_raw`를 재구성해 `(hits_raw, meta)` 반환. 키가 없으면 구버전 파일로 간주해 `None` 반환(신규 스캔 폴백). 라이브 데이터 변동(매칭 행 추가·삭제) 시 offset 재개(A경로) 또는 완료 판정(B경로) 오류 가능 — 검색 대상 DB가 비교적 안정적인 환경에서 사용 권장

### 5-5. API 사용법

**REST API** (`app.py`, 7개 엔드포인트):

요청 간 딜레이는 `speed` 필드로 1~6 레벨 제어 (5.0s ~ 0.0s, 1초 간격). fingerprint 단계는 사용자 delay와 무관하게 최소 0.3s/요청 강제 (`FINGERPRINT_DELAY_FLOOR`).

| 메서드 | 경로 | 용도 |
|--------|------|------|
| GET | `/api/extract/check-existing` | `?name=<excel_name>`으로 기존 파일 존재 확인. `{exists, summary?}` 반환 |
| GET | `/api/extract/search-check-existing` | `?name=<excel_name>&target=<database\|table\|column>&match=<contains\|exact>&keyword=<검색어>`로 특수 검색모드 기존 결과 존재·진행률 확인. `load_search_from_excel`로 파일을 읽어 target/match/keyword가 모두 일치할 때만 `{exists:true, total, current_count}` 반환, 그 외는 `{exists:false}` |
| POST | `/api/extract/start` | job 생성 + fingerprint 백그라운드 시작 |
| GET | `/api/extract/<id>/status` | 진행 상태 폴링 (ctx/절대경로 미노출) |
| POST | `/api/extract/<id>/action` | 액션 트리거 (`dbms_info`/`databases`/`tables`/`columns`/`dump`/`search`) — 동시 호출 시 409 Conflict. `databases`/`tables`/`columns`는 최초 호출 시 COUNT로 총개수를 산출해 `extracted.totals`에 저장(이후 재사용)하고, 목록 길이가 총개수에 못 미치면 부분 추출로 간주해 캐시 미스 처리 — 호출 시 기존 목록에 이어서 추출(resume)한다. 목록·dump·검색 스캔 모두 진행 중 30초 간격으로 조용한 엑셀 체크포인트 저장. `dump` + `confirm:false`는 COUNT 쿼리(Boolean-blind 기준 15~20+ 요청 소요 가능)를 `dump_estimate:<key>` 액션으로 백그라운드 스레드에서 비동기 실행한다 — `extracted.totals.rows["db.tbl"]`에 이미 값이 있으면(이전 견적·엑셀 재사용 로드로 확정된 경우) COUNT 재조회 없이 재사용하고, 없으면 실행 후 저장한다. 다른 액션과 동일하게 즉시 `{ok:true}`만 반환하며, 실제 견적은 상태 폴링(`current_action_id`가 `null`로 복귀)으로 확인한다. 완료 시 상태 응답에 `estimate:{rows,requests,seconds}`(남은 행 기준)·`estimate_resume_from`(0보다 크면 같은 컬럼의 부분 데이터가 있어 이어받기 가능) 필드가 채워진다. `search`는 `search_target`(`database`/`table`/`column`)·`search_match`(`contains`/`exact`)·`search_keyword`로 DB/테이블/컬럼명을 검색해 `{db,table,column,display}` 구조의 히트 목록을 반환 — 기법·DBMS·커스텀 페이로드는 세션 시작 시 확정된 `ctx`를 그대로 사용(재선택 없음). 히트는 검색 완료 후 일괄 반환이 아니라 진행 중 확인되는 즉시 `search_extracted.search.hits`에 증분 반영되어 상태 폴링으로 실시간 노출된다 |
| POST | `/api/extract/<id>/retechnique` | 기법 또는 DBMS 변경 후 fingerprint 재실행. Body `{technique?, dbms?, position?, blind_template?}` — `technique`/`dbms`/`position` 중 하나 필수. DBMS 자동 식별 실패 시 `dbms`만 지정 가능 (SQLite+Error, SQLite+where_case/orderby 조합은 400). `position=custom` 시 `blind_template` 필수 |
| POST | `/api/extract/<id>/cancel` | `ctx.cancelled=True` 동기화로 안전 중단. `_send`의 요청 간 딜레이는 `_throttle()`이 `ctx.cancelled`를 50ms 간격 폴링하므로, 긴 delay 도중에도 진행 중인 1건만 마치고 즉시 `InterruptedError`로 빠져나온다. Body `{reset: bool}` — `false`(기본): 현재 액션만 취소 후 ready 복귀 (누적 데이터 유지), `true`: 완전 종료 후 GC 대상 편입. 진행 중 액션 없으면 상태 무관하게 즉시 cancelled 마킹. `status`가 `completed`/`cancelled`이면 400("이미 종료된 job") — `error`(WAF 차단 등으로 실행 스레드가 이미 종료된 상태)는 허용해 GC 마킹 목적으로 즉시 cancelled 전환한다 |

`extract_jobs` dict는 인메모리 저장이며 완료/취소 후 1시간 경과 job은 다음 start 호출 시 TTL GC 정리. 외부 도메인 차단은 ExtractCtx 생성 시 `allowed_netloc` 1회 저장 후 `_send` 사전·사후 검증으로 강제된다.

`/api/extract/start` 추가 필드: `proxy_host` / `proxy_port` (선택) — 프록시 설정. `base64_encode` (bool, 기본 false) — SQL 페이로드만 Base64 인코딩. `save_excel` (bool, 기본 false) — `true` 시 `excel_name` 필수. `excel_name` (문자열) — 저장 이름 (예: `test` → `extract_test_DBfingerprint.xlsx`, `extract_test_<db>.xlsx`). `reuse` (bool, 기본 false) — `true` 시 기존 파일에서 extracted 복원 + fingerprint 자동탐지 생략. `dbms` (문자열, 선택) — 지정 시 DBMS 자동 탐지 스킵. `union_visible` (정수, 1-based, 선택) — 지정 시 UNION visible 자동 탐지 스킵. `union_row_batch` (정수, 기본 1) — UNION dump 시 한 요청으로 추출할 행 수. 1이면 기존 1행씩 동작, N이면 DBMS 집계 함수로 묶음 추출 후 한계 초과·잘림 시 윈도우 단위 폴백. `position_mode` (문자열, `"auto"`/`"manual"`, 기본 `"auto"`) — Boolean-blind 전용. `auto`이면 fingerprint 2단계에서 자동 탐지(Phase 1: WHERE AND, Phase 2: WHERE_CASE/ORDER BY CASE WHEN). `manual`이면 `position_value`로 명시. `position_value` (문자열, `"where"`/`"where_case"`/`"orderby"`/`"custom"`) — `position_mode=manual` 시 필수. `where_case`/`orderby`는 boolean 기법 + non-SQLite DBMS 전용. `custom`은 boolean 전용으로 `blind_template`을 함께 전달해야 함. `blind_template` (문자열) — `position_value=custom` 시 필수. `{cond}` 자리표시자를 포함한 전체 페이로드 템플릿(따옴표·CASE WRAP·주석 포함). qc 탐지·위치 탐지 모두 스킵하고 SQLite 제한도 미적용.

`/api/extract/<id>/action`의 `search_mode` 필드(bool, 기본 false, `search` 포함 모든 액션 공통) — `true`이면 일반 추출용 `extracted` 대신 격리된 `search_extracted`를 대상으로 액션을 실행하는 **검색 결과 드릴다운 모드**로 전환된다. `databases`/`tables`/`columns`/`dump`는 코드 변경 없이 그대로 재사용되며(대상 dict만 교체), 엑셀 저장도 `_search_file_prefix(job)`(`search(<target>-<keyword>)`)로 자동 격리된다. `search_extracted`가 아직 없는 상태에서 `search_mode:true` + `action != "search"`이면 400 에러(먼저 검색 실행 필요). `search` 액션 전용 추가 필드: `resume_search` (bool, 기본 false) — `true`이면 `save_excel=True` + `excel_name`이 있을 때 기존 검색 파일에서 hits_raw/total을 복원해 이어서 스캔. 파일 없음·포맷 불일치·조건(target/match/keyword) 불일치 시 조용히 신규 스캔으로 폴백. MSSQL table/column 경로는 완료 DB 스킵 + 미완료 DB 재스캔(raw dedup으로 중복 제거, COUNT는 항상 재계산).

`/api/extract/<id>/status` 응답의 `fingerprint` 객체: `failure_reason` 필드 추가 — `"dbms_detection"` (DBMS 자동 식별 실패, 수동 선택 모달 트리거) / `"technique"` (기법 미지원, 기법 재선택 모달 트리거). `unsupported_techniques`는 `failure_reason === "technique"`일 때만 `[ctx.technique]`으로 채워짐.

`/api/extract/<id>/status` 응답에 특수 검색모드 전용 필드 추가 — `search_extracted`(검색/드릴다운 결과 dict, 미실행 시 `null`) / `search_meta`(`{target, match, keyword}`, 미실행 시 `null`) / `search_excel_files`(검색 결과 엑셀 파일명 목록, 일반 `excel_files`와 별개 배열).

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

---

## 7. 정보수집 OSINT (별도 모드)

본 섹션은 SpaceScan의 정보수집(OSINT) 모드를 설명한다. 탐지 모듈(§4)·SQLi 추출(§5)·엑셀 취합(§6)과 인터페이스를 공유하지 않으며, 사용자가 대시보드 "정보수집 (OSINT)" 탭에서 직접 진입한다. 구현체는 [modules/recon.py](modules/recon.py)이며 모듈 상세는 [modules/recon.md](modules/recon.md)를 참고한다.

### 7-1. 하드 룰 — 순수 패시브

**대상 도메인·서브도메인·서버로는 어떤 요청도 직접 보내지 않는다.** 직접 접속하는 호스트는 아래 7개 제3자 소스뿐이다.

| 소스 키 | 호스트 | 조회 내용 |
|---------|--------|----------|
| `crtsh` | crt.sh (실패/타임아웃 시 api.certspotter.com 무키 폴백) | CT(Certificate Transparency) 로그 → 서브도메인 + 인증서 메타 |
| `wayback` | web.archive.org | Wayback Machine CDX 인덱스(`matchType=domain`) → 서브도메인 + 아카이브 URL (스냅샷 본문 미조회) |
| `commoncrawl` | index.commoncrawl.org | Common Crawl 인덱스(CDX, 무키, 최신 3개 인덱스) → 서브도메인 + 관측 URL |
| `urlscan` | urlscan.io | 기존 공개 스캔 결과 검색(search API, 무키·읽기 전용, 신규 스캔 제출 안 함) → 서브도메인 + 관측 URL |
| `archivepaths` | web.archive.org | robots.txt/sitemap.xml **아카이브 스냅샷 본문** 파싱 → 선언된 엔드포인트 경로 (대상이 아닌 아카이브에서 읽음) |
| `dns` | 8.8.8.8 / 1.1.1.1 | 공용 DNS 리졸버로 레코드 조회 (`dns.resolver.Resolver(configure=False)`로 OS 기본 리졸버 배제) |
| `internetdb` | internetdb.shodan.io | Shodan이 사전 수집해 둔 IP별 포트 정보 (무키, 읽기 전용 — 온디맨드 스캔 아님) |

### 7-2. 오케스트레이션 — `run_recon()`

```
1. crt.sh 조회 (실패 시 certspotter 무키 폴백) → 서브도메인 집합 확보 + 인증서 메타  [progress 6%]
2. Wayback CDX 조회          → 서브도메인 집합 병합 + URL 확보                [progress 12%]
3. Common Crawl 조회         → 서브도메인 집합 병합 + URL 확보                [progress 20%]
4. urlscan.io 조회           → 서브도메인 집합 병합 + URL 확보                [progress 26%]
5. 아카이브 robots/sitemap 파싱 → 각 서브도메인의 아카이브 스냅샷에서 엔드포인트 추출 [progress 45%]
6. 서브도메인 정렬 후 max_subdomains(기본 200, 10~1000)로 절단
7. DNS 조회 (공용 리졸버만) → 절단된 각 host의 A/AAAA/(CNAME) 확인            [progress 45→85%]
8. InternetDB 조회 → DNS로 확인된 각 IP의 포트/서비스 정보                    [progress 85→100%]
```

`sources`에 `internetdb`만 선택해도 IP 확보를 위해 `dns`가 자동 포함된다. 각 단계 반복 지점에서 `modules/_cancel.py`의 `wait_or_cancel(stop_event, 0)`로 중단 요청을 즉시 검사한다. 수집된 URL은 소스별로 누적된 뒤 호스트 단위로 그룹핑되어 `subdomain_urls`(호스트별 URL+발견소스 목록)로 반환된다 — `exclude_static`(기본 `True`)이면 정적 리소스 확장자(`gif`/`jpg`/`jpeg`/`png`/`webp`/`svg`/`ico`/`css`/`woff`/`woff2`/`mp4`) URL을 호스트당/전체 URL 상한 카운트 **전에** 제외하여, 정적 리소스가 상한 자리를 차지해 실제 엔드포인트가 밀려나지 않도록 한다. 반환 dict의 `subdomains`/`dns_records`/`certificates`/`subdomain_urls`/`ports`/`errors`/`meta` 필드 상세는 [modules/recon.md](modules/recon.md) 참고.

### 7-3. 결과 저장

- `generate_recon_html(result, output_dir)` — `reports/recon_<domain>_<timestamp>.html`. 서브도메인/DNS/인증서/서브도메인별 URL/포트 5개 섹션 + 상단 통계 카드. 수집 URL 섹션 제목에 정적 리소스 제외 여부·제외 개수(`meta.exclude_static`/`meta.url_excluded_static`) 표시.
- `save_recon_to_excel(result, output_dir)` — `reports/recon_<domain>_<timestamp>.xlsx`. 시트 구성: `INFO`/`Subdomains`/`DNS`/`Certificates`/`SubdomainURLs`/`Ports`. `INFO` 시트에 정적 리소스 제외 여부·제외 개수 행 포함. 셀 sanitize: `=`/`+`/`-`/`@`/탭/CR로 시작하는 문자열에 `'` prefix (Excel formula injection 차단).

### 7-4. API

| 메서드 | 경로 | 용도 |
|--------|------|------|
| POST | `/api/recon/start` | job 생성 + 백그라운드 실행. 요청 필드: `domain`(필수), `sources`(배열, 기본 `SOURCE_KEYS` 전체), `timeout`(3~30초 범위 보정, 기본 30), `max_subdomains`(10~1000 범위 보정, 기본 200), `exclude_static`(bool, 기본 `True` — 정적 리소스 확장자 URL 수집 제외) |
| GET | `/api/recon/<id>/status` | 진행 상태 폴링. `stop_event`/`html_report`/`excel_report`(절대경로) 제외, 대신 `has_html_report`/`has_excel_report` boolean 노출 |
| POST | `/api/recon/<id>/cancel` | `stop_event.set()`으로 중단. 이미 종료(`completed`/`cancelled`/`error`) 상태면 400 |
| GET | `/api/recon/<id>/report/html` | HTML 리포트 다운로드 (`send_file`) |
| GET | `/api/recon/<id>/report/excel` | Excel 리포트 다운로드 (`send_file`, `as_attachment=True`) |

**job_dict 구조**
```python
{
    "job_id":       str,          # recon_YYYYMMDD_HHMMSS_<6자리 hex>
    "domain":       str,
    "sources":      list[str],
    "status":       str,          # pending / running / completed / cancelled / error
    "progress":     int,          # 0~100
    "stop_event":   "Event",      # threading.Event (클라이언트 미노출)
    "result":       dict | None,  # run_recon() 반환값
    "html_report":  str | None,   # 절대 경로 (클라이언트 미노출)
    "excel_report": str | None,   # 절대 경로 (클라이언트 미노출)
    "error":        str | None,
    "created_at":   str,
    "completed_at": str | None,
}
```

`recon_jobs` dict는 인메모리 저장이며, 완료/취소/에러 후 1시간(`JOB_TTL_SEC`) 경과한 job은 다음 `/api/recon/start` 호출 시 TTL GC로 정리된다.

---

## 8. JS 데이터플로우 분석 (별도 모드)

본 섹션은 SpaceScan의 JS/HTML/XFDL/XADL/XJS/XML(및 내용이 순수 JS인 `.axd`) 정적 데이터플로우 분석 모드를 설명한다. 함수 인벤토리·호출 그래프·데이터플로우 재구성에 더해, fetch/XHR/jQuery/axios/beacon/WebSocket/EventSource/Nexacro transaction/form action(정적 HTML 및 JS 문자열로 동적 조립되는 `<form>` 모두) 등 HTTP 요청 sink를 탐지해 URL·메서드·전달 파라미터를 재구성하는 **엔드포인트 탐지**도 포함한다. 코드가 프로그램적으로 서버 URL을 요청 가능한 형태로 조립하는 화면 내비게이션·콘텐츠 로딩·기존 DOM 폼 재활용(`window.open`/`location.href`·`replace`·`assign`/iframe·팝업 컨트롤 로더/`<formRef>.action=url; ...; <formRef>.submit()`)도 동일한 공격표면으로 보아 확정 엔드포인트에 함께 담는다. 설정 객체는 리터럴뿐 아니라 `t={}; t.url=...` 같은 속성-대입 조립도 인식하고, URL이 삼항/if-else/논리연산/switch/변수 재대입으로 조건부 분기하면 분기당 엔드포인트를 하나씩 발행한다. 레거시/SPA에서 흔한, URL이 함수 파라미터로 조립되거나 action 단위로 분기하는 패턴, 래퍼가 래퍼를 감싼 다단 호출은 호출자 체인을 따라 최대 4단계까지 실제 인자로 구체화한다(N-hop 파라미터 전파, 엔드포인트당 서로 다른 `(url, params)` 조합 최대 300개). 이름 패턴으로 확정할 수 없는 커스텀 HTTP 래퍼(프로덕션 minify 번들에서 흔한 `obj["a"].fetch(url)` 형태)는 인자가 URL/경로처럼 생겼는지만으로 저신뢰 후보(`candidate_endpoints`)를 별도로 수집하는 **URL-형태 휴리스틱**도 포함한다. 함수별 **제어흐름 그래프(CFG)**와 각 호출·엔드포인트가 어떤 조건(if/switch/논리 AND·OR)에서만 도달 가능한지 나타내는 **가드 체인**도 재구성해, 클라이언트 단 인증우회·강제호출 가능 엔드포인트 파악을 지원한다(§8-7). 탐지 모듈(§4)·SQLi 추출(§5)·엑셀 취합(§6)·정보수집(§7)과 인터페이스를 공유하지 않으며, 사용자가 대시보드 "JS 데이터플로우 분석" 탭에서 직접 진입한다. 구현체는 [modules/js_analysis.py](modules/js_analysis.py)이며 모듈 상세는 [modules/js_analysis.md](modules/js_analysis.md)를 참고한다.

### 8-1. 하드 룰 — 완전 오프라인

**이 모듈은 어떤 외부 호스트로도 요청을 보내지 않는다.** 업로드된 바이트만 읽어 파싱한다(esprima·tree-sitter-javascript 백엔드 체인, §8-6 참고). HTML의 `<script src="...">` 외부 참조는 URL 문자열만 기록할 뿐 절대 fetch하지 않는다.

### 8-2. 지원 입력 형식

| 확장자 | 추출 방식 |
|--------|-----------|
| `.js` | 파일 전체를 단일 유닛(스크립트)으로 파싱 |
| `.axd` | ASP.NET WebResource/ScriptResource 핸들러 출력 — 확장자만 다를 뿐 내용은 순수 JS라 `.js`와 동일하게 파일 전체를 단일 유닛으로 파싱 |
| `.html` / `.htm` | `<script>` 블록(stdlib `html.parser` 기반, 관대한 파싱) + 인라인 이벤트 핸들러 속성(`onclick` 등 화이트리스트 44종) 값을 각각 별도 유닛으로 추출. 외부 `<script src="...">`는 URL만 `external_refs`에 기록. `<form action>`은 유닛이 아니라 엔드포인트로 직접 수집(하위 `<input>`/`<select>`/`<textarea>`/`<button>`의 `name`/`value`를 파라미터로 포함, 빈 action·`javascript:` 의사 URL은 제외) |
| `.xfdl` / `.xadl` / `.xml` | 투비소프트 Nexacro/XPlatform 폼·앱정의 XML. `xml.etree.ElementTree`로 파싱해 `<Script>` 엘리먼트의 CDATA를 유닛으로 추출 |
| `.xjs` | Nexacro 스크립트 파일. 우선 위와 동일한 XML(`<Script>` 루트) 파싱을 시도하고, XML 파싱 실패 시(순수 JS로 저장된 경우) 파일 전체를 단일 JS 유닛으로 폴백 |

지원하지 않는 확장자는 `files[].kind = "unsupported"`로 표시되고 분석 없이 스킵된다(배치 중단 없음). 하나의 유닛이 파싱에 실패해도 `parse_errors`에 기록만 하고 같은 파일의 나머지 유닛·다른 파일은 계속 처리된다(단, `.js`는 파일 전체가 유닛 1개이므로 실패 시 그 파일 전체가 스킵됨). 파싱 이후 분석 4단계(모듈 의존관계·axios 인스턴스·함수 인벤토리·모듈 최상위 스캔, 8-3 참고)도 유닛 단위로 동일하게 격리된다 — 이 구간에서 예외가 나도 `parse_errors`에 "분석 실패"로 기록하고 해당 유닛만 스킵할 뿐 배치 전체는 중단되지 않는다. 극단적으로 깊게 중첩된 코드(난독화·제어흐름 평탄화 등)로 인한 `RecursionError`도 `analyze()` 진입 시 재귀 한계 상향(`_RECURSION_LIMIT=5000`, 대시보드 실행 스레드는 스택 크기도 64MB로 함께 확장)으로 1차 완화하고, 그래도 넘는 경우는 이 격리로 흡수한다.

### 8-3. 분석 설계 — 4단계(함수 인벤토리 → 함수 내부 데이터플로우 → 파일 간 모듈 의존 관계 → 엔드포인트 탐지·N-hop 전파·URL-형태 휴리스틱)

**1단계 — 함수 인벤토리 (`_collect_functions`)**: 유닛의 AST를 재귀 순회하며 함수 선언식/표현식/화살표 함수를 모두 찾는다. 이름 없는 함수 표현식은 대입 위치에서 이름 힌트를 끌어온다(`const login = function(){}` → `login`, 클래스 메서드 `Foo.bar(){}` → `Foo.bar`). 각 함수는 `{file}::{name}@{line}` 형식의 고유 id를 부여받는다.

**2단계 — 함수 내부 데이터플로우 (`_analyze_dataflow`)**: 함수 본문을 스캔하여 지역변수 정의(`defs`)·반환(`returns`)·외부 호출(`out_calls`)과 각각의 의존 식별자(`depends_on`)를 추출한다. 흐름 비민감(flow-insensitive) 근사치로, if/else·루프 분기를 모두 순회하되 상호배타성은 구분하지 않는다(어떤 경로로도 도달 가능하면 의존관계로 기록). 중첩 함수 정의는 경계로 삼아 내려가지 않으며 별도 인벤토리 항목으로 자기 자신의 dataflow를 갖는다. 같은 순회 중 `guard_stack`으로 if/삼항(`? :`)/논리 AND·OR(`&&`/`||`)/switch case를 진입할 때마다 조건을 push하고 벗어나면 pop한다 — 이 구간에서 기록되는 `out_calls`/엔드포인트는 그 시점의 스택 스냅샷을 `guards`(`{kind, cond, line, auth_hint}` 목록)로 갖는다. `auth_hint`는 조건식 텍스트에 인증/권한 관련 키워드(`admin`/`auth`/`login`/`role`/`token`/`권한`/`인증` 등)가 포함되는지의 휴리스틱이며(`_is_auth_guard`), 클라이언트 단 인증우회·강제호출 가능 엔드포인트를 표에서 한눈에 구분하기 위한 참고 신호다.

**함수 내부 제어흐름 그래프 (`_build_cfg`)**: 함수 인벤토리 구성 중 `_analyze_dataflow`와 함께(같은 함수 본문 재파싱 없이) 실행되어 각 함수 레코드에 `cfg`(`{nodes, edges, entry, truncated}`)를 채운다. basic-block 정밀도 대신 AST 구조(if/switch/loop/try)를 그대로 결정 노드로 매핑하는 구조 기반(structural) 근사치로, 연속된 단순 문장은 하나의 block 노드로 묶고 분기가 시작되는 지점만 결정(마름모) 노드로 분리한다. `_analyze_dataflow`가 같은 함수에서 찾은 **확정** 엔드포인트(HTTP sink) 라인 집합을 받아 그 문장을 포함한 노드에 `has_sink=true`를 표시한다(sink 판정 로직을 중복 구현하지 않고 엔드포인트 탐지 결과를 그대로 재사용). URL-형태 휴리스틱 후보(`candidate_endpoints`)는 이 라인 집합에 포함되지 않아 CFG 강조에 영향을 주지 않는다(저신뢰 후보가 확정 신호를 흐리지 않도록). 노드 수 상한(`_CFG_MAX_NODES=150`) 도달 시 이후 구조는 생략되고 `truncated=true`가 채워진다.

**3단계 — 파일 간 모듈 의존 관계 (`_collect_module_info` → `_build_module_graph`)**: 유닛 파싱 중 ESM `import`/`export`(+ `export ... from` 재export)·CommonJS `require`/`module.exports`/`exports.x`·Nexacro `include "lib::common.xjs";`·HTML `<script src>`를 수집한다. 업로드가 `<input type="file" multiple>`/드래그앤드롭 기반이라 폴더 구조가 보존되지 않으므로, 경로형 지정자는 **베이스네임만으로** 업로드된 파일명 집합과 매칭한다(`_normalize_specifier`). 동일 베이스네임이 여러 개 업로드되면 "ambiguous"로 미해소 처리한다. 재export 체인은 `(file, name)` 방문 집합으로 순환을 방지하며 원본 정의까지 추적한다(`_resolve_export_chain`). 결과는 `modules.edges`(해소된 관계: `{from, to, kind, specifier}`, kind ∈ `import`/`require`/`include`/`script`)와 `modules.unresolved`(미해소: `{from, specifier, kind, reason}`)로 구성된다.

**호출 대상 해소 우선순위 (`_resolve_call_targets`)**: 각 `out_calls` 항목은 다음 순서로 해소를 시도하며, 성공한 첫 단계의 등급이 `resolution`에 기록되고 해소된 함수 id 목록이 `resolved_ids`에 채워진다.
1. **import/require 바인딩** — `obj.foo()` 형태에서 `obj`가 namespace import/require로 바인딩된 경우 해당 모듈 파일 내 `foo`를 조회 (`resolution="import"`/`"require"`)
2. **동일 파일 내 로컬 일치** — 같은 파일 내 이름이 일치하는 함수 (`resolution="local"`)
3. **include/script 공유 스코프** — Nexacro `include` 또는 HTML `<script src>`로 연결된 파일들 중 이름이 일치하는 함수(두 경우 모두 `resolution="include"`로 표기 — 전역 스코프 공유라는 동일한 의미)
4. **이름 매칭 폴백** — 위 단계가 모두 실패하면 전체 함수 중 이름이 일치하는 모든 후보로 연결 (`resolution="name"`, 과다 연결 가능)
5. 위 어느 것도 해당 없으면 `resolution="unresolved"`, `resolved_ids=[]`

**전역 호출 그래프**: `analyze()` 마지막 단계에서 모든 `out_calls`에 대해 위 해소 절차를 적용해 `resolved_ids`를 채우고, 이를 바탕으로 각 함수의 `called_by`(호출자 id 역인덱스)를 구성한다. 단일 파일만 업로드된 경우 import/require/include 관계가 없으므로 항상 2번(local) 또는 4번(name) 단계로 귀결되어 기존 이름 기반 매칭과 동일한 결과를 낸다.

**4단계 — 엔드포인트 탐지·N-hop 파라미터 전파·URL-형태 휴리스틱 (`_analyze_dataflow`의 sink 매칭 → `_propagate_endpoint_params`)**: 함수 내부 데이터플로우(2단계)를 스캔하는 동일한 AST 순회에서 HTTP 요청 sink 호출(`CallExpression`/`NewExpression`)을 함께 탐지한다 — 별도 순회를 두지 않아 함수 경계(중첩 함수는 내려가지 않음) 처리가 자동으로 일관된다. 이름 패턴으로 확정 sink가 아닌 호출은 URL-형태 휴리스틱(`_match_url_shape_candidate`, 아래 별도 항목)으로 저신뢰 후보를 시도한다 — 같은 호출이 확정 sink와 후보에 동시에 들어가지 않도록 상호 배타적으로 갈린다. 함수 밖(모듈 최상위) sink는 유닛별로 `_analyze_dataflow(program, [], ...)`를 한 번 더 호출해(함수 경계에서 멈추므로 각 함수 내부와 중복되지 않음) `func_id=None`으로 포착한다. HTML `<form action>`은 AST가 아니므로 `_ScriptCollector`가 별도로 수집한다. JS 문자열로 동적 조립되는 `<form>`(결제/SSO 리다이렉트 폼 등 `$("<form action='...'>...")` 관용구)은 `_ScriptCollector`가 볼 수 없어, `_match_sink_kind` 실패 시(구조적으로 배타) `_match_dynamic_form_sink`가 AST 레벨에서 bare `$(...)`/`jQuery(...)` 호출의 문자열 인자를 재구성해 `<form` 포함 여부로 별도 탐지하고, 매치되면 `_InlineFormParser`(stdlib `html.parser`)로 `action`/`method`/필드를 뽑아 동일하게 `kind="form"` 확정 엔드포인트로 발행한다(`.submit()` 호출 여부는 추적하지 않음 — 문장 간 흐름 추적 없이 마크업 자체를 충분한 신호로 간주).

- **sink 종류**(`_match_sink_kind`/`_match_new_sink_kind`, callee의 점(.) 경로로 매칭): `fetch` · `xhr`(`.open(method, url)`, arg0가 실제 HTTP 메서드 리터럴일 때만 — `window.open()` 등 오탐 방지) · `jquery-ajax`(`$.ajax`/`jQuery.ajax`, `$.ajax(url, settings)`/`$.ajax(settings)` 두 형태 모두) · `jquery-short`(`$.get`/`$.post`/`$.getJSON`/`$.load`) · `axios`(`axios(cfg)`/`axios.request`, 또는 아래 **import/require 별칭**의 동일 형태) · `axios-short`(`axios.get`/`post`/`put`/`delete`/`patch`, 또는 **axios 인스턴스 변수**·**import/require 별칭**의 동일 메서드 호출) · `beacon`(`navigator.sendBeacon`) · `websocket`/`eventsource`(`new WebSocket/EventSource(url)`) · `nexacro`(`.transaction(id, url, inDS, outDS, args, ...)` 또는 `gfnTransaction(...)`/`this.gfnTransaction(...)`, 관례상 POST) · `form`(정적 HTML `<form action>` 또는 JS 동적 조립 `<form>`, `_match_dynamic_form_sink`, 또는 여러 문장에 걸쳐 기존 DOM 폼의 action을 변조한 뒤 제출하는 `<formRef>.action=url; ...; <formRef>.submit()`/`.fireSubmit()` 관용구, `form_action_refs`) · `window-open`(`window.open`/`self.open`/`parent.open`/`top.open`, 화면 내비게이션) · `navigate`(`location.href=` 대입 또는 `location.replace`/`location.assign` 호출, 화면 내비게이션) · `content-url`(iframe/팝업 컨트롤 로더 메서드 관례, 예: DevExpress `ASPxClientPopupControl.SetContentUrl` — nexacro와 동일하게 메서드명으로 판별, `about:blank`/빈 값/`javascript:` 리셋 호출은 제외).
- **axios import/require 별칭 해소 (`_collect_axios_aliases`)**: 소스가 여러 파일로 업로드된 경우(번들링 전 원본 트리) `import ax from 'axios'`/`const n = require('axios')`처럼 axios 모듈 전체를 받은 로컬 변수명을 리터럴 `axios`와 동일하게 취급하고, `import {get} from 'axios'`처럼 메서드 하나만 구조분해 임포트한 경우의 단독 호출(`get(...)`)도 axios-short로 인식한다. `_collect_module_info`가 뽑은 유닛별 import 목록에서 `source === "axios"`인 항목만 걸러 만들며, 지역 스코프(함수 파라미터·지역변수)에 같은 이름으로 가려지면 axios 인스턴스와 동일하게 제외한다(shadowing 오탐 방지). ky/got/superagent 등 다른 HTTP 클라이언트 패키지는 메서드명·인자 형태가 달라 이 범위에 포함하지 않는다.
- **axios 인스턴스 탐지 (`_collect_axios_instances`)**: 프로덕션 번들은 `axios`라는 리터럴 이름이 minify로 사라지고, 요청도 `axios.create({baseURL})`로 만든 인스턴스를 통해 나가는 경우가 흔하다(레거시 게이트웨이의 action 분기와 별개의, 실전에서 더 흔한 패턴). 유닛 트리 전체(함수 경계를 넘어)를 사전 스캔해 두 형태를 인스턴스 테이블(`{인스턴스명: {url, static}}`)로 수집한다 — ① **직접 생성**: `V = <expr>.create({baseURL: "..."})`. ② **팩토리 경유**: `F = p => <expr>.create({baseURL: `...${p}...`})`로 팩토리를 먼저 인식한 뒤 `V = F(argExpr)` 호출을 만나면 팩토리의 baseURL 템플릿에서 `p`를 `argExpr`로 1-hop 치환. 판별 기준은 이름이 아니라 **설정 객체에 `baseURL` 키가 존재하는지**이므로 axios가 어떤 별칭으로 minify됐든 무관하게 동작하고, `baseURL` 없는 다른 라이브러리의 `.create()`는 자동으로 배제된다. 동일 이름이 여러 번 발견되면 최초 발견만 채택(다른 dataflow 근사치와 동일한 흐름 비민감 정책). 인스턴스 변수가 지역 스코프(함수 파라미터·지역변수)에서 같은 이름으로 가려지면 sink 판정에서 제외한다(shadowing 오탐 방지). 인스턴스 sink로 잡힌 호출은 재구성된 경로 앞에 `_join_url`로 baseURL을 결합해 완전한 URL을 만든다 — 경로가 이미 절대/프로토콜 상대 URL이면 baseURL을 무시한다(axios 실제 동작과 동일). 테이블은 **유닛(파일) 단위**로만 유효하며, 정의와 사용이 서로 다른 파일에 걸친 크로스파일 인스턴스는 대응하지 않는다.
- **설정 객체 조립: 리터럴 vs 속성-대입 병합** (`_merged_object_props`/`_is_object_like`, `local_props`): `$.ajax({url:"..."})`처럼 인자에 객체 리터럴을 직접 넣는 관례뿐 아니라 `var t={}; t.url="..."; $.ajax(t);`(빈 객체 후 속성-대입으로 조립, computed 키 `t["url"]`도 지원)도 동일하게 인식한다. `_analyze_dataflow`가 `obj.key=value` 형태의 대입을 변수명별로 누적한 `local_props`를 객체 리터럴 속성과 병합해 sink의 설정 객체(`opts`/`cfg`/데이터 인자)를 조회하는 모든 지점에서 참조한다(동일 키는 리터럴이 우선, `+=`로만 채워진 속성은 대상 밖). 이 병합이 없으면 속성-대입으로만 조립된 설정 객체가 빈 객체로 보여 `url` 키를 못 찾아 **sink 판정 자체가 취소**되는 미탐이 생긴다.
- **URL/파라미터 재구성** (`_reconstruct_str`): 리터럴·템플릿 리터럴·문자열 `+` 연결·지역변수(1단계 인라인, 최초 대입값 기준)는 값을 그대로 접어 넣는다. 함수 파라미터·해소 불가 식별자는 `{이름}` 플레이스홀더로, `this.PROP` 읽기는 유닛 전체에서 수집한 인스턴스 속성 테이블(`_collect_this_props`, axios_instances와 동일한 흐름 비민감 트레이드오프)로 정적 해소를 시도하고 실패하면 `{PROP}` 플레이스홀더로, 그 외 복잡한 표현식(멤버·호출·객체 리터럴 등)은 원문 슬라이스 그대로(중괄호로 감싸지 않음) 표기한다. 결과에 플레이스홀더가 전혀 없으면 `static=true`.
- **URL 분기 열거** (`_build_endpoints`/`_enumerate_url_node_variants`/`_reassignment_variants_for_identifier`): URL 노드 자체 또는 그것이 가리키는 변수가 조건부(삼항/if-else/논리 AND·OR/switch/변수 재대입)로 여러 값을 가지면 분기당 엔드포인트 레코드를 하나씩 발행한다(분기가 없으면 기존과 동일하게 정확히 1개). `+`연결·템플릿 리터럴은 조각별 후보의 데카르트 곱으로, 변수 재대입은 선언 이후의 모든 대입(`=`/`+=`)을 프로그램 순서대로 적용하되 가드 경로가 모순되는(`_guard_paths_compatible`, if/else·switch 형제 분기) 후보 위에는 겹쳐 적용하지 않아 삼항 체인 등에서 값이 교차 결합되지 않는다. 완전분기 자체는 증명하지 않는 안전한 근사치라 "분기 전 값"도 함께 남을 수 있으며(경로 형태가 아니면 잡음으로 간주해 제거), 호출 1건당 `_URL_BRANCH_CAP`(8)으로 조합을 제한한다.
- **전달 파라미터 추출**: URL 재구성 결과의 쿼리스트링 부분(`_split_url_query`)과, sink별 데이터 인자(`fetch`의 `opts.body`, `jquery-ajax`/`axios`의 `cfg.data`/`cfg.params`, `axios-short`/`beacon`/`jquery-short`의 위치 인자, `nexacro`의 인자 문자열+in/out Dataset명)를 `_extract_data_params`로 통합 추출한다. 객체(리터럴 직접/지역변수 간접/속성-대입 조립, `JSON.stringify(obj)` 언랩 포함)는 `_merged_object_props`로 키별로 분해하고, 그렇지 않으면 문자열을 쿼리스트링 형식(`a=1&b=2`, 공백 구분 `a=1 b=2`도 지원)으로 재시도하며, 그마저 실패하면 통째로 `"(body)"` 파라미터 하나로 표기한다(값을 버리지 않는 best-effort 정책). 각 파라미터는 `{name, value, in, static}`(`in` ∈ `query`/`body`/`form`/`dataset`).
- **N-hop 파라미터 전파** (`_propagate_endpoint_params` → `_propagate_one` 재귀, `called_by`가 확정된 뒤 실행): 엔드포인트의 url/params 값에 남은 `{paramName}` 플레이스홀더 중 소속 함수(`func_id`)의 매개변수와 일치하는 이름을, 그 함수를 호출하는 함수(`called_by`)의 실제 인자값(호출자 자신의 스코프에서 이미 재구성된 `out_calls[].args[].value`, 매개변수 위치로 대응)으로 치환해 `variants`에 채운다. 치환 결과에 **그 호출자 자신의 매개변수**와 일치하는 플레이스홀더가 남아 있으면(래퍼가 래퍼를 감싼 다단 구조) 그 호출자의 호출자로 재귀적으로 계속 전개한다. 최대 `_HOP_MAX`(4)단계까지만 거슬러 올라가며, 순환은 방문 집합으로 차단하고 엔드포인트당 서로 다른 `(url, params)` 조합 수는 `_VARIANT_CAP`(300)으로 제한한다 — url만으로 dedup하면 URL은 정적이고 파라미터만 갈리는 게이트웨이 패턴(예: `cmd` 파라미터로 action을 분기하는 레거시 게이트웨이)에서 서로 다른 값이 잘못 병합되므로 반드시 url과 params를 함께 묶어 dedup한다. 더 못 가는 갈래(호출자 없음/hop 상한/순환/구체화 대상 소진)마다 그 시점까지 구체화된 값을 `{from, chain, hops, url, params}`로 확정한다(부분 구체화도 버리지 않는 best-effort). 호출자 인자가 리터럴이 아니면 치환 결과에도 플레이스홀더가 남을 수 있다.
- **URL-형태 휴리스틱** (`_match_url_shape_candidate`): 이름 패턴으로 확정 sink가 아닌 호출을, 인자가 URL/경로처럼 생겼는지만으로 저신뢰 후보(`candidate_endpoints`)로 수집한다. 프로덕션 minify 번들에서 axios 인스턴스가 `obj["a"].fetch(url)`처럼 computed 접근·임의의 메서드명 뒤에 숨어 이름 패턴으로는 놓치는 경우를 겨냥한다. callee 말단이 순수 문자열/배열 빌트인이거나 `require`면 제외하고, 인자 노드가 `Literal`/`TemplateLiteral`/`Identifier`/문자열 `+` 연결일 때만(나눗셈 등 산술식의 원문 슬라이스 폴백에 우연히 `/`가 섞이는 오탐 방지) URL-형태(절대경로·`http(s)://`·`//`·`word/word` 상대경로 세그먼트)를 검사한다. 후보는 `method="?"`·`kind="heuristic"`으로 고정되고 확정 sink와 절대 섞이지 않으며(구조적으로 상호 배타), 파라미터 전파(N-hop)는 적용되지 않는다. 이름 기반이 아니므로 확정 sink보다 오탐 가능성이 높다(예: Vuex `dispatch("User/getProfile")` 같은 비-HTTP 경로형 문자열).

### 8-4. Mermaid 그래프 생성

다섯 종류의 mermaid 소스를 생성한다(구현: `to_mermaid_call_graph` / `to_mermaid_dataflow` / `to_mermaid_cfg` / `to_mermaid_file_cfg` / `to_mermaid_module_graph`). 호출·데이터플로우·모듈 그래프는 좌→우 흐름이 자연스러워 `graph LR`, CFG 계열(함수 단위·파일 단위)은 위→아래 분기 흐름이 자연스러워 `graph TD`.

- **호출 그래프** (`to_mermaid_call_graph(analysis, center_id=None, max_nodes=120, depth=1, cross_file_only=False)`): `center_id` 미지정 시 전체 함수(최대 `max_nodes`개)를, 지정 시 해당 함수를 중심으로 `resolved_ids` 기반 BFS로 `depth`홉(1~5, 기본 1)까지 확장한 서브그래프를 그린다. 확장된 집합이 `max_nodes`를 넘으면 `center_id`를 항상 우선 포함하고 나머지는 결정적 순서(id 정렬)로 채운다(과거엔 집합이 Python set이라 슬라이싱 순서가 비결정적이었고 사용자가 선택한 center_id 자신이 잘려나가는 결함이 있었다 — 실제 대형 번들 재현 시 다수 발생 확인 후 수정). 중심 노드는 강조 스타일(주황색 채움)로 표시. `cross_file_only=True`이면 같은 파일 내부 호출 엣지는 숨기고 파일 경계를 넘는 엣지만 표시(노드 자체는 유지).
- **데이터플로우 그래프** (`to_mermaid_dataflow(func, analysis=None, expand=False, max_nodes=80)`): 함수 하나를 대상으로 좌→우 흐름(param 노드[둥근 모양] → 지역변수 정의 노드[사각] → return/외부호출 노드[알약 모양])을 그린다. `expand=True`이고 `analysis`가 주어지면, `out_calls`가 `resolved_ids`로 해소된(단일 대상) 호출의 경우 그 대상 함수의 데이터플로우를 재귀적으로 인라인 전개한다(인자→파라미터 위치 바인딩, 방문 집합으로 순환 방지, `max_nodes` 도달 시 확장 중단).
- **제어흐름 그래프(CFG)** (`to_mermaid_cfg(func)`): 함수 레코드의 `cfg`(8-3 참고)를 IDA 스타일의 분기 그래프로 그린다. decision 노드는 마름모, block/terminal 노드는 사각형. `has_sink=true`인 노드는 주황색으로 강조해 "이 HTTP 요청에 도달하려면 어떤 분기 조건을 거쳐야 하는지"를 한눈에 보여준다(강제호출 가능 엔드포인트 파악용). 여러 문장을 묶은 block 노드는 `<br/>`로 줄바꿈해 표시(mermaid `securityLevel:'strict'`에서도 DOMPurify가 `<br/>`는 보존).
- **파일 단위 분기 흐름 그래프** (`to_mermaid_file_cfg(analysis, file_name, page=0)`): 파일에 속한 함수를 라인 순으로 `_FILE_CFG_PAGE_SIZE`(80)개씩 페이지로 나눠, `page`번째 페이지에 속한 함수만 함수별 `subgraph`에 담아 이어붙인다(렌더링 규칙은 위 CFG와 동일). 같은 페이지 내 함수 호출(`resolved_ids`)은 호출자 함수의 entry 노드 → 피호출 함수의 entry 노드 점선 화살표로 연결해(함수 진입점 기준 근사) 함수 흐름을 조망한다(IDA 스타일 함수 그래프의 파일 전체 버전). 반환값은 `{mermaid, page, page_size, total_functions, total_pages}` — 대시보드는 이 값으로 이전/다음 페이지 버튼과 "전체 N개 중 M개 표시" 커버리지를 안내한다. mermaid 소스 맨 앞에 `_MERMAID_ELK_INIT` 지시문을 붙여 레이아웃 엔진을 ELK로 지정한다(dagre의 클러스터 렌더링 버그 회피 — §8-6 참고). 80은 사람이 한 화면에서 식별 가능한 함수 수 기준의 가독성 상한이다. 노드 id는 `_file_cfg_prefix()`가 정하는 규칙(함수 묶음 `ff{페이지내순번}_sg`, CFG 노드 `ff{페이지내순번}_{노드순번}`)을 따르며, 정렬·페이지 분할·라벨 생성 규칙은 아래 함수 위치 검색과 공유한다(`_file_cfg_sorted_funcs`/`_file_cfg_prefix`/`_file_cfg_sub_label`).
- **함수 위치 검색** (`find_file_cfg_functions(analysis, file_name, name_query="", limit=100)`): 위 그래프에서 특정 함수가 **몇 페이지의 어느 노드로 그려지는지** 되돌려준다 — 함수가 많은 파일은 그래프가 페이지로 나뉘고 원본 크기도 수만 px에 달해 눈으로 찾기 어렵기 때문이다. 그래프 생성과 같은 공유 헬퍼를 써 정렬·페이지 분할·id 규칙이 어긋날 수 없게 했고, 각 항목은 `{id, name, line, page, sg_id, entry_id, label, drawn}` — `drawn=false`는 본문이 비어 CFG 노드가 없는 함수(그래프에 그려지지 않음)다. 대시보드는 `page`로 해당 페이지를 그린 뒤 `sg_id`(→ 라벨 텍스트 → `entry_id` 순 폴백)로 화면에서 그 함수를 찾아 중앙으로 스크롤하고 약 4초간 강조한다.
- **모듈 의존 그래프** (`to_mermaid_module_graph(analysis, max_nodes=120)`): `analyze()`가 구성한 `modules.edges`를 파일 단위 노드로 시각화한다. 엣지 라벨에 관계 종류(`import`/`require`/`include`/`script`)를 표시.

노드 라벨은 파일명/함수명/코드 조각 등 업로드 콘텐츠 기반 문자열이므로 `_mmd_escape()`로 따옴표·개행 제거 및 길이 제한(50~60자) 후 삽입한다. CFG 계열(`to_mermaid_cfg`/`to_mermaid_file_cfg`)의 엣지 라벨(분기 조건 텍스트)은 노드 라벨과 달리 `_mmd_edge()`로 항상 인용부호(`-->|"..."|`)로 감싸 생성한다 — 괄호/중괄호/대괄호/파이프 등이 섞인 라벨(예: `switch` case의 문자열 리터럴)이 그대로 들어가면 mermaid 파서가 깨지기 때문(실측 확인 후 수정). 프론트엔드는 mermaid.js를 CDN이 아닌 로컬 번들(`static/vendor/mermaid.min.js`)로 서빙하며 `securityLevel:'strict'`, `maxEdges:3000`(기본값 500은 호출이 몰리는 허브 함수 패턴 등 실제 코드에서 쉽게 초과되어 "Edge limit exceeded"로 렌더 실패함을 실측 확인해 상향)으로 초기화한다(노드 라벨에 업로드 파일명·코드 조각이 들어가는 신뢰할 수 없는 데이터이므로 securityLevel은 strict 유지).

### 8-5. API

대용량 단일 파일(예: 1MB+ 프로덕션 번들)은 파싱만 수 초가 걸릴 수 있어, 정보수집(OSINT)과 동일한
**백그라운드 job + 폴링** 구조다. `POST /analyze`는 `analysis_id`만 즉시 반환하고, 실제 분석은
데몬 스레드에서 `js_analysis.analyze(sources, progress_cb, stop_event)`로 실행되며 진행률은
`/status` 폴링으로, 중단은 `/cancel`로 요청한다.

| 메서드 | 경로 | 용도 |
|--------|------|------|
| POST | `/api/jsanalysis/analyze` | multipart/form-data: `files`(여러 파일). 검증 통과 시 job을 생성하고 백그라운드 스레드로 즉시 시작. 응답: `{analysis_id}`만 반환(결과는 `/status` 폴링) |
| GET | `/api/jsanalysis/<id>/status` | job 진행 상태 조회. 응답: `{status, progress, stage, summary, error}` — `status` ∈ `pending`/`running`/`completed`/`cancelled`/`error`, `progress`는 0~100(진행 중엔 0~99), `stage`는 현재 단계 라벨, `summary`는 `completed`일 때만 `{files, function_count, module_edge_count, module_unresolved_count, endpoint_count, candidate_endpoint_count}`, `error`는 `error`일 때만 메시지 |
| POST | `/api/jsanalysis/<id>/cancel` | 실행 중인 job을 즉시 중단(`stop_event.set()` — 협조적 취소, modules/_cancel.py). 이미 종료된 job이면 400 |
| GET | `/api/jsanalysis/<id>/search` | 쿼리파라미터 `name`(함수명)·`file`(파일명) 부분/대소문자 무관 일치 검색. `completed` 상태가 아니면 409/404(진행 중/결과 없음). 응답: `{results}` |
| GET | `/api/jsanalysis/<id>/function` | 쿼리파라미터 `id`(함수id). 응답: `{function}` (defs/returns/out_calls/called_by/cfg 전체, out_calls 각 항목에 resolved_ids/resolution/args[].value/guards 포함) |
| GET | `/api/jsanalysis/<id>/modules` | 파일 간 import/require/include/script-src 의존 관계 목록. 응답: `{edges, unresolved}` |
| GET | `/api/jsanalysis/<id>/endpoints` | 쿼리파라미터 `method`(완전일치)·`url`(부분일치, 원문 `url`·표시용 정규화 경로 `path` 양쪽 대조)·`kind`(완전일치), 모두 대소문자 무관. 응답: `{results}` — 엔드포인트 목록(method/url/path/params/kind/file/line/func_id/static/variants/guards/placeholders), 상세는 [modules/js_analysis.md](modules/js_analysis.md) 참고 |
| GET | `/api/jsanalysis/<id>/candidate-endpoints` | 쿼리파라미터 `url`(부분일치, 대소문자 무관, 원문 `url`·표시용 정규화 경로 `path` 양쪽 대조). 확정 sink와 별도인 URL-형태 휴리스틱 저신뢰 후보 목록 — method는 항상 `"?"`, kind는 항상 `"heuristic"`. 응답: `{results}` — 후보 목록(url/path/url_expr/callee/params/file/line/func_id/static/guards/placeholders), 상세는 [modules/js_analysis.md](modules/js_analysis.md) 참고 |
| GET | `/api/jsanalysis/<id>/files-with-functions` | 함수가 하나 이상 있는 파일 목록(업로드 순서, "파일 별 분기 흐름" 탭의 파일 선택 목록용). 동일 파일명 중복 업로드 시 한 항목으로 합쳐 표시. 응답: `{files}` — `[{name, count}]` |
| GET | `/api/jsanalysis/<id>/filecfg-find` | 쿼리파라미터 `file`(파일명, 필수 — 없으면 400)·`name`(함수명 부분일치, 대소문자 무관, 빈 값이면 그 파일 전체 함수). 파일 별 분기 흐름 그래프에서 함수가 **몇 페이지의 어느 노드로 그려지는지** 조회 — 대시보드가 그 페이지를 그린 뒤 해당 함수로 스크롤·강조하는 데 쓴다. 응답: `{results, limit, page_size, total_functions, total_pages}` — `results`는 `[{id, name, line, page, sg_id, entry_id, label, drawn}]` |
| GET | `/api/jsanalysis/<id>/graph` | 쿼리파라미터 `kind`(`call`\|`dataflow`\|`cfg`\|`filecfg`\|`module`, 기본 `call`)·`id`(call/dataflow/cfg에서 사용, call은 중심 함수 지정 시 서브그래프·미지정 시 전체 그래프, dataflow·cfg는 필수, filecfg·module은 불필요)·`file`(filecfg 전용, 파일명, 필수 — 없으면 400)·`page`(filecfg 전용, 0-based, 기본 0)·`depth`(call 전용, 1~5, 기본 1)·`cross_file_only`(call 전용, `1`/`true`/`yes`)·`expand`(dataflow 전용, `1`/`true`/`yes`). 응답: `{mermaid}` — filecfg는 `page`/`page_size`/`total_functions`/`total_pages`도 함께 반환 |

결과 조회 8종(`search`/`function`/`modules`/`endpoints`/`candidate-endpoints`/`files-with-functions`/`filecfg-find`/`graph`)은 공통 헬퍼 `_jsanalysis_result_or_404()`로
job 상태를 확인한다 — job 없음(404, 만료/오탈자), `pending`/`running`(409, 진행 중), 그 외
`completed`가 아님(404, cancelled/error로 결과 없음)을 구분해 안내한다.

**진행률 가중치**: `js_analysis._UNIT_STAGE_WEIGHTS`가 유닛 하나를 처리하는 5단계(파싱 60·모듈
의존관계 6·axios 인스턴스 5·함수 인벤토리 25·최상위 스캔 4, 합계 100)의 실측 비중을 정의한다.
모듈 의존관계(axios import/require 별칭 포함)를 axios 인스턴스·함수 인벤토리보다 먼저 수집하는
순서는 실제 처리 순서와 동일하다(axios 별칭이 이후 두 단계의 sink 매칭에 필요하기 때문).
파일·유닛 개수로 0~95%를 균등 배분하고 각 유닛 내부는 이 가중치로 보간하며, 마지막 전역 단계
(모듈 그래프 구성·호출 해소·N-hop 전파)에 95~99%를 배분한다. 대용량 단일 파일은 파싱(esprima
단일 원자 호출)이 시간의 과반을 차지해 진행률이 부드럽게 차오르기보다 단계 경계에서 점프하지만,
`stage` 라벨로 현재 무엇을 하는지는 항상 정직하게 보여준다.

**즉시 중단**: [중단] 클릭 → `stop_event.set()` → analyze()는 파일/유닛 루프 경계에서 `wait_or_cancel`로,
유닛 내부 5단계 각각은 `run_cancellable`(modules/_cancel.py)로 감싸 원자적으로 오래 걸리는 구간
(esprima 파싱 등)에서도 중단을 검사한다 — 실측 기준 신호 후 100ms~1s 내(GIL 경합에 따라 변동)
`ScanCancelled`가 전파되어 job이 `cancelled`로 전환된다. `progress_cb`/`stop_event` 둘 다 생략하면
`analyze()`는 기존과 완전히 동일하게 동작한다(오버헤드 없음, 하위 호환).

`jsanalysis_jobs` dict는 인메모리 저장이며, 완료/취소/에러 후 1시간(`JOB_TTL_SEC`) 경과 시 다음
`/api/jsanalysis/analyze` 호출 진입부에서 TTL GC로 정리된다(정보수집 job GC와 동일 패턴 — 실행
중인 job은 완료 시점을 알 수 없으므로 GC 대상에서 제외).

### 8-6. 알려진 한계 (설계 단계에서 사용자와 합의된 근사치 분석 범위)

- 파싱은 esprima(1차, ES2017, 순수 파이썬) → 실패 시 tree-sitter-javascript(2차, ES2020+, 네이티브 바이너리) 순으로 재시도하는 2단 백엔드 체인이다(`_try_parse`). 후자는 `modules/_js_ts_adapter.py`가 esprima와 동일한 ESTree 노드 모양으로 변환해 반환하므로 다운스트림은 어느 백엔드가 파싱했는지 구분하지 않는다. 옵셔널 체이닝(`?.`)은 tree-sitter 백엔드에서 일반 멤버/호출 접근과 동일하게 근사(null-safety 자체가 추적 대상 밖)되며, TypeScript 타입 주석·JSX·데코레이터 등 두 백엔드 모두 지원하지 않는 문법만 해당 유닛의 파싱 실패로 이어져 `parse_errors`에 기록되고 스킵된다.
- 파일 간 관계 해소는 **베이스네임 매칭**이다(업로드가 폴더 구조를 보존하지 않으므로). 동일 베이스네임이 여러 개 업로드되면 어느 파일을 가리키는지 판별할 수 없어 "ambiguous"로 미해소 처리한다.
- 호출 그래프는 import/require/include/script-src로 우선 연결하고, 이 경로로 해소되지 않으면 **이름 기반 매칭**으로 폴백한다. 동적 디스패치(`obj[key]()`), `eval`, 클로저로 캡처된 외부 스코프 변수는 추적하지 않는다.
- 데이터플로우는 **흐름 비민감(flow-insensitive) 근사치**다. 조건 분기의 상호배타성을 구분하지 않고 모든 경로를 도달 가능한 것으로 간주한다. 데이터플로우 확장(`expand=1`)은 `resolved_ids`가 단일 대상으로 해소된 호출만 전개하며, 이름 매칭 폴백(여러 후보)이나 미해소 호출은 전개하지 않는다.
- XFDL/XADL/XJS/XML `<Script>` 블록 내부 라인 번호는 **블록 상대 라인**이다(파일 전체 절대 라인 매핑 미구현). 실제 Nexacro 샘플로 검증하지 못한 부분이다.
- 투비소프트 Nexacro **xscript**(ECMAScript 상위 방언)의 매개변수 타입 어노테이션(`function f(obj:Form)`), `<>` 부등호 연산자는 위 백엔드 체인이 원본 파싱에 모두 실패했을 때만 길이 보존 방식(공백/동일 길이 치환)으로 무력화해 재시도한다(`_sanitize_xscript`, 그 뒤 같은 체인 재적용). 표준 JS는 1차 파싱에서 성공하므로 영향 없음. `include "...";` 지시문은 별도로 파일 간 모듈 의존 관계로 추적된다(위 3단계 참고).
- XFDL/XADL/XML이 XML 금지 제어문자(0x00~0x1F 중 tab/LF/CR 제외)를 포함해 원본 파싱이 실패하면, 해당 바이트를 공백으로 치환해 재시도한다(`_strip_illegal_xml_bytes`). UTF-16 등 원본이 정상 파싱되는 인코딩에는 적용되지 않는다.
- 확정 엔드포인트(`endpoints`) 탐지는 위 표(8-3 4단계)에 나열된 **명명 패턴 기반 sink 목록에 한정**된다. 동적 디스패치(`obj[key]()`)·`eval`로 만든 호출은 확정 sink로도 URL-형태 휴리스틱으로도 탐지하지 않는다(callee 이름 자체를 특정할 수 없음). `.transaction`/`gfnTransaction`으로 끝나는 모든 멤버/함수 호출을 Nexacro 요청으로 간주하므로 무관한 동명 메서드가 있으면 과탐 가능하다(이름 매칭 폴백과 동일한 성격의 근사치). 목록에 없는 커스텀 HTTP 래퍼는 URL-형태 휴리스틱(`candidate_endpoints`)이 저신뢰 후보로만 보완하며, 확정 판정으로 승격되지 않는다.
- URL-형태 휴리스틱(`_match_url_shape_candidate`)은 **인자의 URL/경로 형태만으로** 판별하고 callee 이름·의미는 보지 않으므로 확정 sink보다 오탐 가능성이 높다. Vuex `dispatch("User/getProfile")`처럼 경로 형태를 띤 비-HTTP 문자열(라우터 경로, 액션 이름 등)이 후보로 섞일 수 있다 — 참고용 저신뢰 목록일 뿐 확정 판정이 아니며, 파라미터 전파(N-hop)도 적용되지 않는다.
- URL/파라미터 재구성은 **함수 자신의 스코프(파라미터 + 그 함수 내부에서 최초 대입된 지역변수, 1단계 인라인)까지만** 정적으로 해석한다. 모듈 최상위 `const`/전역 변수, 멤버 표현식의 프로퍼티 값(`cfg.base`처럼 객체 리터럴 프로퍼티를 다시 따라가지 않음)은 인라인하지 않고 식별자/원문 텍스트 그대로 표기한다 — **단, axios 인스턴스의 baseURL과 `this.PROP`(인스턴스 속성)는 예외**로, 모듈 최상위(또는 팩토리 1-hop)/유닛 전체에서 각각 별도 수집해 결합·해소한다(위 4단계, `_collect_this_props` 참고). baseURL/`this.PROP` 자체가 다른 모듈 상수를 참조하면(예: `` `https://api.${ENV}` `` 의 `ENV`) 그 조각은 여전히 플레이스홀더로 남는다.
- 설정 객체(sink 인자)는 리터럴 프로퍼티뿐 아니라 같은 함수 스코프 안에서 `obj.key=value`/`obj["key"]=value`로 나중에 채워진 속성도 인식한다(`local_props`, `_merged_object_props`) — 함수 스코프를 벗어난 크로스 함수 속성-대입은 대응하지 않으며, 대입 연산자가 `+=`인 속성-대입은 추적 대상 밖이다(`=`만 인식).
- URL이 조건부(삼항/if-else/논리 AND·OR/switch/변수 재대입)로 여러 값을 가지면 분기당 엔드포인트 레코드를 하나씩 발행한다(`_build_endpoints`/`_enumerate_url_node_variants`, 호출 1건당 `_URL_BRANCH_CAP`=8개 상한). 서로 다른 분기에서 나온 재대입은 가드 경로 모순 판별(`_guard_paths_compatible`)로 교차 결합을 막지만, **완전분기(if에 else가 있는지, switch에 default가 있는지) 자체는 증명하지 않는** 안전한 근사치라 값을 잃는 대신 "분기 전 값"이 경로 형태(`/` 포함)로 남으면 과다탐지될 수 있다.
- axios 인스턴스 테이블(`_collect_axios_instances`)은 **유닛(파일) 단위**로만 유효하다. 인스턴스를 파일 A에서 만들고 파일 B에서 사용하는 크로스파일 패턴은 대응하지 않으며, 이 경우 해당 파일에서는 인스턴스가 아닌 일반 식별자로 취급되어(`baseURL` 결합 없이) 종전처럼 `{이름}` 플레이스홀더로만 표기된다.
- XHR은 `.open(method, url)` 호출만 sink로 잡는다. 바디는 별도의 `.send(data)` 호출로 전달되는데, 같은 XHR 인스턴스의 `.open`과 `.send`를 연결하는 흐름 추적은 구현하지 않아 XHR 요청의 바디 파라미터는 추출되지 않는다.
- N-hop 파라미터 전파는 **호출자 체인을 최대 4단계(`_HOP_MAX`)까지만** 거슬러 올라간다. 순환은 방문 집합으로, 엔드포인트당 variant 총량은 **최종 `(url, params)` 조합 기준으로 중복을 제거한 뒤** `_VARIANT_CAP`(300)으로 방어하며, 상한에 걸리면 그 시점까지 구체화된 값을 variant로 남긴다. dedup 덕분에 이름 매칭 과다연결(`resolution="name"`) 등으로 생기는 동일/유사 조합 노이즈는 상한을 낭비하지 않고, 하나의 sink에 정당하게 수십~수백 개의 서로 다른 URL이 몰리는 케이스(레거시 팝업 게이트웨이 등)는 상한을 온전히 채운다. 호출자가 넘긴 인자 자체가 비-리터럴 표현식이면(예: 상수가 아닌 변수를 그대로 전달) 치환 결과에도 `{이름}` 플레이스홀더가 남을 수 있다(원본을 억지로 리터럴화하지 않는 정직한 표기).
- `window.open`/`location.href` 등 화면 내비게이션 sink는 이름 패턴 확정이라 분석 대상 코드 자체의 내비게이션은 정확히 잡히지만, 같은 파일에 포함된 라이브러리·프레임워크 코드(예: 페이지 전환 플러그인의 ctrl-클릭 새 탭 열기) 내부 호출도 구분 없이 함께 수집된다 — `kind`로 필터링해 구분해야 한다(값 손실보다 여분의 후보가 남는 쪽을 택하는 기존 정책과 동일).
- `<formRef>.action=url; ...; <formRef>.submit()` 폼 변조 탐지(`form_action_refs`)는 **함수 스코프 한정**이다 — 같은 함수 안에서 action 대입과 submit이 모두 일어나야 이어붙여지며, 함수 경계를 넘는 조립(예: 한 함수가 action을 설정하고 다른 함수/이벤트 핸들러가 나중에 submit)은 놓친다. 필드(input/select 등) 목록은 마크업이 없어 수집하지 않고 메서드는 항상 GET으로 근사한다(정적/동적 조립 form과 달리 `<form method>` 속성을 읽을 수 없음).
- 제어흐름 그래프(`_build_cfg`)는 **basic-block 정밀도가 아닌 구조 기반(structural) 근사치**다. 레이블 붙은 break/continue는 레이블을 구분하지 않고 가장 가까운 루프/switch를 대상으로 하며(레이블이 바깥쪽 루프를 가리키는 경우 잘못 연결될 수 있음), try 블록은 "블록 전체에서 예외가 발생할 수 있다"로 근사(문장 단위 정밀 추적 없음), switch case의 fallthrough는 break 유무로만 판단한다.
- 파일 단위 분기 흐름 그래프(`to_mermaid_file_cfg`)의 함수 간 호출 연결은 **호출부의 정확한 CFG 노드가 아닌 호출자/피호출 함수의 entry 노드 기준 근사**다(어느 분기 아래서 호출했는지는 각 함수 subgraph 내부의 has_sink/decision 노드로 별도 확인). 함수 수가 `_FILE_CFG_PAGE_SIZE`(80)를 넘는 파일은 페이지로 나눠 표시하며, 다른 페이지에 있는 함수로의 호출 화살표는 그리지 않는다(그 페이지만 보면 호출 관계 일부가 안 보일 수 있음 — 다음 페이지로 이동해 확인).
- mermaid(10.9.1)의 기본 레이아웃 엔진 dagre는 클러스터(subgraph, 즉 함수 묶음)가 많은 그래프에서 드물게 `Cannot set properties of undefined (setting 'order')`로 렌더가 깨진다(실제 프로덕션 minify 번들 2종, 함수 수백~수천 개로 재현 확인 — 클러스터 수와 상관성은 있으나 정확한 트리거 조건은 미확정이며, 페이지 크기를 80으로 낮춘 뒤에도 실제 번들 33페이지 중 5페이지에서 재현됨을 확인). 우리 쪽이 생성하는 mermaid 소스 자체에는 결함이 없음을 확인했다(전체 페이지 검사 결과 엣지가 선언되지 않은 노드를 참조하는 사례 0건 — dagre 내부 버그로 판단). `to_mermaid_file_cfg`는 mermaid에 이미 포함된 대체 레이아웃 엔진 **ELK**로 전환하는 지시문(`_MERMAID_ELK_INIT`)을 소스 맨 앞에 붙여 문제의 dagre 클러스터 코드 경로 자체를 우회한다 — 재현에 쓰인 두 번들 전체(43페이지)를 ELK로 재검증해 렌더 실패 0건, 클러스터·주황 강조·점선 호출·엣지 라벨 등 시각 요소 보존, dagre 대비 동등한 렌더 속도를 확인했다. 그럼에도 예기치 못한 렌더 실패가 남을 가능성에 대비해 프론트엔드는 dagre/ELK 어느 쪽이든 렌더가 실패하면 subgraph 테두리(함수 묶음 표시)만 제거한 평면 그래프로 자동 재시도하는 2차 폴백을 둔다(함수 구분은 각 진입 노드 라벨에 남음).
- 파일 별 분기 흐름 그래프는 mermaid가 렌더 결과 SVG에 직접 박아 넣는 인라인 `style="max-width:<원본폭>px"`(+`width="100%"`) 때문에 컨테이너 폭에 맞춰 통째로 축소된다 — 함수 수백 개짜리 파일에서는 글자를 읽을 수 없어 분석 자체가 불가능했다. 인라인 스타일은 스타일시트 규칙보다 우선하므로 CSS만으로는 되돌릴 수 없고, 프론트엔드가 렌더 직후 `viewBox`의 원본 크기를 읽어 SVG의 `width`/`height`/`max-width`를 **직접 덮어써야** 원본 크기가 나온다(`_jsaApplyFileCfgZoom`). 이렇게 펼친 그래프(실측 폭 2만 px 이상)는 카드 안 뷰포트(최대 78vh)에서 스크롤·드래그 팬·Ctrl+휠 줌(5~400%)으로 탐색한다.
- 함수 검색으로 찾아간 함수를 화면에서 특정할 때, ELK 레이아웃은 함수 묶음을 **라벨 노드(`id=flowchart-<묶음id>-<일련번호>`)와 id가 없는 테두리 rect(`g.subgraphs` 안) 두 조각**으로 그린다(실측). 따라서 테두리는 id로 찾을 수 없어 "라벨을 감싸는 가장 작은 rect"라는 좌표 포함 관계로 특정하며, 묶음을 찾지 못하면 라벨 텍스트 → 진입 노드 id 순으로 폴백한다(평면 폴백 렌더 대비). 대상이 캔버스 가장자리에 있으면 브라우저 스크롤 한계상 정중앙 정렬은 불가능하며, 화면 안에 들어오는 위치까지만 이동한다.
- 가드 체인은 **if/삼항(`? :`)/논리 AND·OR(`&&`/`||`)/switch case 4종만** 추적한다. 이 외의 암묵적 가드(예: 단축 평가가 아닌 별도 변수에 조건 결과를 저장했다가 나중에 분기하는 경우, `??`)는 guards에 반영되지 않는다.
- `auth_hint`(인증/권한 가드 추정)는 조건식 텍스트의 **키워드 부분일치 휴리스틱**이다. 키워드가 없는 인증 검사(예: 난독화된 변수명)는 놓치고, 키워드는 있지만 인증과 무관한 조건(예: UI 표시용 `role` 필드)은 오탐할 수 있다 — 참고 신호일 뿐 확정 판정이 아니다.
