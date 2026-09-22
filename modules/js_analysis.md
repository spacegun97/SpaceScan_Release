# js_analysis.py — JS/HTML/XFDL/XADL/XJS/XML 데이터플로우 분석 모듈

## 개요

업로드된 `.js`/`.axd`/`.html`(`.htm`)/`.xfdl`/`.xadl`/`.xjs`/`.xml` 소스에서 함수를 찾아내고, 함수별 내부 데이터플로우(파라미터→지역변수→반환/외부호출)와 함수 간 호출 관계(호출 그래프)를 정적 분석으로 재구성한다(`.axd`는 ASP.NET WebResource/ScriptResource 핸들러 출력으로, 확장자만 다를 뿐 내용은 순수 JS라 `.js`와 동일하게 처리). 파싱은 esprima(1차, ES2017)·tree-sitter-javascript(2차, ES2020+)의 2단 백엔드 체인으로 수행하며, 두 백엔드 모두 동일한 ESTree 노드 모양으로 다운스트림에 노출되므로 분석 로직 자체는 어느 백엔드가 파싱했는지 구분하지 않는다. 더불어 fetch/XHR/jQuery/axios(리터럴 호출 및 `axios.create({baseURL})` 인스턴스·팩토리 경유 포함)/beacon/WebSocket/EventSource/Nexacro transaction/form action(정적 HTML 및 JS 문자열로 동적 조립되는 `<form>`, 그리고 여러 문장에 걸쳐 기존 DOM 폼의 action을 변조한 뒤 제출하는 관용구까지 모두) 등 HTTP 요청 sink를 탐지해 URL·메서드·전달 파라미터를 재구성하고(엔드포인트 탐지), URL/파라미터가 함수 파라미터에 의존하는 경우(레거시 게이트웨이의 action 단위 분기 등) 호출자의 실제 인자로 N-hop 구체화한다. 코드가 프로그램적으로 서버 URL을 요청 가능한 형태로 조립하는 화면 내비게이션·콘텐츠 로딩(`window.open`/`location.href`·`replace`·`assign`/iframe·팝업 컨트롤 로더)도 동일한 공격표면으로 보아 확정 엔드포인트에 함께 담는다. 함수별로 IDA 스타일의 **제어흐름 그래프(CFG)**를 구성하고, 각 호출·엔드포인트가 어떤 조건(if/삼항/논리 AND·OR/switch case)에서만 도달 가능한지 나타내는 **가드 체인**(`guards`, 인증/권한 키워드 휴리스틱 `auth_hint` 포함)을 함께 기록해 클라이언트 단 인증우회·강제호출 가능 엔드포인트 파악을 지원한다.

탐지 모듈(`scan()` 인터페이스)·SQLi 추출·엑셀 취합·OSINT 정찰과 분리된 **별도 모드 유틸**이다(대시보드 UI·자체 job 흐름 기준 — 이 모듈은 스캔 결과나 다른 모듈 상태에 의존하지 않는다). 단, `extract_endpoints()`는 크롤러·SQLi/경로순회 입력 포인트 수집이 정규식을 보강하는 라이브러리 함수로 재사용한다 — 이 모듈 → 스캐너 단방향 참조이며 반대 방향 의존은 없다.

**하드 룰: 이 모듈은 어떤 외부 호스트로도 요청을 보내지 않는다.** 업로드된 바이트만 읽어 파싱하며, HTML의 `<script src="...">` 외부 참조는 URL 문자열만 기록하고 절대 fetch하지 않는다.

---

## 공개 함수

### `analyze(sources, progress_cb=None, stop_event=None) -> Dict[str, Any]`

```python
sources: List[Tuple[str, bytes]]                    # [(파일명, 바이트스트림), ...]
progress_cb: Optional[Callable[[int, str], None]]   # (진행률 0~99, 현재 단계 라벨) 통지
stop_event: Optional[threading.Event]                # set되면 협조적으로 즉시 중단
```

파일별 소스 추출 → 유닛별 파싱(esprima·tree-sitter 백엔드 체인, `_try_parse`) → 함수 인벤토리 구성 → 파일 간 모듈 의존 관계(import/require/include/script src) 구성 → 전역 호출 그래프(called_by 역인덱스) 구성 → 엔드포인트(HTTP 요청 sink) 탐지·N-hop 파라미터 전파까지 한 번에 수행한다.

`progress_cb`/`stop_event`는 app.py가 백그라운드 job(진행률 표시 + [중단] 버튼)으로 이 함수를 실행할 때 쓰이며, 둘 다 생략하면(기본값) 기존과 완전히 동일하게 동작한다(오버헤드 없음).

- **진행률**: 유닛 하나를 처리하는 5단계(파일 파싱→모듈 의존관계 분석→axios 인스턴스 분석→함수 인벤토리 구성→모듈 최상위 스캔)에 실측 비중 기반 가중치(`_UNIT_STAGE_WEIGHTS`, 합계 100: 60/6/5/25/4)를 매겨 파일·유닛 개수로 배분한 0~95% 구간에 보간하고, 마지막 전역 단계(모듈 그래프 구성·호출 해소·1-hop 전파)에 95~99%를 배분한다. 100은 이 함수 내부에서 도달하지 않으며 호출자(app.py)가 완료 후 명시적으로 설정한다. 파싱이 원자적 단일 호출(esprima)이라 대용량 단일 파일은 진행률이 부드럽게 오르기보다 단계 경계에서 점프하지만, 단계 라벨은 항상 정직하게 현재 작업을 반영한다. 모듈 의존관계(axios import/require 별칭 포함, "엔드포인트 탐지" 참고)를 axios 인스턴스·함수 인벤토리보다 먼저 수집하는 순서는 실제 처리 순서와 동일하다(별칭 정보가 이후 두 단계의 sink 매칭에 필요하기 때문).
- **중단**: `wait_or_cancel`(파일·유닛 루프 경계, 대기 없이 즉시 검사)과 `run_cancellable`(유닛 내부 5단계 각각을 감싸 원자적으로 오래 걸리는 구간에서도 협조적 중단 가능, 둘 다 `modules/_cancel.py`)을 조합한다. `stop_event`가 set되면 `ScanCancelled`(`BaseException` 하위, 기존 `except Exception` 폭넓은 처리에 흡수되지 않음)가 즉시 전파되어 `analyze()` 호출이 중단된다. 유닛 하나의 일반 파싱 실패(`ScanCancelled`가 아닌 예외)는 기존과 동일하게 `parse_errors`에 기록하고 계속 진행한다. 파싱 이후 분석 4단계(모듈 의존관계·axios 인스턴스·함수 인벤토리·모듈 최상위 스캔)도 유닛 단위로 하나의 예외 처리로 묶여 동일하게 격리된다 — 실패 시 `parse_errors`에 "분석 실패"로 기록하고 그 유닛만 스킵할 뿐 배치 전체는 중단되지 않는다. 극단적으로 깊게 중첩된 코드(난독화·제어흐름 평탄화 등)로 인한 `RecursionError`는 `analyze()` 진입 시 재귀 한계 상향(`_RECURSION_LIMIT=5000`, 이전 값이 더 크면 유지)으로 1차 완화하고(app.py의 백그라운드 job 스레드는 OS 스택도 64MB로 함께 확장), 그래도 넘는 경우는 이 유닛 단위 격리로 흡수한다.

반환 dict:

| 키 | 타입 | 설명 |
|----|------|------|
| `files` | `List[dict]` | 파일별 처리 통계 |
| `functions` | `List[dict]` | 전체 함수 인벤토리 (파일 간 import/require/include/script src로 우선 연결, 실패 시 이름 매칭 폴백) |
| `modules` | `dict` | 파일 간 의존 관계 `{edges: [...], unresolved: [...]}` |
| `endpoints` | `List[dict]` | HTTP 요청 sink(fetch/XHR/jQuery/axios/beacon/WebSocket/EventSource/Nexacro transaction/HTML form action)에 더해, 코드가 프로그램적으로 서버 URL을 요청 가능한 형태로 조립하는 화면 내비게이션·폼 제출(window.open/location.href·replace·assign/iframe·팝업 컨트롤 로더/여러 문장에 걸쳐 조립되는 DOM 폼 action+submit)까지 동일한 공격표면으로 보아 함께 담은 목록 |
| `candidate_endpoints` | `List[dict]` | 확정 sink 이름 패턴과 일치하지 않지만 인자가 URL/경로처럼 생긴 호출(이름을 알 수 없는 커스텀 HTTP 래퍼 등)을 모은 저신뢰 후보 목록. `endpoints`와 절대 섞이지 않는 별도 목록 — 상세는 "URL-형태 휴리스틱(candidate_endpoints)" 참고 |

`files` 항목 구조:

| 키 | 설명 |
|----|------|
| `name` | 파일명 |
| `kind` | 확장자(`.js`/`.axd`/`.html`/`.htm`/`.xfdl`/`.xadl`/`.xjs`/`.xml`) 또는 `"unsupported"` |
| `units` | 파싱에 성공한 유닛 수 |
| `parse_errors` | 유닛별 파싱/추출 실패 메시지 목록 (실패해도 나머지 유닛·파일은 계속 처리) |
| `external_refs` | HTML `<script src="...">` 외부 URL 목록 (fetch하지 않음, 기록만) |

`functions` 항목 구조 (함수 하나 = 하나의 레코드):

| 키 | 설명 |
|----|------|
| `id` | `{file}::{name}@{line}` 형식 고유 식별자 |
| `file` / `unit` | 소속 파일명 / 유닛 라벨(예: `<script>@L12`, `Script[btnSave]`, `inline:onclick@L5`) |
| `name` | 함수명 (이름 없는 함수는 대입 위치에서 힌트 추출, 그래도 없으면 `<anonymous#N>`) |
| `line` | 정의 라인 (유닛 `line_offset` 반영) |
| `params` | 매개변수명 목록 (구조분해/기본값/rest 모두 평탄화) |
| `defs` | 지역변수 정의 목록 — `{var, depends_on, expr, line}` |
| `returns` | 반환문 목록 — `{depends_on, expr, line}` |
| `out_calls` | 외부 호출 목록 — `{callee, args, line, expr, resolved_ids, resolution, guards}`. `args` 항목은 `{kind:"function_literal"}` 또는 `{kind:"expr", depends_on, value}` (`value`는 호출자 자신의 스코프에서 재구성된 인자 문자열 — 엔드포인트 N-hop 전파에 사용). `resolved_ids`는 해소된 대상 함수 `id` 목록, `resolution`은 해소 등급(`import`/`require`/`local`/`include`/`name`/`unresolved`) — 상세는 "파일 간 호출 해소" 참고. `guards`는 이 호출을 감싸는 조건 체인 — 상세는 "제어흐름 그래프(CFG)·가드 체인" 참고 |
| `calls` | `out_calls`의 callee 이름 집합 (정렬됨) |
| `called_by` | 이 함수를 호출하는 함수의 `id` 목록 (`resolved_ids` 기반 역인덱스로 채워짐) |
| `cfg` | 이 함수의 제어흐름 그래프 — `{nodes, edges, entry, truncated}`. 상세는 "제어흐름 그래프(CFG)·가드 체인" 참고 |

`modules` 구조:

| 키 | 설명 |
|----|------|
| `edges` | 해소된 파일 간 의존 관계 목록 — `{from, to, kind, specifier}`. `kind` ∈ `import`(ESM)/`require`(CommonJS)/`include`(Nexacro `include`)/`script`(HTML `<script src>`) |
| `unresolved` | 미해소 참조 목록 — `{from, specifier, kind, reason}`. `reason`은 `"missing"`(대상 파일 없음) 또는 `"ambiguous"`(동일 베이스네임 다중 업로드) |

`endpoints` 항목 구조 (엔드포인트 하나 = HTTP 요청 sink 호출 1건 또는 HTML form 1개):

| 키 | 설명 |
|----|------|
| `method` | HTTP 메서드(`GET`/`POST`/...) 또는 `WS`/`SSE`(WebSocket/EventSource) |
| `url` | 재구성된 URL 문자열(원문 — 절대 가공하지 않음). 해소 불가 부분은 `{이름}`(함수 파라미터·해소 불가 식별자·`this.PROP`) 또는 원문 슬라이스(그 외 복잡한 표현식)로 표기. URL이 조건부로 여러 값을 가지면(삼항/if-else/논리연산/switch/변수 재대입) 값마다 별도 레코드로 나뉜다 — 상세는 "URL 분기 열거" 참고 |
| `path` | `url`을 화면 표시용으로 정규화한 경로 — 상세는 "표시용 정규화 경로·플레이스홀더 출처 주석" 참고 |
| `url_expr` | URL 인자의 원문 소스 슬라이스 — 분기로 여러 레코드가 나뉘어도(위 `url` 참고) 모두 동일한 원본 소스를 가리킨다 |
| `kind` | sink 종류 — `fetch`/`xhr`/`jquery-ajax`/`jquery-short`/`axios`/`axios-short`/`beacon`/`websocket`/`eventsource`/`nexacro`/`form` |
| `file` / `unit` / `line` | 소속 파일명 / 유닛 라벨 / 호출 라인 — 분기로 여러 레코드가 나뉘어도 모두 같은 호출 라인 |
| `func_id` | 소속 함수 `id`. 함수 밖(모듈 최상위) 호출이거나 HTML form이면 `None` |
| `static` | `url`과 모든 `params[].value`에 플레이스홀더가 전혀 없으면(완전 리터럴로 확정) `True` |
| `params` | 전달 파라미터 목록 — `{name, value, in, static}`. `in` ∈ `query`(URL 쿼리스트링)/`body`(요청 바디)/`form`(HTML form 필드)/`dataset`(Nexacro in/out Dataset명) |
| `variants` | N-hop 파라미터 전파 결과 — `{from(가장 가까운 호출자 함수 id), chain(원 엔드포인트에서 가까운 순으로 나열한 호출자 id 목록), hops(전파 단계 수), url, path(url의 정규화 경로), params}` 목록. 전파 대상이 없거나 호출자가 없으면 빈 목록. 상세는 "엔드포인트(HTTP 요청 sink) 탐지 및 N-hop 파라미터 전파" 참고. 대시보드 "구체화된 값" 열은 앞 2개 항목만(각 48자 초과 시 말줄임) 미리보기로 보여주고, 그 이상이거나 항목 하나가 길어 잘렸으면 "전체보기" 버튼으로 전체 목록을 모달에서 보여준다 |
| `guards` | 이 엔드포인트를 감싸는 조건 체인 — `{kind, cond, line, auth_hint}` 목록. HTML form은 JS 조건 가드 개념이 없어 항상 빈 목록. 상세는 "제어흐름 그래프(CFG)·가드 체인" 참고 |
| `placeholders` | `path`(및 `params[].value`)에 남은 `{이름}` 플레이스홀더의 출처 주석 목록 — 상세는 "표시용 정규화 경로·플레이스홀더 출처 주석" 참고 |

`candidate_endpoints` 항목 구조 (확정 sink가 아닌 URL-형태 휴리스틱 후보 1건 = 호출 1건):

| 키 | 설명 |
|----|------|
| `method` | 항상 `"?"`(미상) — URL 형태만으로는 HTTP 메서드를 알 수 없음 |
| `kind` | 항상 `"heuristic"` |
| `url` | 재구성된 URL 문자열(`endpoints.url`과 동일한 `_reconstruct_str` 규칙, 원문 — 절대 가공하지 않음) |
| `path` | `url`을 화면 표시용으로 정규화한 경로 — `endpoints.path`와 동일 규칙 |
| `url_expr` | URL 인자의 원문 소스 슬라이스 |
| `callee` | 호출식 callee의 원문 소스 슬라이스(최대 60자, 예: `a["a"].fetch`) — 이름이 아니라 원문을 그대로 보여줘 동일 이름이 서로 다른 객체를 가리키는 경우도 구분 가능 |
| `file` / `unit` / `line` | 소속 파일명 / 유닛 라벨 / 호출 라인 |
| `func_id` | 소속 함수 `id`. 함수 밖(모듈 최상위) 호출이면 `None` |
| `static` | `url`과 모든 `params[].value`에 플레이스홀더가 전혀 없으면 `True` |
| `params` | 전달 파라미터 목록 — `{name, value, in, static}`. URL 인자 외 객체 리터럴 인자에서 best-effort로 추출(`in="body"`) |
| `guards` | 이 호출을 감싸는 조건 체인 — `endpoints.guards`와 동일 구조 |
| `placeholders` | `endpoints.placeholders`와 동일 규칙(다만 `func_id`가 없는 경우가 많아 대부분 `"unresolved"`로 표기됨) |

`candidate_endpoints`에는 `variants`가 없다 — 파라미터 전파(N-hop)는 확정 `endpoints`에만 적용된다.

**표시용 정규화 경로·플레이스홀더 출처 주석 (`_normalize_display_path`/`_placeholder_origins`)**: `url`(원문 재구성 결과)은 `this.contextRoot` 같은 인스턴스 속성이 안 풀리면 `{contextRoot}api/login`처럼 맨 앞에 플레이스홀더가, minify 코드의 `i.contextRoot`처럼 `this.`가 아닌 일반 멤버 접근은 플레이스홀더로 못 감싸져 `i.contextRootad/api/...`처럼 원문 슬라이스가 그대로 남아 화면에서 실제 경로 앞에 혼란을 주는 잔재가 붙을 수 있다. `path`는 이 두 잔재(①맨 앞 `{placeholder}`, ②첫 `/` 앞의 "ident.ident2" 형태 멤버식 잔재 — 단 `gateway.do/x`처럼 알려진 서버 경로 확장자로 끝나면 실제 경로로 보아 보존)만 제거한 표시 전용 값이며, `url` 자체는 절대 바꾸지 않는다(회귀 테스트·N-hop 전파 모두 원문 기준). 대시보드는 `path`를 기본 표시하고 `url`은 hover(title)로만 보여준다. `placeholders`는 `path`/`params`에 남은 각 `{이름}`이 대상 함수(`func_id`)의 매개변수와 일치하면 `{name, origin:"param", func_id, from_args}`(그 함수를 호출하는 모든 호출자가 해당 위치에 실제로 넘기는 인자식을 최대 8개까지 중복 없이 수집 — 리터럴이 아니어도 표시)로, 아니면(지역/전역/외부 식별자로 끝내 해소되지 않음) `{name, origin:"unresolved"}`로 출처를 표기한다. 리터럴로 확정되는 값 자체의 치환은 이미 `variants`(N-hop 파라미터 전파)가 담당하므로 `placeholders`는 "이 이름이 어디서 오는가"라는 설명 정보만 부가한다.

### 파일 간 호출 해소 (`_resolve_call_targets`)

`out_calls`의 각 호출은 아래 순서로 해소를 시도하고, 성공한 첫 단계의 등급이 `resolution`에 기록된다.

1. **`import`/`require`** — `obj.foo()` 형태에서 `obj`가 namespace import(`import * as obj`)나 `require()` 바인딩(`const obj = require(...)`)이면 해당 모듈 파일에서 `foo`를 조회
2. **`local`** — 같은 파일 내에서 이름이 일치하는 함수
3. **`include`** — Nexacro `include`로 연결되거나 HTML에서 같은 `<script src>` 셋에 속한 파일들 중 이름이 일치하는 함수 (include와 script-src 모두 "전역 스코프 공유"라는 동일 의미로 `"include"` 라벨을 공유)
4. **`name`** — 위 단계가 모두 실패하면 전체 함수 중 이름이 일치하는 모든 후보로 연결(폴백, 과다 연결 가능)
5. 모두 실패하면 `resolution="unresolved"`, `resolved_ids=[]`

경로형 지정자(`import`/`require`/`include`의 파일 경로)는 실제 상대경로가 아닌 **베이스네임만으로** 업로드된 파일명 집합과 매칭한다(`_normalize_specifier`) — 브라우저 파일 업로드가 폴더 구조를 보존하지 않기 때문. 동일 베이스네임이 여러 개 업로드되면 대상을 특정할 수 없어 미해소(`reason="ambiguous"`) 처리된다. `export ... from` 재export 체인은 `(file, name)` 방문 집합으로 순환을 방지하며 원본 정의까지 추적한다(`_resolve_export_chain`).

`"!"`가 포함된 지정자(예: `require("i18n!nls/commons")`, `text!template.html`)는 AMD/RequireJS **로더 플러그인** 호출이다 — `!` 앞은 파일 경로가 아니라 플러그인 이름이라 업로드 파일 집합에 대응 대상이 존재할 수 없으므로, 베이스네임 매칭을 시도하지 않고 의존 엣지·미해소 참조 어느 쪽에도 기록하지 않는다(완전 제외).

단일 파일만 업로드된 경우 import/require/include 관계가 존재하지 않으므로 항상 `local` 또는 `name` 단계로 귀결되어, 이 기능 추가 이전과 동일한 결과를 낸다.

### 엔드포인트(HTTP 요청 sink) 탐지 및 N-hop 파라미터 전파

함수 내부 데이터플로우를 스캔하는 `_analyze_dataflow`의 동일한 AST 순회(`CallExpression`/`NewExpression`/`AssignmentExpression`)에서 HTTP 요청 sink도 함께 탐지한다 — 별도 순회를 두지 않아 함수 경계(중첩 함수는 내려가지 않음) 처리가 자동으로 일관된다. 이름 패턴으로 확정 sink가 아닌 호출은 URL-형태 휴리스틱(`_match_url_shape_candidate`, 아래 별도 절)으로 저신뢰 후보를 시도한다 — 확정 sink와 후보는 같은 순회에서 상호 배타적으로 갈린다. 함수 밖(모듈 최상위) sink는 유닛별로 `_analyze_dataflow(program, [], ...)`를 한 번 더 호출해(함수 경계에서 멈추므로 각 함수 내부와 중복되지 않음) `func_id=None`으로 포착한다. HTML `<form action>`은 AST가 아니므로 `_ScriptCollector`가 별도로 수집한다. JS 문자열로 동적 조립되는 `<form>`(결제/SSO 리다이렉트 폼 등)은 `_ScriptCollector`가 볼 수 없어 `_match_dynamic_form_sink`가 AST 레벨에서 따로 탐지한다(아래 별도 절). HTTP 요청이 아니라 화면 내비게이션·콘텐츠 로딩·기존 DOM 폼 재활용이지만 코드가 프로그램적으로 서버 URL을 요청 가능한 형태로 조립한다는 점에서 동일한 공격표면으로 보아 함께 담는 sink도 있다(아래 표의 `window-open`/`navigate`/`content-url`과, 별도 절의 `<formRef>.action=url; ...; <formRef>.submit()` 관용구).

**sink 매칭 (`_match_sink_kind`/`_match_new_sink_kind`)**: callee를 점(.) 경로로 분해(`_callee_path`)해 이름 패턴으로 매칭한다.

| kind | 패턴 | URL 위치 | 기본 메서드 |
|------|------|---------|------|
| `fetch` | `fetch(url, opts?)` | arg0 | `opts.method` (기본 GET) |
| `xhr` | `.open(method, url)` — arg0가 실제 HTTP 메서드 리터럴일 때만(`window.open()` 등 오탐 방지) | arg1 | arg0 |
| `jquery-ajax` | `$.ajax`/`jQuery.ajax` — `$.ajax(url, settings)`/`$.ajax(settings)` 두 형태 모두 | arg0 또는 `settings.url` | `settings.type`\|`settings.method` (기본 GET) |
| `jquery-short` | `$.get`/`$.post`/`$.getJSON`/`$.load` | arg0 | 함수명 유래 |
| `axios` | `axios(cfg)`/`axios.request(cfg)` (또는 아래 axios 인스턴스·import/require 별칭의 `.request(cfg)`) | `cfg.url` | `cfg.method` (기본 GET) |
| `axios-short` | `axios.get`/`post`/`put`/`delete`/`patch` (또는 아래 axios 인스턴스·import/require 별칭의 동일 메서드) | arg0 | 함수명 유래 |
| `beacon` | `navigator.sendBeacon(url, data?)` | arg0 | POST |
| `websocket`/`eventsource` | `new WebSocket(url)`/`new EventSource(url)` | arg0 | WS/SSE |
| `nexacro` | `.transaction(id, url, inDS, outDS, args, ...)` 또는 `gfnTransaction(...)`/`this.gfnTransaction(...)` (경로 마지막 세그먼트가 `transaction`/`gfnTransaction`이면 매칭) | arg1 | POST(관례) |
| `form` | HTML `<form action="...">`(정적) 또는 `$("<form action='...'>...")`/`jQuery(...)`로 JS 문자열 조립되는 `<form>`(동적, 아래 별도 절), 또는 여러 문장에 걸쳐 기존 DOM 폼의 action을 변조한 뒤 제출하는 관용구(`<formRef>.action=url; ...; <formRef>.submit()`/`.fireSubmit()`, 아래 별도 절) | `action` 속성 또는 마지막 `.action=` 대입 우변 | `<form method>`(정적/동적 조립) 또는 GET(근사, DOM 변조 폼) |
| `window-open` | `window.open(url, target?, features?)`/`self.open`/`parent.open`/`top.open` — 화면 내비게이션(새 창). bare `open(...)`은 지역 함수와 구분 불가해 대상에서 제외 | arg0 | GET |
| `navigate` | `location.href = url` 대입(`window.location`/`document.location` 등 접두 경로 포함) 또는 `location.replace(url)`/`location.assign(url)` 호출(인자 정확히 1개일 때만) — 화면 내비게이션 | 대입 우변 또는 arg0 | GET |
| `content-url` | iframe/팝업 컨트롤에 URL을 로드하는 프레임워크 메서드 관례(`_IFRAME_CONTENT_URL_METHODS`, 예: DevExpress `ASPxClientPopupControl.SetContentUrl`) — 객체 변수명과 무관하게 메서드명으로 매칭(nexacro와 동일 방식). `about:blank`/빈 문자열/`javascript:` 의사 URL(팝업 리셋 관용구)은 정적 form과 동일 기준으로 제외 | arg0 | GET |

**axios 인스턴스 탐지 (`_collect_axios_instances`)**: 프로덕션 번들에서는 `axios`라는 리터럴 이름이 minify로 사라지고, `axios.create({baseURL})`로 만든 인스턴스 변수를 통해 요청이 나가는 경우가 흔하다. `analyze()`가 유닛 하나를 파싱한 직후 트리 전체(함수 경계를 넘어)를 한 번 더 스캔해 인스턴스 테이블(`{인스턴스명: {url, static}}`)을 만들고, 이를 `_collect_functions`와 함수 밖 최상위 스캔 모두에 전달해 `_match_sink_kind`가 함께 참조한다.

- **판별 기준**: 이름이 아니라 **설정 객체에 `baseURL` 키가 존재하는지**(`_is_create_call_with_baseurl`) — axios가 어떤 별칭으로 minify됐든 무관하게 동작하며, `baseURL` 없는 다른 라이브러리의 `.create()`(예: 검증 라이브러리)는 자동으로 배제된다.
- **직접 생성**: `V = <expr>.create({baseURL: "..."})` → `V`를 인스턴스로 등록.
- **팩토리 경유**: `F = p => <expr>.create({baseURL: `...${p}...`})` 형태의 팩토리 함수를 먼저 인식한 뒤, `V = F(argExpr)` 호출을 만나면 팩토리의 baseURL 템플릿에서 파라미터 `p`를 `argExpr`로 1-hop 치환해 `V`의 baseURL을 재구성한다(`레거시 게이트웨이의 action 단위 팩토리`와 유사한 1-hop 인라인).
- 동일 이름이 여러 번 발견되면 최초 발견만 채택한다(다른 dataflow 근사치와 동일한 흐름 비민감 정책).
- 인스턴스 sink 호출은 `_build_endpoints`에서 (분기가 있으면 분기당) 재구성된 경로 앞에 `_join_url`로 baseURL을 결합해 완전한 URL을 만든다. 경로가 이미 절대/프로토콜 상대 URL(`http://`·`https://`·`//`로 시작)이면 baseURL을 무시한다(axios/브라우저 실제 동작과 동일). `static`은 baseURL과 경로 양쪽이 모두 정적일 때만 `True`.
- 인스턴스 변수명이 지역 스코프(함수 파라미터 또는 그 함수 내 지역변수)에서 같은 이름으로 가려지면(shadowing) 그 스코프에서는 sink로 판정하지 않는다.
- 인스턴스 테이블은 **유닛(파일) 단위**로만 유효하다 — 정의와 사용이 서로 다른 파일에 걸친 크로스파일 인스턴스는 대응하지 않는다.

**axios import/require 별칭 해소 (`_collect_axios_aliases`)**: 소스가 번들링 전 원본 파일 트리로 여러 개 업로드된 경우, `import`/`require`로 받은 axios의 로컬 변수명도 리터럴 `axios`처럼 인식한다.

- `_collect_module_info`가 유닛별로 뽑은 `imports` 목록에서 `source === "axios"`인 항목만 걸러 두 그룹으로 정리한다: **roots**(axios 모듈 전체를 받은 이름 — `import ax from 'axios'`의 `ax`, `const n = require('axios')`의 `n`)와 **methods**(메서드 하나만 구조분해 임포트한 이름 → HTTP 메서드 — `import {get} from 'axios'`의 `get` → `GET`).
- `_match_sink_kind`는 callee 경로의 첫 세그먼트가 roots에 속하면 그 세그먼트를 `"axios"`로 정규화한 뒤 위 sink 매칭 표를 그대로 적용하고(`ax.get(...)` → `axios.get(...)`과 동일하게 매칭), methods에 속하는 단독 호출(`get(...)`)은 axios-short로 직접 인식한다.
- 지역 스코프(함수 파라미터·지역변수)에서 같은 이름으로 가려지면(shadowing) axios 인스턴스와 동일하게 sink 판정에서 제외한다.
- ky/got/superagent 등 다른 HTTP 클라이언트 패키지는 메서드명·인자 형태가 axios와 달라 이 범위에 포함하지 않는다(오탐 방지 — 필요 시 별도 sink kind로 확장).

**URL/파라미터 재구성 (`_reconstruct_str`)**: 식을 최대한 정적으로 접어 문자열화한다.
- 리터럴/템플릿 리터럴(`` `${a}/b` ``)/문자열 `+` 연결/지역변수(그 함수 내부에서 최초 대입된 값, 1단계 인라인, `local_inits`)는 값을 그대로 접어 넣는다.
- 함수 파라미터 또는 해소 불가 식별자(외부 스코프/전역/import 등)는 `{이름}` 플레이스홀더로 표기한다 — `{이름}`은 N-hop 전파의 매칭 대상이자 시각적 표식이다.
- `this.PROP` 읽기는 `this_props`(아래 "`this.PROP` 인스턴스 속성 해소" 참고)로 정적 해소를 시도하고, 값이 없거나 비정적이면 `{PROP}` 플레이스홀더로 표기한다.
- 그 외 복잡한 표현식(멤버 접근·호출·객체 리터럴 등)은 중괄호로 감싸지 않고 원문 슬라이스 그대로 표기한다(객체 리터럴처럼 원문 자체에 중괄호가 있는 경우 이중 래핑을 피하고, `{이름}` 형태와 시각적으로 구분하기 위함).
- 조건식(`a ? b : c`)은 consequent를 대표값으로 쓰되 분기가 있었다는 사실이 드러나도록 `static`은 항상 `False`(URL 노드 자체가 이 형태면 아래 "URL 분기 열거"가 별도로 양쪽을 모두 반영한다).
- 순환 참조는 방문 집합으로, 과도한 재귀는 깊이 상한(6)으로 차단한다.

**`this.PROP` 인스턴스 속성 해소 (`_collect_this_props`)**: `initialize(){ this.contextRoot = ...; }`처럼 한 메서드가 설정한 인스턴스 속성을 다른 메서드가 나중에 읽는 패턴에 대응한다. `axios_instances`와 동일하게 유닛(파일) 전체를 함수 경계를 넘어 한 번 스캔해 `this.PROP = 값` 대입에서 `{PROP: {value, static}}` 테이블을 만들고, `_collect_functions`·함수 밖 최상위 스캔 모두에 전달해 `_reconstruct_str`이 참조한다. 동일 이름이 여러 번 발견되면 최초 발견만 채택하며, 서로 무관한 클래스/객체가 같은 이름의 속성을 가져도 구분하지 않고 하나로 합친다(axios_instances와 같은 흐름 비민감 트레이드오프).

**설정 객체 조립: 리터럴 vs 속성-대입 병합 (`_merged_object_props`/`_is_object_like`/`local_props`)**: `$.ajax({url:"..."})`처럼 인자에 객체 리터럴을 직접 넣는 관례뿐 아니라, `var t={}; t.url="..."; $.ajax(t);`(빈 객체 후 속성 대입으로 조립, `t["url"]=...`형 computed 키도 지원)도 동일하게 인식한다. `_analyze_dataflow`가 `AssignmentExpression`을 방문하며 `obj.key=value`/`obj["key"]=value`(대입 좌변이 `Identifier`가 아닌 `MemberExpression`) 형태를 변수명별로 누적한 `local_props` 테이블을, sink의 설정 객체(`fetch`의 `opts`, `jquery-ajax`/`axios`의 `cfg`, `_extract_data_params`의 데이터 인자)를 조회하는 모든 지점에서 객체 리터럴 속성과 병합해 하나의 키→값 매핑으로 다룬다(동일 키가 리터럴과 속성-대입 양쪽에 있으면 리터럴이 우선). `$.ajax(url, settings)`처럼 "이 인자가 URL 문자열인가 설정 객체인가"를 구분해야 하는 자리는 `_is_object_like`(빈 `{}`나 속성-대입만 있는 변수도 "객체"로 인정)로 먼저 게이트한다. 이 병합이 없던 이전에는 속성-대입으로만 조립된 설정 객체가 빈 객체로 보여 `url` 키를 못 찾고 **sink 판정 자체가 취소**되는 미탐이 있었다.

**전달 파라미터 추출 (`_extract_data_params`)**: URL 재구성 결과의 쿼리스트링 부분(`_split_url_query`, `?` 이후)과 sink별 데이터 인자(`fetch`의 `opts.body`, `jquery-ajax`/`axios`의 `cfg.data`/`cfg.params`, `axios-short`/`beacon`/`jquery-short`의 위치 인자, `nexacro`의 인자 문자열+in/out Dataset명)를 통합 추출한다. 객체(리터럴 직접/지역변수 간접, 속성-대입 조립 포함, `JSON.stringify(obj)` 언랩 포함)이면 `_merged_object_props`로 키별로 분해하고, 그렇지 않으면 문자열을 쿼리스트링 형식(`a=1&b=2`, 공백 구분 `a=1 b=2`도 지원, `_parse_querystring_params`)으로 재시도하며, 그마저 실패하면 통째로 `"(body)"` 파라미터 하나로 표기한다(값을 버리지 않는 best-effort 정책).

**URL 분기 열거 (`_build_endpoints`/`_enumerate_url_node_variants`/`_reassignment_variants_for_identifier`/`_guard_paths_compatible`)**: URL이 조건부로 여러 값을 가질 수 있으면(레거시 로그인 폼의 `e=base; cond ? e+="a" : e+="b";` 같은 분기별 조립 패턴) 분기당 엔드포인트 레코드를 하나씩 발행한다 — 분기가 없으면(압도적 다수) 기존과 동일하게 정확히 1개만 반환해 하위 호환된다.
- `_enumerate_url_node_variants`는 URL 노드 자체가 `ConditionalExpression`/`LogicalExpression`(`&&`/`||`)/`BinaryExpression`(`+`)/`TemplateLiteral`/`Identifier`이면 재귀적으로 각 조각의 후보를 열거한 뒤, 삼항·논리연산은 양쪽을 합치고 `+`연결·템플릿 리터럴은 조각별 후보의 데카르트 곱(`_cross_join_variants`)을 만든다 — 분기 변수가 `this.contextRoot + n`처럼 URL의 일부에만 묻혀 있어도 값이 유실되지 않는다.
- `Identifier`가 가리키는 지역변수의 실제 재대입 이력은 `_analyze_dataflow`가 선언(`VariableDeclarator`)·재대입(`AssignmentExpression`, `=`/`+=` 모두)마다 프로그램 순서대로 쌓는 `var_events`(변수명 → `{op, right, guards}` 목록, 대입 시점의 `guard_stack` 스냅샷 포함)로 판별한다. `_reassignment_variants_for_identifier`는 이 이벤트들을 순서대로 적용하되, 가드 없는(무조건) 이벤트는 현재 후보 전체에 적용(`+=`는 접미사 결합, `=`는 완전 대체 후 단일화)하고, 가드 있는(조건부) 이벤트는 **자신의 가드 경로와 모순되지 않는 후보에서만** 분기해 새 후보를 추가한다.
- **가드 호환성 판별 (`_guard_paths_compatible`)**: 두 가드 경로가 같은 (cond, line) 지점(if/삼항의 짝, 또는 switch의 같은 `group`=해당 switch 문 라인)에서 kind/cond가 다르면(if vs else, 서로 다른 case) 상호배타적인 형제 분기이므로 모순으로 판정해 값이 교차 결합되지 않게 막는다 — 이 판별이 없으면 삼항 체인의 서로 다른 갈래에서 나온 재대입이 하나의 실행 경로에 잘못 겹쳐 붙는다.
- **완전분기 여부는 증명하지 않는다**: 어느 분기가 실제로 모든 경로를 덮는지(예: `if`에 `else`가 있는지, `switch`에 `default`가 있는지) 확인하지 않는 안전한 근사치다 — 값을 잃는 것보다 여분의 후보("분기 전 값")가 남는 쪽을 택한다. 다만 그 "분기 전 값"이 `/`도 `http(s)://`도 포함하지 않는 경로 형태가 아니면(예: `this.PROP` 해소 실패로 남은 `{PROP}` 플레이스홀더뿐인 경우) 다른 후보가 있는 한 잡음으로 간주해 제거한다.
- 조합 폭발 방지를 위해 호출 1건당 발행 가능한 URL 개수를 `_URL_BRANCH_CAP`(8)으로, 재귀 깊이를 6으로 제한한다(N-hop 파라미터 전파의 `_VARIANT_CAP`과는 별개의, 더 이른 단계의 상한).

**N-hop 파라미터 전파 (`_propagate_endpoint_params` → `_propagate_one` 재귀)**: `called_by` 역인덱스가 확정된 뒤 실행된다. 엔드포인트의 `url`/`params[].value`에 남은 `{paramName}` 플레이스홀더 중 소속 함수(`func_id`)의 `params`와 일치하는 이름을 후보로 모으고, 그 함수를 호출하는 함수들(`called_by`)의 `out_calls` 중 `resolved_ids`에 이 함수가 포함된 호출을 찾아 매개변수 위치(인덱스)로 대응하는 `args[].value`(호출자 자신의 스코프에서 이미 재구성된 문자열)로 치환한다. 치환 결과에 **그 호출자 자신의 매개변수 이름**과 일치하는 플레이스홀더가 남아 있으면(래퍼가 래퍼를 감싼 다단 구조, 예: `http(path)` → `getUser(id){http("/users/"+id)}` → `load(){getUser(cur)}`) 그 호출자의 호출자로 재귀적으로 계속 전개한다(`_propagate_one`). 더 못 가는 갈래(호출자 없음/`_HOP_MAX`(4) 도달/순환/구체화 대상 소진)마다 그 시점까지 구체화된 값을 `variants` 항목(`{from, chain, hops, url, params}`)으로 확정한다 — 부분 구체화도 버리지 않는 best-effort 정책. 순환은 방문 집합(`visited`)으로, 무한 확산은 hop 상한과 엔드포인트당 variant 총량 상한(`_VARIANT_CAP`=300)으로 차단한다. 이 상한은 **최종 `(url, params)` 조합 기준으로 중복을 제거한 뒤**(`seen_keys`, url만으로 잡으면 URL은 정적이고 파라미터만 갈리는 게이트웨이 패턴에서 서로 다른 값이 잘못 병합된다) 세는 "서로 다른 조합 수"라, 이름 매칭 과다연결(`resolution="name"`) 등으로 생기는 동일/유사 조합 노이즈는 자연히 접히고, 하나의 sink(예: `content-url` 프레임워크 로더 하나)에 정당하게 수십~수백 개의 서로 다른 URL이 몰리는 레거시 팝업 게이트웨이 같은 케이스는 상한을 온전히 채운다. `chain`은 원 엔드포인트에서 가까운 호출자부터 먼 호출자 순으로 나열되며(`from`은 `chain[0]`과 동일, 하위 호환용), 호출자 인자가 리터럴이 아니면 치환 결과에도 `{이름}`이 남을 수 있다.

**동적 `<form>` 문자열 조립 탐지 (`_match_dynamic_form_sink`/`_InlineFormParser`)**: `_ScriptCollector`(HTML 파서)는 소스 문서에 실제로 존재하는 정적 `<form action="...">`만 본다. 실무 코드에서는 `$("<form action='"+url+"'>...</form>")`처럼 JS 문자열로 HTML을 조립해 DOM에 붙이고 `.submit()`하는 관용구가 흔한데(결제/SSO 리다이렉트 폼 등), 이 문자열은 HTML 파서 단계에 아예 나타나지 않아(순수 JS 문자열 리터럴) 정적 탐지가 놓친다. `_match_sink_kind`가 실패한 `CallExpression`에 한해(구조적으로 배타) callee가 `$(...)`/`jQuery(...)` 단독 호출(경로 길이 1)인지 확인하고, 그 첫 인자가 문자열 조립 노드(`Literal`/`TemplateLiteral`/문자열 `+`/`Identifier`, `_is_url_shape_source_node`와 동일 제한)면 `_reconstruct_str`로 재구성한 뒤 `<form` 포함 여부로 사전 필터링한다(대다수의 `$("<div>...")` 호출은 파싱 없이 배제). 포함되면 `_InlineFormParser`(stdlib `html.parser` 기반, 완전한 문서가 아닌 문자열 조각에서 첫 `<form>` 하나만 관대하게 추출)로 `action`/`method`/필드(`input`/`select`/`textarea`/`button`의 `name`/`value`)를 뽑아 `kind="form"` 확정 엔드포인트로 즉시 발행한다(정적 form과 동일 취급 — `func_id`가 있으면 다른 kind와 동일하게 N-hop 전파도 자동 적용됨, 정적 form과 달리 `guards`도 채워짐). `action`이 비어있거나 `javascript:` 의사 URL이면 정적 form과 동일 기준으로 제외한다. `.submit()` 호출 여부는 추적하지 않는다 — 문장 간 흐름 추적이 이 모듈의 단일 패스 구조와 맞지 않고, `<form action=...>` 마크업을 문자열로 조립하는 것 자체가 이미 충분히 구체적인 신호라 오탐 위험이 낮다(값을 잃는 것보다 여분의 후보가 남는 쪽을 택하는 기존 정책과 동일).

**기존 DOM 폼 action 변조 + 제출 탐지 (`form_action_refs`)**: 위 두 가지(정적 form/동적 조립 form)는 모두 "폼 마크업을 새로 만드는" 패턴이다. 반면 레거시 코드에는 페이지에 이미 있는 공용 폼(예: `<form id="theForm">`)의 `action`을 여러 문장에 걸쳐 바꿔치기한 뒤 제출하는 관용구가 흔하다:

```js
var oAction = document.forms[0].action;   // 원래 값 백업
document.forms[0].action = pUrl;          // action 변조
document.forms[0].submit();               // 제출 — 이 시점의 pUrl로 나감
document.forms[0].action = oAction;       // 원복
```

`_analyze_dataflow`가 `AssignmentExpression`을 방문하며 좌변 속성명이 `action`인 대입을 만나면(object가 단순 식별자든 `document.forms[0]`처럼 계산 접근이 섞였든 상관없이) 그 object의 원문 텍스트를 키로 `form_action_refs`(변수명 → {속성키: 값}의 `local_props`와 같은 성격의 참조 테이블, 다만 키가 임의 원문 텍스트라는 점이 다름)에 최근 대입 우변을 기록한다. 이후 같은 원문 텍스트를 object로 갖는 `.submit()`/`.fireSubmit()` 호출(Xjos 환경의 `fireSubmit` 관례 포함)을 만나면 기록해둔 값을 URL로 삼아 `kind="form"` 확정 엔드포인트를 즉시 발행한다(다른 kind와 동일하게 `func_id`가 있으면 N-hop 전파도 자동 적용). 같은 함수 안에 선행 `action` 대입이 없으면(참조가 다르거나 아예 없음) 조용히 무시한다 — 근거 없는 URL을 지어내지 않는다. `local_props`/`local_inits`와 동일한 흐름 비민감·함수 스코프 한정 근사치다(같은 원문 텍스트는 같은 참조로 간주하고, 이 함수 밖으로는 전파되지 않는다). 필드(input/select 등) 목록은 마크업이 없어 수집하지 않고, 메서드는 항상 GET으로 근사한다(정적/동적 조립 form처럼 `<form method>` 속성을 읽을 수 없음).

### URL-형태 휴리스틱(candidate_endpoints) 탐지

확정 sink는 이름 패턴(위 sink 매칭 표)에 한정되는데, 프로덕션 minify 번들에서는 `axios.create({baseURL})`로 만든 인스턴스가 `obj["a"].fetch(url)`/`obj.modify(url)`처럼 **computed 접근 뒤에 숨거나 임의의 이름으로** 노출되는 경우가 흔해 이름 패턴만으로는 놓친다(축소 변수명·객체 프로퍼티에 담긴 인스턴스 등). `_match_url_shape_candidate`는 이런 커스텀 HTTP 래퍼를 이름이 아니라 **인자가 URL/경로처럼 생겼는지**만으로 저신뢰 후보로 수집한다.

- **판별 대상**: 확정 sink(`_match_sink_kind`)가 이름 패턴으로 실패하고, 동적 `<form>` 조립(`_match_dynamic_form_sink`, 위 참고)에도 해당하지 않는 `CallExpression`에 한해서만 시도한다(세 판정 모두 같은 호출이 두 목록 이상에 동시에 들어가지 않도록 구조적으로 배타).
- **제외 조건**: callee 말단 이름이 `_URL_SHAPE_EXCLUDE_TAILS`(순수 문자열/배열 빌트인 — `concat`/`split`/`join`/`replace`/`slice`/`substring`/`substr`/`match`/`test`/`startsWith`/`endsWith`/`includes`/`indexOf`/`lastIndexOf`/`push`/`toString`/`trim`/`repeat`, 그리고 모듈 경로를 URL로 오인하는 흔한 원인인 `require`)에 속하면 후보로 보지 않는다.
- **URL-형태 판별 (`_looks_like_url_shape`)**: 절대경로(`/...`)·`http://`·`https://`·프로토콜 상대(`//...`)는 접두사만으로, 그 외에는 `word/word` 형태의 상대경로 세그먼트 구조(`_REL_PATH_SHAPE_RE`, 예: `users/me`)로 판별한다. 공백이 섞이면(문장·설명 텍스트) URL이 아닌 것으로 간주한다. 선행하는 `{name}` 플레이스홀더(레거시 코드의 `var rootURL; rootURL = '/'+...+'/';`처럼 해소하지 못한 전역 베이스경로 등)는 `_normalize_display_path`와 동일한 규칙으로 무시하고 그 뒤 나머지로 형태를 판별한다 — `{rootURL}Pages/.../x.aspx`처럼 베이스경로만 미해소인 경로도 후보로 인정해, 이름 패턴 없는 커스텀 HTTP 래퍼가 전역 베이스경로를 쓴다는 이유만으로 후보에서 누락되지 않게 한다.
- **후보 인자 노드 제한 (`_is_url_shape_source_node`)**: 인자 노드가 `Literal`/`TemplateLiteral`/`Identifier`/문자열 `+` `BinaryExpression`일 때만 URL-형태 검사 대상으로 삼는다 — 그 외 타입(나눗셈 `a/8` 같은 산술식 등)은 `_reconstruct_str`이 원문 슬라이스로 폴백하는데, 그 원문에 우연히 `/`가 섞이면 URL로 오인할 수 있어 애초에 제외한다.
- 인자를 앞에서부터 훑어 첫 URL-형태 인자를 URL로 채택하고, 나머지 인자 중 객체 리터럴이 있으면 `_extract_data_params`로 best-effort 파라미터를 추출한다(`in="body"`).
- 후보 레코드는 `method="?"`(미상)·`kind="heuristic"`으로 고정되며, `endpoints`와 동일한 `guards`(가드 체인)를 갖지만 **파라미터 전파(N-hop)는 적용되지 않는다**(`variants` 필드 자체가 없음).
- 이름 기반이 아니므로 확정 sink보다 오탐 가능성이 높다(예: Vuex `dispatch("User/getProfile")`처럼 경로 형태의 비-HTTP 문자열, 라우터 경로 등) — 참고용 저신뢰 목록일 뿐 확정 판정이 아니다.

---

### 제어흐름 그래프(CFG)·가드 체인

클라이언트 단 인증우회·강제호출 가능 엔드포인트 파악을 위해, 함수별 제어흐름 구조(`cfg`)와 각 호출·엔드포인트가 어떤 조건 하에서만 도달 가능한지(`guards`)를 함께 재구성한다.

**가드 체인 (`_analyze_dataflow`의 `guard_stack`)**: `_analyze_dataflow`가 함수 본문을 순회하는 동일한 재귀에서, 아래 4종 노드에 진입할 때 조건을 `guard_stack`에 push하고 벗어나면 pop한다. `out_calls`/엔드포인트를 기록하는 시점의 스택 스냅샷이 `guards`(`List[{kind, cond, line, auth_hint}]`, 바깥→안쪽 순서)로 남는다.

| kind | 발생 조건 | cond |
|------|-----------|------|
| `if` | `IfStatement`/`ConditionalExpression`(삼항)의 참 분기(consequent) 방문 중 | 조건식 원문 |
| `else` | `IfStatement`/`ConditionalExpression`의 거짓 분기(alternate) 방문 중 | 조건식 원문(부정 의미) |
| `and` | `LogicalExpression`(`&&`)의 우변 방문 중 | 좌변 원문 |
| `or` | `LogicalExpression`(`||`)의 우변 방문 중 | 좌변 원문(부정 의미) |
| `case` | `SwitchCase`의 본문(consequent) 방문 중 | `"{discriminant} === {case.test}"` 또는 `"default"` |

`known`/`defs`/`returns` 수집은 이 4종을 특별 취급하기 전과 동일하게 모든 자식을 방문하므로(흐름 비민감 근사치 유지), 가드 체인 추가가 그 외 분석 결과에 영향을 주지 않는다. `auth_hint`는 `cond` 텍스트에 인증/권한 관련 키워드(`_AUTH_GUARD_KEYWORDS`: `admin`/`auth`/`login`/`logged`/`permission`/`role`/`token`/`session`/`권한`/`관리자`/`로그인`/`인증`)가 대소문자 무관 부분일치하는지의 휴리스틱이다(`_is_auth_guard`) — 오탐·누락 가능한 참고 신호일 뿐 확정 판정이 아니다. HTML `<form>` 엔드포인트는 JS 조건 가드 개념이 없어 `guards`가 항상 빈 목록이다.

**제어흐름 그래프 (`_build_cfg`)**: 함수 인벤토리 구성(`_collect_functions`) 중 `_analyze_dataflow`와 나란히 실행되어(함수 본문 재파싱 없음) 각 함수 레코드의 `cfg`를 채운다. basic-block 정밀도 대신 AST 구조(if/switch/loop/try)를 그대로 결정 노드로 매핑하는 **구조 기반(structural) 근사치**다.

- 연속된 단순 문장(선언/식/return/throw 등)은 하나의 `block` 노드로 묶는다(최대 `_CFG_BLOCK_MAX_LINES`=6줄, 초과분은 `"…(+N)"`으로 축약).
- `if`/`for`/`while`/`do-while`/`for-in`/`for-of`/`switch`는 `decision` 노드(마름모)로 분리하고, 분기별 진입 엣지에 `"true"`/`"false"`/`"loop"`/`"exit"`/`"case ..."`/`"default"` 라벨을 붙인다. `if`에 `else`가 없으면 거짓 분기는 결정 노드에서 다음 흐름으로 직접 이어진다(별도 노드 없이 통과).
- `break`/`continue`는 `terminal` 노드로 명시적으로 만든다 — 분기 본문이 break/continue 하나뿐이어도(`if(x){ continue; }`) "빈 본문"과 혼동되지 않고 가장 가까운 루프의 조건 노드(`continue`)나 루프 이후 지점(`break`)으로 정확히 연결된다. 레이블은 구분하지 않고 항상 가장 가까운 루프/switch를 대상으로 한다.
- `try`는 try 블록 전체에서 예외가 발생할 수 있다고 근사해 `try_entry --exception--> catch_entry` 엣지 하나로 표시한다(문장 단위 정밀 추적 없음). `finally`는 try/catch의 모든 탈출 경로를 재수렴시킨다.
- `switch`의 case는 `break` 없이 끝나면 다음 case로 fallthrough 엣지가 이어진다.
- `LabeledStatement`는 레이블을 무시하고 내부 문장만 처리한다(레이블 자체는 구조에 반영되지 않음).
- `_analyze_dataflow`가 같은 함수에서 찾은 **확정** 엔드포인트(`endpoints`, HTTP sink)의 라인 집합(`sink_lines`)을 받아, 그 라인과 겹치는 문장을 포함한 노드는 `has_sink=true`로 표시한다(sink 판정 로직을 중복 구현하지 않고 엔드포인트 탐지 결과를 유일한 출처로 재사용). `candidate_endpoints`(URL-형태 휴리스틱 후보)는 `sink_lines`에 포함되지 않으므로 CFG 강조에 영향을 주지 않는다 — 저신뢰 후보가 IDA 스타일 그래프의 확정 신호(주황색 강조)를 흐리지 않도록 하기 위함이다.
- 노드 수가 `_CFG_MAX_NODES`(150)에 도달하면 그 이상 노드를 만들지 않고 `truncated=true`를 반환한다(엣지는 만들어지지 않은 노드를 참조하지 않도록 방어적으로 처리).

`cfg` 구조: `{nodes: [{id, kind, label, line, has_sink}], edges: [{from, to, label}], entry, truncated}`. `kind` ∈ `block`/`decision`/`terminal`.

---

### `extract_endpoints(name, data) -> List[Dict[str, Any]]`

```python
name: str    # 합성 파일명(확장자만 의미 있음 — 예: "page.html", "page.js")
data: bytes  # 소스 바이트
```

크롤러(`modules/_crawl.py`)·SQLi/경로순회 입력 포인트 수집(`modules/_sqli_util.py`)이 정규식 대신 AST 기반으로 엔드포인트를 발견하는 데 쓰는 경량 진입점(`modules/_endpoint_extract.py` 경유). 내부적으로 `analyze([(name, data)])`를 그대로 재사용하며, CFG·함수 인벤토리 등 분석 화면 전용 정보는 버리고 `endpoints`만 반환한다. `candidate_endpoints`(저신뢰 URL-형태 휴리스틱)는 포함하지 않는다.

esprima/tree-sitter 미설치·파싱 실패(TS/JSX 등 미지원 문법) 시에도 `analyze()`의 기존 유닛 단위 격리에 의해 예외 없이 빈 리스트를 반환한다 — 호출자는 정규식 결과와 병합(union)해 쓴다. `stop_event`/`progress_cb`를 받지 않는다(크롤 중 페이지 1개 단위의 짧은 호출이라 대용량 배치 분석용 중단 인프라 대상이 아님). 네트워크 요청 없음(`analyze()`와 동일한 하드 룰 승계).

이 함수가 반환한 엔드포인트를 실제 요청 가능한 것만 걸러 절대 URL로 정규화하는 게이트(동일 도메인/로그아웃 경로/미해소 플레이스홀더 판정)는 `modules/_endpoint_extract.py`의 `gate()`가 담당하며, `js_analysis.analyze()`(대시보드 분석 모드) 자체는 이 게이트를 거치지 않는다 — 상세는 `design.md`의 "공통 크롤러" 절과 `modules/sql_injection.md`의 "AST 기반 JS 엔드포인트 보강" 참고.

---

### `search_functions(analysis, name_query="", file_query="", limit=200) -> List[Dict[str, Any]]`

파일명·함수명 부분/대소문자 무관 일치로 함수 후보를 검색한다. 각 결과 항목: `{id, name, file, unit, line, params, calls, called_by_count}` (상세 `defs`/`returns`/`out_calls`/`called_by` 전체 목록은 미포함 — `get_function()`으로 별도 조회).

---

### `get_function(analysis, func_id) -> Optional[Dict[str, Any]]`

함수 id로 상세 레코드(`defs`/`returns`/`out_calls`/`called_by` 전체 포함)를 조회한다. 없으면 `None`.

---

### `list_files_with_functions(analysis) -> List[Dict[str, Any]]`

함수가 하나 이상 있는 파일 목록을 업로드 순서대로 반환한다. 각 항목: `{name, count}`(`count`는 그 파일에 속한 함수 개수). 함수가 하나도 없는 파일(파싱 실패·정적 마크업뿐인 HTML 등)은 제외된다 — "파일 별 분기 흐름" 탭의 파일 선택 목록용. 동일한 파일명이 여러 번 업로드된 경우(`analyze()`는 파일명만으로 함수를 귀속시켜 이미 합산 집계됨) 첫 등장 항목 하나만 남기고 중복 행을 제거한다.

---

### `list_endpoints(analysis, method_query="", url_query="", kind_query="", limit=500) -> List[Dict[str, Any]]`

엔드포인트 목록을 `method`(대소문자 무관 완전일치)·`url`(부분/대소문자 무관 일치)·`kind`(완전일치) 조건으로 필터링해 반환한다. 각 결과 항목은 `analyze()`의 `endpoints` 레코드 전체(위 표 참고)이며 별도 요약본을 만들지 않는다.

---

### `list_candidate_endpoints(analysis, url_query="", limit=500) -> List[Dict[str, Any]]`

URL-형태 휴리스틱 후보 목록을 `url`(부분/대소문자 무관 일치)로 필터링해 반환한다. `method`/`kind`는 항상 고정값(`"?"`/`"heuristic"`)이라 그 기준의 필터는 두지 않는다. 각 결과 항목은 `analyze()`의 `candidate_endpoints` 레코드 전체(위 표 참고).

---

### `to_mermaid_call_graph(analysis, center_id=None, max_nodes=120, depth=1, cross_file_only=False) -> str`

`graph LR` mermaid 소스를 생성한다. 호출 대상 탐색은 이름 매칭이 아닌 `out_calls[].resolved_ids`(파일 간 해소 결과)를 기준으로 한다.

- `center_id` 미지정: 전체 함수 중 앞에서부터 `max_nodes`개만 노드로 사용
- `center_id` 지정: 해당 함수를 시작점으로 `resolved_ids`/`called_by`를 따라 `depth`홉(1~5, 기본 1)까지 BFS 확장한 서브그래프. 확장된 함수 집합이 `max_nodes`를 넘으면 `center_id`를 항상 우선 포함하고 나머지는 id 정렬로 결정적으로 채운다(과거엔 집합이 Python set이라 슬라이싱 순서가 비결정적이었고 center_id 자신이 잘려나가는 결함이 있었음 — 실제 대형 번들 재현 시 샘플 200개 중 다수에서 발생 확인 후 수정). 중심 노드는 `fill:#f96` 강조 스타일 적용. `depth=1`(기본값)은 기존 1-hop 서브그래프와 동일한 결과
- `cross_file_only=True`: 같은 파일 내부 호출 엣지(화살표)는 그리지 않고 파일 경계를 넘는 엣지만 표시. 노드 자체는 그대로 유지되며 엣지만 필터링됨

노드 라벨은 `이름 (파일명)` 형식이며 `_mmd_escape()`로 이스케이프(따옴표 제거·개행 제거·50자 제한) 후 삽입한다.

---

### `to_mermaid_dataflow(func, analysis=None, expand=False, max_nodes=80) -> str`

함수 레코드 하나(`get_function()` 반환값)의 내부 데이터플로우를 `graph LR` mermaid 소스로 생성한다. 좌→우 흐름: param 노드(둥근 모양) → 지역변수 정의 노드(사각) → return/외부호출 노드(알약 모양). 각 노드는 `depends_on`에 나열된 선행 노드로부터 화살표를 받는다.

`expand=True`이고 `analysis`가 주어지면, `out_calls` 중 `resolved_ids`가 정확히 하나의 함수로 해소된 호출에 한해 그 대상 함수의 데이터플로우를 재귀적으로 인라인 전개한다(인자는 위치 기준으로 대상 함수의 `params`에 바인딩). 순환 호출은 방문 중(`visiting`) 집합으로 차단하고, 노드 수가 `max_nodes`에 도달하면 그 이상 확장하지 않는다. `expand=False`(기본값)는 기존과 동일하게 확장 없는 단일 함수 데이터플로우만 그린다.

---

### `to_mermaid_cfg(func) -> str`

함수 레코드 하나(`get_function()` 반환값)의 `cfg`(제어흐름 그래프)를 `graph TD` mermaid 소스로 생성한다. `decision` 노드는 마름모, `block`/`terminal` 노드는 사각형으로 그린다. `has_sink=true`인 노드는 `style ... fill:#f96`으로 강조해 IDA 스타일로 "이 HTTP 요청(엔드포인트)에 도달하려면 어떤 분기 조건을 거쳐야 하는지"를 한눈에 보여준다(강제호출 가능 엔드포인트 파악용). 여러 문장을 묶은 block 노드는 `<br/>`로 줄바꿈해 표시한다. `cfg`가 비어 있으면(빈 함수 본문) 플레이스홀더 노드 하나만 있는 그래프를 반환한다. `truncated=true`면 노드 상한 도달을 알리는 노드를 마지막에 덧붙인다.

엣지 라벨(`decision`의 분기 조건 텍스트 등)은 소스 코드 원문이 그대로 들어가므로 `_mmd_edge()`로 항상 인용부호(`-->|"..."|`)로 감싸 생성한다 — 괄호/중괄호/대괄호/파이프/따옴표가 섞인 라벨(예: `switch` case의 문자열 리터럴)이 인용부호 없이 들어가면 mermaid 파서가 깨지기 때문이다(실측 확인). 라벨이 없으면(또는 이스케이프 후 빈 문자열이면) 라벨 없는 엣지(`-->`)로 그린다.

---

### `to_mermaid_file_cfg(analysis, file_name, page=0) -> Dict[str, Any]`

파일 하나에 속한 함수의 `cfg`를 함수별 `subgraph`로 묶어 `graph TD` mermaid 소스로 생성한다 — IDA 스타일 분기 그래프의 파일 전체 버전으로, 함수 하나가 아니라 파일 안 함수들의 분기 흐름을 한 그래프에서 조망한다. 반환값은 문자열이 아닌 `{mermaid, page, page_size, total_functions, total_pages}` dict.

- 파일에 속한 함수를 라인 순으로 정렬한 뒤 `_FILE_CFG_PAGE_SIZE`(80)개씩 페이지로 나누고, `page`(0-based, 기본 0. 범위를 벗어나면 가장 가까운 유효 페이지로 고정)번째 페이지에 속한 함수만 그린다. 함수마다 자신의 `cfg`(재파싱 없이 기존 값 재사용)를 `to_mermaid_cfg`와 동일한 규칙(decision=마름모, `has_sink`=주황 강조)으로 subgraph 안에 그린다.
- 같은 페이지 내 함수 호출(`out_calls[].resolved_ids` 중 이 페이지에 포함된 대상)은 호출자 함수의 entry 노드 → 피호출 함수의 entry 노드로 점선 화살표(`-.->`)를 그어 함수 흐름을 나타낸다(호출부의 정확한 CFG 노드가 아닌 함수 진입점 기준 근사 — 설계 합의). 파일 경계를 넘는 호출·같은 함수 재귀 호출·다른 페이지에 있는 함수로의 호출은 그리지 않는다(그 페이지에 없는 노드를 참조할 수 없음).
- mermaid 소스 맨 앞에 `_MERMAID_ELK_INIT` 지시문(`%%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%`)을 붙여 레이아웃 엔진을 mermaid 기본값인 dagre 대신 ELK로 지정한다. subgraph(클러스터) 수가 많은 그래프에서 dagre가 "Cannot set properties of undefined (setting 'order')"로 깨지는 것을 실제 프로덕션 minify 번들 2종(함수 수백~수천 개)으로 재현했고, 우리 쪽 생성 결과에는 결함이 없음을 확인(미선언 노드 참조 없음)한 뒤 ELK로 전환해 해당 번들 전체 페이지가 정상 렌더됨을 재검증했다(상세는 design.md §8-6). subgraph를 쓰는 유일한 그래프인 이 함수에만 적용 — 다른 그래프는 클러스터가 없어 dagre로도 문제가 없다.
- **페이지 크기(80)의 근거**: 사람이 한 화면에서 식별 가능한 함수 수 기준의 가독성 상한이다. 이전 버전은 "파일 전체 노드 총량 예산(400) 소진 시 이후 함수 생략(break)" 방식이었으나 앞쪽 큰 함수 하나가 예산을 다 쓰면 뒤쪽 작은 함수들이 전부 생략되는 결함이 있어, 함수 개수 기준 고정 페이지네이션으로 대체했다(모든 함수가 어느 한 페이지에는 반드시 나타남).
- 이 파일에 함수가 없으면 `total_functions=0`·`total_pages=0`이고 `mermaid`는 플레이스홀더 노드 하나만 있는 그래프.
- 노드 id 규칙: 함수 묶음은 `ff{페이지내순번}_sg`, 그 함수의 CFG 노드는 `ff{페이지내순번}_{노드순번}`(접두사는 전체 순번이 아니라 **페이지 안 순번** 기준). 정렬·페이지 분할·라벨 생성은 공유 헬퍼(`_file_cfg_sorted_funcs` / `_file_cfg_prefix` / `_file_cfg_sub_label`)에만 정의돼 있고, `find_file_cfg_functions`가 같은 헬퍼를 써서 위치를 역조회한다 — 한쪽만 바뀌면 "검색은 되는데 엉뚱한 곳으로 이동"하는 조용한 결함이 되므로 규칙을 반드시 이 헬퍼들에서만 변경할 것.

---

### `find_file_cfg_functions(analysis, file_name, name_query="", limit=100) -> Dict[str, Any]`

파일 별 분기 흐름 그래프에서 함수를 찾아 **"몇 페이지의 어느 노드인지"**를 반환한다. 함수가 많은 파일은 그래프가 페이지로 나뉘고 원본 크기도 수만 px에 달해 눈으로 특정 함수를 찾기 어렵기 때문에, 대시보드가 이 응답으로 해당 페이지를 그린 뒤 그 함수 위치로 스크롤·강조하는 데 쓴다.

- `name_query`는 함수명 부분/대소문자 무관 일치(빈 값이면 그 파일의 전체 함수 목록, `limit`개까지).
- 반환: `{results, limit, page_size, total_functions, total_pages}`. `results` 각 항목:

| 필드 | 의미 |
|------|------|
| `id` / `name` / `line` | 함수 식별 정보 (라인 오름차순) |
| `page` | 그 함수가 그려지는 페이지(0-based) |
| `sg_id` | 그래프 안 함수 묶음(subgraph) id (`ff{페이지내순번}_sg`). 그려지지 않는 함수면 `None` |
| `entry_id` | 함수 진입 노드 id — 함수 묶음 테두리 없이 평면으로 렌더된 폴백 화면에서 위치를 찾기 위한 대비책 |
| `label` | 묶음 라벨 텍스트(`함수명 (:라인)`) — id로 못 찾을 때 라벨 텍스트로 찾기 위한 폴백용 |
| `drawn` | CFG 노드가 하나도 없어(빈 본문) 그래프에 그려지지 않는 함수면 `False` |

- `to_mermaid_file_cfg`와 **동일한 공유 헬퍼**(`_file_cfg_sorted_funcs` / `_file_cfg_prefix` / `_file_cfg_sub_label`)로 정렬·페이지·id·라벨을 계산하므로 그래프와 검색 결과가 구조적으로 어긋날 수 없다(회귀 테스트가 "보고한 페이지의 그래프에 그 sg_id·라벨이 실제로 존재하는지"를 직접 검증한다).
- 없는 파일명을 주면 `results=[]`·`total_functions=0`(오류가 아님).

---

### `to_mermaid_module_graph(analysis, max_nodes=120) -> str`

`analyze()`가 구성한 파일 간 의존 관계(`modules.edges`)를 파일 단위 `graph LR` mermaid 소스로 생성한다. 노드는 업로드된 파일(최대 `max_nodes`개), 엣지는 `-->|kind|` 형식으로 관계 종류(`import`/`require`/`include`/`script`)를 라벨에 표시한다. 동일한 `(from, to, kind)` 조합은 한 번만 그린다.

---

## 알고리즘 상세

### 함수 인벤토리 (`_collect_functions`) — 유닛 하나를 재귀 순회

```
visit(node, hint=None, class_ctx=None):
    함수 노드(선언식/표현식/화살표) 발견 시:
        name = 명시적 id.name ?: hint ?: "<anonymous#N>"
        full_name = class_ctx가 있고 익명이면 "class_ctx.name", 아니면 name
        params/body를 _analyze_dataflow()에 위임 → defs/returns/out_calls 획득
        함수 레코드 생성 후 인벤토리에 추가
        본문/매개변수 기본값 내부도 재귀 (중첩 함수 계속 탐색)
    VariableDeclarator(const login = function(){}):
        hint = 변수명으로 init을 재귀 방문 → 이름 없는 함수가 변수명을 이름으로 획득
    AssignmentExpression(obj.x = function(){} / this.x = ...):
        hint = 좌변 프로퍼티명으로 우변을 재귀 방문
    ClassDeclaration/Expression: class_ctx = 클래스명으로 본문 방문
    MethodDefinition: hint = 메서드 키 이름으로 값(함수) 방문
    Property({ key: function(){} }): hint = 키 이름으로 값 방문
    그 외 노드: 모든 자식 필드를 재귀 방문 (hint/class_ctx는 전파하지 않음)
```

### 함수 내부 데이터플로우 (`_analyze_dataflow`) — 함수 본문 하나를 스캔

```
known = set(params)   # 파라미터 + 지역변수 누적 집합

visit(node):
    함수 노드(중첩 함수): 경계로 삼아 내려가지 않음 (별도 인벤토리 항목이 됨)
    CallExpression: out_calls에 1회만 기록(callee 이름 + 인자별 depends_on) 후
                    인자·callee 내부도 재귀 방문 (f(g(x)) 같은 중첩 호출 지원)
    VariableDeclarator(let x = expr): init에서 depends_on 수집 → defs에 기록,
                    선언 즉시 known에 등록(이후 문장에서 참조 가능하게)
    AssignmentExpression(x = expr, 단순 식별자 좌변만): defs에 기록 + known 등록
    ReturnStatement: argument에서 depends_on 수집 → returns에 기록
    그 외: 모든 자식 필드 재귀 방문

_collect_used(expr, known, out): 식별자 사용 수집 헬퍼
    - Identifier: known에 속하면 out에 추가
    - MemberExpression: obj는 항상 재귀, obj[expr] computed 접근만 property도 재귀
      (obj.prop의 prop은 리터럴 이름이라 변수 의존성 아님)
    - 중첩 함수 경계는 넘지 않음 (클로저 캡처 변수는 추적 대상 밖)
```

화살표 함수의 축약형 본문(`x => expr`)은 암묵적 `return`과 동일하게 취급되어 `returns`에 1건 기록된다.

### 파일 어댑터

| 확장자 | 어댑터 | 유닛 분리 기준 |
|--------|--------|----------------|
| `.js` | 없음(전체가 1유닛) | 파일 전체 = 단일 스크립트 |
| `.axd` | 없음(`.js`와 동일 처리) | ASP.NET WebResource/ScriptResource 핸들러 출력 — 확장자만 다를 뿐 내용은 순수 JS. 파일 전체 = 단일 스크립트 |
| `.html`/`.htm` | `_ScriptCollector`(stdlib `html.parser` 서브클래스, 관대한 파싱) | `<script>` 블록마다 1유닛 + 인라인 이벤트 핸들러 속성(`HTML_EVENT_ATTRS` 화이트리스트 44종)마다 1유닛. `<form action>`은 유닛이 아니라 `endpoints`(kind=`form`)로 직접 수집(하위 `input`/`select`/`textarea`/`button`의 `name`/`value` 속성을 파라미터로 포함) |
| `.xfdl`/`.xadl`/`.xml` | `xml.etree.ElementTree`(`_extract_from_xml`) | 네임스페이스 무관 `<Script>` 엘리먼트(CDATA 존재)마다 1유닛, id/name 없으면 `#N` 순번 |
| `.xjs` | `_extract_from_xml` 우선 시도 → `ET.ParseError`(XML 아님) 시 전체를 JS 1유닛으로 폴백 | Nexacro `<Script>` 루트 XML이면 위 규칙과 동일, 순수 JS 저장본이면 `.js`와 동일(전체 = 단일 스크립트) |

인코딩은 `_decode_bytes()`로 `utf-8-sig → utf-8 → cp949` 순 폴백, 모두 실패 시 손실 허용 디코딩(`errors="replace"`).

### 엣지 케이스 처리

| 상황 | 처리 |
|------|------|
| 미지원 확장자 | `files[].kind="unsupported"`, `parse_errors`에 안내 메시지, 분석 스킵(배치 중단 없음) |
| 유닛 파싱 실패 (TypeScript 타입 주석·JSX·데코레이터 등 esprima·tree-sitter 모두 지원 밖인 문법) | 해당 유닛만 `parse_errors`에 기록하고 스킵. `.js`는 파일 전체가 1유닛이라 파일 전체가 스킵됨 |
| classic script 파싱 실패 | `esprima.parseModule()`(ES module, import/export)로 재시도 → 그것도 실패하면 tree-sitter-javascript(ES2020+, 옵셔널 체이닝 `?.`/nullish `??`/클래스 필드·private 필드/static 블록 등) 3차 재시도(`_try_parse`, `_js_ts_adapter`) |
| 파싱 이후 분석 4단계(모듈 의존관계·axios 인스턴스·함수 인벤토리·모듈 최상위 스캔) 실패 | 유닛 파싱 실패와 동일하게 해당 유닛만 `parse_errors`에 "분석 실패"로 기록하고 스킵, 다른 유닛/파일은 계속 처리(배치 중단 없음) |
| 극단적으로 깊게 중첩된 코드(난독화·제어흐름 평탄화·기계생성 등)로 인한 `RecursionError` | `analyze()` 진입 시 재귀 한계를 `_RECURSION_LIMIT`(5000)로 상향(이전 값이 더 크면 유지, 동시 분석 job에 안전)하고 app.py의 백그라운드 job 스레드는 OS 스택도 64MB로 함께 키워 실제로 그 깊이를 감당하게 한다. 그래도 넘으면 위 행과 동일하게 해당 유닛만 스킵 |
| 이름 없는 함수 표현식 | 대입 위치(변수/속성/this.x/클래스 메서드)에서 이름 힌트 추출, 그마저 없으면 `<anonymous#N>` |
| 계산된 속성 접근/키 (`obj[expr]`, `{[expr]: ...}`) | 이름 추적 불가 → `"<computed>"` |
| 동일 이름 다중 정의 | import/require/include로 해소되지 않는 호출은 이름 매칭 폴백(`resolution="name"`)으로 모두 후보 연결(과다 연결 가능) |
| 동일 베이스네임 파일 다중 업로드 | import/require/include 지정자를 베이스네임으로 매칭할 대상을 특정할 수 없어 미해소 처리(`modules.unresolved`에 `reason="ambiguous"`로 기록) |
| AMD/RequireJS 로더 플러그인 지정자 (`require("i18n!nls/commons")`, `text!template.html` 등 `"!"` 포함) | 파일 경로가 아니라 플러그인 호출이므로 베이스네임 매칭을 시도하지 않고 완전 제외 — 의존 엣지·미해소 참조(`modules.unresolved`) 어느 쪽에도 기록되지 않음 |
| 깨진 HTML | `html.parser`가 관대하게 처리, `feed()` 예외 발생 시점까지 수집된 유닛은 그대로 반환 |
| XFDL/XADL/XML XML 자체가 깨짐(`ET.ParseError`) | 원본 파싱 실패 시에만 금지 제어문자(0x00~0x1F 중 tab/LF/CR 제외)를 공백으로 치환 후 재시도(`_strip_illegal_xml_bytes`). 그래도 실패하면 파일 단위로 `parse_errors`에 기록, 다른 파일은 계속 처리. UTF-16 등 원본이 정상 파싱되는 인코딩에는 스크럽이 적용되지 않음(1차 시도에서 이미 성공) |
| `.xjs`가 순수 JS로 저장된 경우 | XML 파싱(`ET.ParseError`) 실패를 감지해 파일 전체를 JS 1유닛으로 폴백(별도 에러 기록 없음) |
| xscript(투비소프트 Nexacro) 확장 문법 — `include "...";` 지시문, 매개변수 타입 어노테이션(`obj:Form`), `<>` 부등호 연산자 | esprima 원본 파싱 실패 시에만 3종을 길이 보존 방식(공백/동일 길이 치환)으로 무력화 후 재시도(`_sanitize_xscript`, 그 뒤 백엔드 체인 재적용). 표준 JS는 1차 파싱에서 성공하므로 영향 없음. `include` 지시문은 별도로 `_extract_includes()`가 정규식 추출해 `modules.edges`(kind=`include`)로 연결 |
| 옵셔널 체이닝(`?.`) — tree-sitter 백엔드로 파싱된 경우 | 일반 멤버/호출 접근과 동일하게 근사(`ChainExpression` 래핑·`.optional` 플래그 없음) — null-safety 자체가 애초에 추적 대상 밖이라 esprima 백엔드와 분석 결과 동일 |
| 외부(http/https) `<script src="...">` | fetch하지 않고 `external_refs`에 URL만 기록. 업로드된 파일명과 베이스네임이 일치하는 상대경로 `<script src>`는 `modules.edges`(kind=`script`)로 연결되어 같은 스코프로 취급됨 |
| 클로저로 캡처된 외부 스코프 변수 | `_collect_used`가 중첩 함수 경계를 넘지 않으므로 추적 대상 밖(알려진 한계) |
| `window.open(url)`/`dialog.open()` 등 `.open()` 오탐 | `xhr` sink는 arg0가 실제 HTTP 메서드 리터럴(`_HTTP_METHODS`)일 때만 성립 — 아니면 sink 판정 자체를 취소 |
| 빈 `<form action>`·`javascript:` 의사 URL | 현재 페이지로 제출(대상 불명)이거나 JS가 직접 처리하므로 엔드포인트로 수집하지 않음 |
| 엔드포인트 URL/파라미터 값에 객체 리터럴처럼 원문에 중괄호가 포함된 표현식 | `{이름}`(함수 파라미터/해소 불가 식별자) 형태와만 중괄호를 쓰고, 그 외 복잡한 표현식은 원문 슬라이스를 그대로 표기해 이중 래핑(`{{...}}`)을 방지 |
| `baseURL` 없는 `.create()` 호출(axios 아닌 다른 라이브러리) | 인스턴스로 등록하지 않음 — `baseURL` 키 존재 여부로만 판별해 오탐 방지 |
| axios 인스턴스명이 함수 파라미터/지역변수로 가려짐(shadowing) | 그 스코프에서는 인스턴스로 취급하지 않아 sink 판정 자체를 취소(오탐 방지) |
| axios 인스턴스에 넘긴 URL 인자가 이미 절대/프로토콜 상대 URL | `_join_url`이 baseURL을 무시하고 인자 그대로 사용(axios/브라우저 실제 동작과 동일) |
| axios 인스턴스 정의와 사용이 서로 다른 업로드 파일에 걸침(크로스파일) | 인스턴스 테이블은 유닛(파일) 단위로만 유효 — 대응하지 않고 일반 식별자로 취급(`{이름}` 플레이스홀더) |
| 멤버 대상 복합대입으로 설정 객체 속성을 조립(`obj.key += value`) | `local_props`는 `=`(완전 대입)만 인식한다 — `+=`로만 채워진 속성은 추적 대상 밖(알려진 한계) |
| 서로 무관한 클래스/객체가 같은 이름의 `this.PROP`를 가짐 | `_collect_this_props`가 유닛 전체에서 이름만으로 수집해 하나로 합침(어느 클래스 소속인지 구분하지 않음, axios_instances와 동일한 흐름 비민감 트레이드오프) |
| URL 분기(if-without-else/switch-without-default)가 모든 경로를 덮는지 불확실 | 완전분기를 증명하지 않고 "분기 전 값"도 함께 남긴다(미탐 방지 우선) — 그 값 자체가 경로 형태(`/` 포함)면 과다탐지로 남을 수 있음(알려진 한계, 값 손실보다 안전한 방향) |
| 한 호출에서 열거된 URL 분기 수가 `_URL_BRANCH_CAP`(8) 초과 | 그 이상 조합하지 않고 그 시점까지 열거된 것만 반환(조합 폭발 방지, 부분 열거도 버리지 않는 best-effort) |
| 분기 본문이 `break`/`continue` 하나뿐(`if(x){ continue; }`) | `break`/`continue`를 명시적 `terminal` 노드로 만들어 "빈 본문"과 혼동되지 않고 루프 조건 노드/루프 이후 지점으로 정확히 연결(회귀 방지 — 노드를 만들지 않으면 마치 그냥 통과하는 것처럼 잘못 그려짐) |
| 레이블 붙은 break/continue(`outer: for(...){ break outer; }`) | 레이블은 무시하고 항상 가장 가까운 루프/switch를 대상으로 함(레이블이 바깥쪽 루프를 가리키면 잘못 연결될 수 있음, 알려진 한계) |
| CFG 노드 수가 `_CFG_MAX_NODES`(150) 초과 | 그 이상 노드를 만들지 않고 `truncated=true` 반환. 이미 만들어진 노드까지는 정상 연결되며, 만들어지지 않은 노드를 가리키는 엣지는 생성하지 않음(방어적 처리) |
| 파일 단위 CFG(`to_mermaid_file_cfg`) 대상 파일의 함수 수가 `_FILE_CFG_PAGE_SIZE`(80) 초과 | 함수를 라인 순 정렬 후 80개씩 페이지로 나눔 — 생략 없이 `page` 파라미터로 다음 페이지 조회(범위 밖 페이지 요청은 가장 가까운 유효 페이지로 고정) |
| `auth_hint` 키워드에 없는 방식으로 표현된 인증 검사(예: 난독화된 변수명) | 휴리스틱이 놓침(누락) — `guards` 자체(조건 텍스트)는 여전히 기록되므로 사람이 직접 확인 가능 |
| N-hop 파라미터 전파가 `_HOP_MAX`(4)에 도달하거나 순환 호출을 만남 | 그 이상 전개하지 않고 그 시점까지 구체화된 값을 `variants`에 확정(부분 구체화도 버리지 않음). 순환은 방문 집합(`visited`)으로 재방문을 차단 |
| 엔드포인트 하나당 N-hop 서로 다른 `(url, params)` 조합 수가 `_VARIANT_CAP`(300) 초과 | 그 이상 생성하지 않고 이미 확정된 variants까지만 반환(dedup 후에도 남는 호출 그래프 광범위 확산으로 인한 과다 생성 방지) |
| `window.open`/`location.href` 등 화면 내비게이션 sink가 라이브러리·프레임워크 코드(예: 페이지 전환 플러그인의 ctrl-클릭 새 탭 열기)에서도 함께 잡힘 | 이름 기반 확정 sink라 오탐은 아니지만(실제로 그 코드가 그 URL을 여는 것은 맞음) 분석 대상 코드가 아닌 라이브러리 내부 호출까지 공격표면 목록에 섞여 들어갈 수 있다 — `kind`로 필터링해 구분(알려진 한계, 값 손실보다 여분의 후보가 남는 쪽을 택하는 기존 정책과 동일) |
| `<formRef>.action=url; ...; <formRef>.submit()` 폼 변조가 서로 다른 함수(또는 이벤트 핸들러)에 걸쳐 나뉨 | `form_action_refs`는 함수 스코프 한정(단일 패스 구조의 근사치) — 같은 함수 안에서 action 대입과 submit이 모두 일어나야 탐지되며, 함수 경계를 넘는 조립은 놓친다(알려진 한계) |
| URL-형태 휴리스틱 인자가 나눗셈(`a/8`) 등 슬래시가 우연히 섞인 산술식 | `_is_url_shape_source_node`가 `Literal`/`TemplateLiteral`/`Identifier`/문자열 `+` 연결만 검사 대상으로 삼아 원문 슬라이스 폴백에서 오는 오탐을 차단 |
| URL-형태 휴리스틱이 HTTP가 아닌 경로형 문자열(Vuex `dispatch("User/getProfile")`, 라우터 경로 등)을 후보로 수집 | 이름이 아닌 URL 형태만으로 판별하는 저신뢰 후보 목록(`candidate_endpoints`)의 알려진 한계 — 참고용일 뿐 확정 판정이 아님 |

전역 호출 그래프 한계, 데이터플로우 흐름 비민감성, XFDL/XADL/XJS/XML 블록 상대 라인 번호, 엔드포인트 탐지 sink 범위·URL-형태 휴리스틱 오탐 가능성·N-hop 전파 한계, CFG 구조 기반 근사치·가드 체인 추적 범위(4종)·`auth_hint` 휴리스틱 등 설계 단계에서 합의된 근사치 분석 범위는 [design.md](../design.md) §8-3·§8-6 참고.

---

## 의존성

| 패키지 | 용도 | 설치 방법 |
|--------|------|-----------|
| `esprima` | ES2017 이하 JS 파싱 (ESTree 호환 AST, 1차 백엔드) | `_ensure_jsanalysis_deps()` lazy 설치 (순수 파이썬, import명·pip 패키지명 동일) |
| `tree-sitter` + `tree-sitter-javascript` | ES2020+ JS 파싱 (2차 백엔드, esprima 실패 시에만 진입) | `_ensure_jsanalysis_deps()` lazy 설치 (네이티브 바이너리, import명은 밑줄(`tree_sitter`/`tree_sitter_javascript`) · pip 패키지명은 하이픈). `modules/_js_ts_adapter.py`가 esprima와 동일한 ESTree 노드 모양으로 변환 |
| `html.parser` (stdlib) | HTML `<script>`/인라인 이벤트 핸들러 추출 | 추가 설치 불필요 |
| `xml.etree.ElementTree` (stdlib) | XFDL/XADL/XJS/XML `<Script>` CDATA 추출 | 추가 설치 불필요 |
