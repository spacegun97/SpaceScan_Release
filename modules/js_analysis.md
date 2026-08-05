# js_analysis.py — JS/HTML/XFDL/XADL/XJS/XML 데이터플로우 분석 모듈

## 개요

업로드된 `.js`/`.html`(`.htm`)/`.xfdl`/`.xadl`/`.xjs`/`.xml` 소스에서 함수를 찾아내고, 함수별 내부 데이터플로우(파라미터→지역변수→반환/외부호출)와 함수 간 호출 관계(호출 그래프)를 esprima 기반 정적 분석으로 재구성한다.

탐지 모듈(`scan()` 인터페이스)·SQLi 추출·엑셀 취합·OSINT 정찰과 무관한 **별도 모드 유틸**이다.

**하드 룰: 이 모듈은 어떤 외부 호스트로도 요청을 보내지 않는다.** 업로드된 바이트만 읽어 esprima(순수 파이썬 JS 파서)로 파싱하며, HTML의 `<script src="...">` 외부 참조는 URL 문자열만 기록하고 절대 fetch하지 않는다.

---

## 공개 함수

### `analyze(sources) -> Dict[str, Any]`

```python
sources: List[Tuple[str, bytes]]  # [(파일명, 바이트스트림), ...]
```

파일별 소스 추출 → 유닛별 esprima 파싱 → 함수 인벤토리 구성 → 파일 간 모듈 의존 관계(import/require/include/script src) 구성 → 전역 호출 그래프(called_by 역인덱스) 구성까지 한 번에 수행한다.

반환 dict:

| 키 | 타입 | 설명 |
|----|------|------|
| `files` | `List[dict]` | 파일별 처리 통계 |
| `functions` | `List[dict]` | 전체 함수 인벤토리 (파일 간 import/require/include/script src로 우선 연결, 실패 시 이름 매칭 폴백) |
| `modules` | `dict` | 파일 간 의존 관계 `{edges: [...], unresolved: [...]}` |

`files` 항목 구조:

| 키 | 설명 |
|----|------|
| `name` | 파일명 |
| `kind` | 확장자(`.js`/`.html`/`.htm`/`.xfdl`/`.xadl`/`.xjs`/`.xml`) 또는 `"unsupported"` |
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
| `out_calls` | 외부 호출 목록 — `{callee, args, line, expr, resolved_ids, resolution}`. `args` 항목은 `{kind:"function_literal"}` 또는 `{kind:"expr", depends_on}`. `resolved_ids`는 해소된 대상 함수 `id` 목록, `resolution`은 해소 등급(`import`/`require`/`local`/`include`/`name`/`unresolved`) — 상세는 "파일 간 호출 해소" 참고 |
| `calls` | `out_calls`의 callee 이름 집합 (정렬됨) |
| `called_by` | 이 함수를 호출하는 함수의 `id` 목록 (`resolved_ids` 기반 역인덱스로 채워짐) |

`modules` 구조:

| 키 | 설명 |
|----|------|
| `edges` | 해소된 파일 간 의존 관계 목록 — `{from, to, kind, specifier}`. `kind` ∈ `import`(ESM)/`require`(CommonJS)/`include`(Nexacro `include`)/`script`(HTML `<script src>`) |
| `unresolved` | 미해소 참조 목록 — `{from, specifier, kind, reason}`. `reason`은 `"missing"`(대상 파일 없음) 또는 `"ambiguous"`(동일 베이스네임 다중 업로드) |

### 파일 간 호출 해소 (`_resolve_call_targets`)

`out_calls`의 각 호출은 아래 순서로 해소를 시도하고, 성공한 첫 단계의 등급이 `resolution`에 기록된다.

1. **`import`/`require`** — `obj.foo()` 형태에서 `obj`가 namespace import(`import * as obj`)나 `require()` 바인딩(`const obj = require(...)`)이면 해당 모듈 파일에서 `foo`를 조회
2. **`local`** — 같은 파일 내에서 이름이 일치하는 함수
3. **`include`** — Nexacro `include`로 연결되거나 HTML에서 같은 `<script src>` 셋에 속한 파일들 중 이름이 일치하는 함수 (include와 script-src 모두 "전역 스코프 공유"라는 동일 의미로 `"include"` 라벨을 공유)
4. **`name`** — 위 단계가 모두 실패하면 전체 함수 중 이름이 일치하는 모든 후보로 연결(폴백, 과다 연결 가능)
5. 모두 실패하면 `resolution="unresolved"`, `resolved_ids=[]`

경로형 지정자(`import`/`require`/`include`의 파일 경로)는 실제 상대경로가 아닌 **베이스네임만으로** 업로드된 파일명 집합과 매칭한다(`_normalize_specifier`) — 브라우저 파일 업로드가 폴더 구조를 보존하지 않기 때문. 동일 베이스네임이 여러 개 업로드되면 대상을 특정할 수 없어 미해소(`reason="ambiguous"`) 처리된다. `export ... from` 재export 체인은 `(file, name)` 방문 집합으로 순환을 방지하며 원본 정의까지 추적한다(`_resolve_export_chain`).

단일 파일만 업로드된 경우 import/require/include 관계가 존재하지 않으므로 항상 `local` 또는 `name` 단계로 귀결되어, 이 기능 추가 이전과 동일한 결과를 낸다.

---

### `search_functions(analysis, name_query="", file_query="", limit=200) -> List[Dict[str, Any]]`

파일명·함수명 부분/대소문자 무관 일치로 함수 후보를 검색한다. 각 결과 항목: `{id, name, file, unit, line, params, calls, called_by_count}` (상세 `defs`/`returns`/`out_calls`/`called_by` 전체 목록은 미포함 — `get_function()`으로 별도 조회).

---

### `get_function(analysis, func_id) -> Optional[Dict[str, Any]]`

함수 id로 상세 레코드(`defs`/`returns`/`out_calls`/`called_by` 전체 포함)를 조회한다. 없으면 `None`.

---

### `to_mermaid_call_graph(analysis, center_id=None, max_nodes=120, depth=1, cross_file_only=False) -> str`

`graph LR` mermaid 소스를 생성한다. 호출 대상 탐색은 이름 매칭이 아닌 `out_calls[].resolved_ids`(파일 간 해소 결과)를 기준으로 한다.

- `center_id` 미지정: 전체 함수 중 앞에서부터 `max_nodes`개만 노드로 사용
- `center_id` 지정: 해당 함수를 시작점으로 `resolved_ids`/`called_by`를 따라 `depth`홉(1~5, 기본 1)까지 BFS 확장한 서브그래프. 중심 노드는 `fill:#f96` 강조 스타일 적용. `depth=1`(기본값)은 기존 1-hop 서브그래프와 동일한 결과
- `cross_file_only=True`: 같은 파일 내부 호출 엣지(화살표)는 그리지 않고 파일 경계를 넘는 엣지만 표시. 노드 자체는 그대로 유지되며 엣지만 필터링됨

노드 라벨은 `이름 (파일명)` 형식이며 `_mmd_escape()`로 이스케이프(따옴표 제거·개행 제거·50자 제한) 후 삽입한다.

---

### `to_mermaid_dataflow(func, analysis=None, expand=False, max_nodes=80) -> str`

함수 레코드 하나(`get_function()` 반환값)의 내부 데이터플로우를 `graph LR` mermaid 소스로 생성한다. 좌→우 흐름: param 노드(둥근 모양) → 지역변수 정의 노드(사각) → return/외부호출 노드(알약 모양). 각 노드는 `depends_on`에 나열된 선행 노드로부터 화살표를 받는다.

`expand=True`이고 `analysis`가 주어지면, `out_calls` 중 `resolved_ids`가 정확히 하나의 함수로 해소된 호출에 한해 그 대상 함수의 데이터플로우를 재귀적으로 인라인 전개한다(인자는 위치 기준으로 대상 함수의 `params`에 바인딩). 순환 호출은 방문 중(`visiting`) 집합으로 차단하고, 노드 수가 `max_nodes`에 도달하면 그 이상 확장하지 않는다. `expand=False`(기본값)는 기존과 동일하게 확장 없는 단일 함수 데이터플로우만 그린다.

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
| `.html`/`.htm` | `_ScriptCollector`(stdlib `html.parser` 서브클래스, 관대한 파싱) | `<script>` 블록마다 1유닛 + 인라인 이벤트 핸들러 속성(`HTML_EVENT_ATTRS` 화이트리스트 44종)마다 1유닛 |
| `.xfdl`/`.xadl`/`.xml` | `xml.etree.ElementTree`(`_extract_from_xml`) | 네임스페이스 무관 `<Script>` 엘리먼트(CDATA 존재)마다 1유닛, id/name 없으면 `#N` 순번 |
| `.xjs` | `_extract_from_xml` 우선 시도 → `ET.ParseError`(XML 아님) 시 전체를 JS 1유닛으로 폴백 | Nexacro `<Script>` 루트 XML이면 위 규칙과 동일, 순수 JS 저장본이면 `.js`와 동일(전체 = 단일 스크립트) |

인코딩은 `_decode_bytes()`로 `utf-8-sig → utf-8 → cp949` 순 폴백, 모두 실패 시 손실 허용 디코딩(`errors="replace"`).

### 엣지 케이스 처리

| 상황 | 처리 |
|------|------|
| 미지원 확장자 | `files[].kind="unsupported"`, `parse_errors`에 안내 메시지, 분석 스킵(배치 중단 없음) |
| 유닛 파싱 실패 (ES2020+ 문법 `?.`/`??` 등) | 해당 유닛만 `parse_errors`에 기록하고 스킵. `.js`는 파일 전체가 1유닛이라 파일 전체가 스킵됨 |
| classic script 파싱 실패 | `esprima.parseModule()`(ES module, import/export)로 재시도 |
| 이름 없는 함수 표현식 | 대입 위치(변수/속성/this.x/클래스 메서드)에서 이름 힌트 추출, 그마저 없으면 `<anonymous#N>` |
| 계산된 속성 접근/키 (`obj[expr]`, `{[expr]: ...}`) | 이름 추적 불가 → `"<computed>"` |
| 동일 이름 다중 정의 | import/require/include로 해소되지 않는 호출은 이름 매칭 폴백(`resolution="name"`)으로 모두 후보 연결(과다 연결 가능) |
| 동일 베이스네임 파일 다중 업로드 | import/require/include 지정자를 베이스네임으로 매칭할 대상을 특정할 수 없어 미해소 처리(`modules.unresolved`에 `reason="ambiguous"`로 기록) |
| 깨진 HTML | `html.parser`가 관대하게 처리, `feed()` 예외 발생 시점까지 수집된 유닛은 그대로 반환 |
| XFDL/XADL/XML XML 자체가 깨짐(`ET.ParseError`) | 원본 파싱 실패 시에만 금지 제어문자(0x00~0x1F 중 tab/LF/CR 제외)를 공백으로 치환 후 재시도(`_strip_illegal_xml_bytes`). 그래도 실패하면 파일 단위로 `parse_errors`에 기록, 다른 파일은 계속 처리. UTF-16 등 원본이 정상 파싱되는 인코딩에는 스크럽이 적용되지 않음(1차 시도에서 이미 성공) |
| `.xjs`가 순수 JS로 저장된 경우 | XML 파싱(`ET.ParseError`) 실패를 감지해 파일 전체를 JS 1유닛으로 폴백(별도 에러 기록 없음) |
| xscript(투비소프트 Nexacro) 확장 문법 — `include "...";` 지시문, 매개변수 타입 어노테이션(`obj:Form`), `<>` 부등호 연산자 | esprima 원본 파싱 실패 시에만 3종을 길이 보존 방식(공백/동일 길이 치환)으로 무력화 후 재시도(`_sanitize_xscript`). 표준 JS는 1차 파싱에서 성공하므로 영향 없음. `include` 지시문은 별도로 `_extract_includes()`가 정규식 추출해 `modules.edges`(kind=`include`)로 연결 |
| 외부(http/https) `<script src="...">` | fetch하지 않고 `external_refs`에 URL만 기록. 업로드된 파일명과 베이스네임이 일치하는 상대경로 `<script src>`는 `modules.edges`(kind=`script`)로 연결되어 같은 스코프로 취급됨 |
| 클로저로 캡처된 외부 스코프 변수 | `_collect_used`가 중첩 함수 경계를 넘지 않으므로 추적 대상 밖(알려진 한계) |

전역 호출 그래프 한계, 데이터플로우 흐름 비민감성, XFDL/XADL/XJS/XML 블록 상대 라인 번호 등 설계 단계에서 합의된 근사치 분석 범위는 [design.md](../design.md) §8-6 참고.

---

## 의존성

| 패키지 | 용도 | 설치 방법 |
|--------|------|-----------|
| `esprima` | ES2017 이하 JS 파싱 (ESTree 호환 AST) | `_ensure_jsanalysis_deps()` lazy 설치 (순수 파이썬, import명·pip 패키지명 동일) |
| `html.parser` (stdlib) | HTML `<script>`/인라인 이벤트 핸들러 추출 | 추가 설치 불필요 |
| `xml.etree.ElementTree` (stdlib) | XFDL/XADL/XJS/XML `<Script>` CDATA 추출 | 추가 설치 불필요 |
