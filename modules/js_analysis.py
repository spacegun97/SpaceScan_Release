"""
js_analysis.py — JS/HTML/XFDL/XADL/XJS/XML 정적 데이터플로우 분석 모듈
==============================================================================
탐지 모듈(scan() 인터페이스)·SQLi 추출·엑셀 취합·OSINT 정찰과 분리된 별도 모드(대시보드
UI·자체 job 흐름 기준 — 이 모듈은 스캔 결과나 다른 모듈 상태에 의존하지 않는다).
업로드된 소스에서 함수를 찾아내고, 함수별 내부 데이터플로우(입력→처리→출력)와
함수 간 호출 관계(호출 그래프)를 정적으로 재구성한다. 네트워크 요청 없음(완전 오프라인).
단, extract_endpoints()는 크롤러(_crawl.py)·SQLi/경로순회 입력 포인트 수집(_sqli_util.py)이
정규식을 보강하는 라이브러리 함수로 재사용한다 — 이 모듈 → 스캐너 단방향 참조이며,
반대 방향 의존은 없다(상세: extract_endpoints() 참고).

지원 입력 형식:
  .js    — 파일 전체를 단일 스크립트로 파싱
  .axd   — ASP.NET WebResource.axd/ScriptResource.axd 등의 핸들러 출력. 확장자만 다를 뿐
           내용은 순수 JS라 .js와 동일하게 파싱(예: WebForm_DoCallback 등 프레임워크 스크립트)
  .html/.htm — <script> 블록 + 인라인 이벤트 핸들러 속성(onclick 등) 추출
               (외부 <script src="..."> 는 URL만 기록, 절대 fetch하지 않음)
  .xfdl/.xadl/.xml — 투비소프트 Nexacro/XPlatform 폼·앱정의 XML. <Script> 엘리먼트 CDATA 추출
  .xjs   — Nexacro 스크립트 파일. 우선 XML(<Script> 루트)로 파싱을 시도하고,
           실패하면(순수 JS로 저장된 경우) 파일 전체를 단일 JS 유닛으로 폴백

**하드 룰: 이 모듈은 어떤 외부 호스트로도 요청을 보내지 않는다.** 업로드된 바이트만
읽어 파싱한다. 파싱 백엔드는 esprima(ES2017, 순수 파이썬) 1차 → 실패 시 tree-sitter-
javascript(ES2020+, 네이티브 바이너리) 2차로 재시도하는 체인이며(_try_parse), 후자는
_js_ts_adapter가 esprima와 동일한 ESTree 노드 모양으로 변환해 반환하므로 이 파일의
분석 로직은 어느 백엔드가 파싱했는지 구분하지 않는다.

알려진 한계 (설계 단계에서 사용자와 합의된 근사치 분석 범위):
  - 두 백엔드 모두 실패하면(TypeScript 문법·JSX·데코레이터 등) 해당 유닛만
    parse_errors에 기록하고 스킵
  - tree-sitter 백엔드는 옵셔널 체이닝(`?.`)을 일반 멤버/호출 접근과 동일하게 취급한다
    (null-safety 자체는 애초에 추적 대상 밖이므로 정보 손실 없음, _js_ts_adapter 참고)
  - 호출 그래프는 이름 기반 매칭이다 (동적 디스패치 obj[key](), eval, 클로저로 캡처된
    외부 스코프 변수는 추적하지 않음)
  - 데이터플로우는 흐름 비민감(flow-insensitive) 근사치다 (if/else·루프 분기를
    모두 순회하되 상호배타성은 구분하지 않음 — 어떤 경로로도 도달 가능한 것으로 간주)
  - XFDL/XADL/XML/XJS Script 블록 내부 라인 번호는 블록 상대 라인이다 (파일 전체 절대 라인
    매핑은 미구현 — 실제 Nexacro 샘플로 검증하지 못한 부분)
  - 투비소프트 Nexacro xscript는 ECMAScript의 상위 방언이라 `include "...";` 지시문,
    매개변수 타입 어노테이션(`function f(obj:Form)`), `<>`(부등호, != 의미) 연산자를 쓴다.
    esprima 원본 파싱이 실패했을 때만 이 3종을 "길이 보존" 방식(공백/동일 길이 치환)으로
    무력화해 재시도한다(_sanitize_xscript) — 표준 JS는 원본 그대로 1차 파싱에서 성공하므로
    전혀 영향받지 않는다. include 대상 파일의 의존 관계 자체는 추적하지 않고 버린다.
  - XML 자체가 금지 제어문자(0x00~0x1F 중 tab/LF/CR 제외)를 포함해 파싱 실패하는 경우,
    원본 파싱이 실패했을 때만 해당 바이트를 공백으로 치환해 재시도한다
    (_strip_illegal_xml_bytes) — UTF-16 등 원본이 정상 파싱되는 인코딩에는 적용되지 않음.
  - 엔드포인트 탐지는 명명 패턴 기반 sink 목록(fetch/XHR/jQuery/axios/beacon/WebSocket/
    EventSource/Nexacro transaction/HTML form)에 한정된다. 이름을 알 수 없는 커스텀 HTTP
    래퍼(예: `obj["a"].fetch(url)`처럼 minify·computed 접근을 거치는 프로덕션 번들 관례)는
    별도의 URL-형태 휴리스틱(candidate_endpoints)이 저신뢰 후보로만 수집한다 — callee
    이름이 아니라 인자 문자열이 URL/경로처럼 생겼는지만으로 판별하므로 확정 sink보다
    오탐 가능성이 높고, 파라미터 전파도 적용되지 않는다(확정 endpoints와 절대 섞이지 않음).
  - 엔드포인트 파라미터 전파(_propagate_endpoint_params)는 호출자 체인을 최대 4단계
    (hop)까지만 거슬러 올라간다. 순환·과다 확산은 hop 상한과 엔드포인트당 variant 총량
    상한(50)으로 방어하며, 상한에 걸리면 그 시점까지 구체화된 값을 variant로 남긴다.
  - 설정 객체(sink 인자)는 리터럴뿐 아니라 `var t={}; t.url=...`/`t["url"]=...`(속성-대입
    조립, _merged_object_props)도 인식하고, URL이 조건부(삼항/if-else/논리연산/switch/
    변수 재대입)로 여러 값을 가지면 분기당 하나씩 엔드포인트를 발행한다
    (_enumerate_url_node_variants·_reassignment_variants_for_identifier — 최대
    _URL_BRANCH_CAP개). 어느 분기가 실제로 상호배타적인지 완전히 증명하지는 않는 안전한
    근사치라, 값을 잃는 대신(미탐 방지 우선) if-without-else·switch-without-default처럼
    분기가 모든 경로를 덮는지 확실치 않은 경우 "분기 전 값"도 함께 남긴다(그 값 자체가
    `/`를 포함하는 등 경로처럼 보이면 — 플레이스홀더뿐인 잡음만 걸러내고 나머지는 유지).
    분기 열거는 URL 노드가 직접 삼항/논리연산/`+`연결/템플릿 리터럴/변수인 경우에만
    적용되고(속성 대입으로 채워진 값이 그 자체로 삼항/변수인 경우도 포함), 그 변수 자체를
    또 다른 변수 재대입 체인으로 감싸는 등 더 깊은 형태는 첫 재구성 값 하나로 근사한다.
    `obj.key += value`(멤버 대상 복합대입)로 조립되는 값은 아직 속성-대입 추적 대상이
    아니다(속성-대입은 `=`만 인식 — 알려진 한계). `this.PROP` 읽기는 유닛 전체에서 수집한
    최초 대입만 반영하며(axios_instances와 동일한 흐름 비민감 근사치), 서로 무관한
    클래스/객체가 같은 이름의 속성을 가지면 구분하지 않고 하나로 합쳐진다.
"""
import html.parser as _htmlparser
import re
import sys
import xml.etree.ElementTree as ET
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import _js_ts_adapter  # tree-sitter 자체는 무거우므로 이 모듈이 아닌 parse() 내부에서 지연 import
from ._cancel import ScanCancelled, run_cancellable, wait_or_cancel  # 진행률 표시용 협조적 중단

# esprima는 최상단이 아닌 _try_parse() 내부에서 지연 import한다 — app.py가 이 모듈을
# import하는 시점(앱 기동)에는 esprima 미설치 여도 죽지 않아야 하고, 실제 분석
# 진입 시점에 app.py의 _ensure_jsanalysis_deps()가 먼저 설치를 보장한다.

# ── 상수 ────────────────────────────────────────────────────────────────────

SUPPORTED_EXTS = frozenset({".js", ".axd", ".html", ".htm", ".xfdl", ".xadl", ".xjs", ".xml"})

# 인라인 이벤트 핸들러로 인정할 속성명 화이트리스트 (data-* / Vue 커스텀 속성 오탐 방지)
HTML_EVENT_ATTRS = frozenset({
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmousemove",
    "onmouseout", "onmouseenter", "onmouseleave", "onkeypress", "onkeydown", "onkeyup",
    "onload", "onunload", "onabort", "onerror", "onresize", "onscroll", "onselect",
    "onchange", "onsubmit", "onreset", "onfocus", "onblur", "oninput", "oncontextmenu",
    "ondrag", "ondragstart", "ondragend", "ondragover", "ondragenter", "ondragleave", "ondrop",
    "ontouchstart", "ontouchend", "ontouchmove", "ontouchcancel", "onwheel",
    "onanimationend", "onanimationstart", "ontransitionend", "onplay", "onpause", "onended",
})

# <script type="..."> 중 JS로 취급할 값 (빈 값/생략은 기본 JS)
_JS_SCRIPT_TYPES = frozenset({"", "text/javascript", "application/javascript", "module", "text/babel"})

# 함수로 취급하는 esprima 노드 타입 (선언식/표현식/화살표)
_FUNC_TYPES = frozenset({"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"})

# ── 엔드포인트(HTTP 요청 sink) 탐지 상수 ────────────────────────────────────────

_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"})
_JQUERY_ROOTS = frozenset({"$", "jQuery"})
# jQuery 단축 메서드/axios 단축 메서드 → 기본 HTTP 메서드 매핑
_JQUERY_SHORT_METHODS = {"get": "GET", "getJSON": "GET", "load": "GET", "post": "POST"}
_AXIOS_SHORT_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE", "patch": "PATCH"}
# window.open(url)/self.open(url)/parent.open(url)/top.open(url) — 새 창 내비게이션 판별용
# 루트 이름. bare open(...)은 지역 함수와 구분 불가해 대상에서 제외한다.
_WINDOW_OPEN_ROOTS = frozenset({"window", "self", "parent", "top"})
# iframe/팝업 컨트롤에 URL을 로드하는 프레임워크 메서드 관례(Nexacro의 transaction/
# gfnTransaction과 동일한 성격) — DevExpress ASPxClientPopupControl.SetContentUrl이 대표적.
# 다른 프레임워크의 유사 메서드가 확인되면 이 집합에 추가해 확장한다.
_IFRAME_CONTENT_URL_METHODS = frozenset({"SetContentUrl"})
# "k=v" / "k=v&k2=v2" / "k=v k2=v2"(Nexacro 인자 문자열) 형태에서 키/값 쌍 추출
_QS_PAIR_RE = re.compile(r'([^&=\s]+)=([^&\s]*)')
# 재구성된 문자열 안의 {paramName} 플레이스홀더 — N-hop 파라미터 전파 대상 탐지용
_PLACEHOLDER_RE = re.compile(r'\{([A-Za-z_$][\w$]*)\}')
# N-hop 파라미터 전파(_propagate_endpoint_params) 상한 — 호출 그래프 순환/광범위 확산으로 인한
# 무한 확장·과다 variants 생성을 막는 안전장치(끝까지 못 풀려도 그 시점 값을 variant로 확정).
_HOP_MAX = 4          # 원 엔드포인트로부터 최대 4단계 호출자까지만 거슬러 올라간다
# 엔드포인트 하나당 생성 가능한 variants 총량 상한 — _propagate_one이 최종 (url, params)
# 조합 기준으로 중복을 제거한 뒤(seen_keys) 세므로 "서로 다른 (url, params) 조합 수"에
# 대한 상한이다(url만으로 dedup하면 URL은 정적이고 params만 갈리는 게이트웨이 패턴에서
# 서로 다른 값이 잘못 병합된다). 이름 매칭 과다연결(resolution="name") 등으로 생기는
# 동일/유사 조합 노이즈는 dedup으로 자연히 접히고, SetContentUrl처럼 하나의 sink에
# 정당하게 수십~수백 개의 서로 다른 URL이 몰리는 케이스(레거시 팝업 게이트웨이 등)는
# 상한을 온전히 채운다.
_VARIANT_CAP = 300

# URL 노드 자체가 분기(삼항/if-else/논리연산/변수 재대입)를 포함할 때 sink 호출 1건에서
# 발행하는 엔드포인트 레코드 개수 상한(_enumerate_url_node_variants) — 중첩이 깊은 코드에서
# 조합 폭발을 막는다. N-hop 파라미터 전파(_VARIANT_CAP)와는 별개의, 더 이른 단계의 상한이다.
_URL_BRANCH_CAP = 8

# 표시용 정규화 경로(_normalize_display_path)에서 "실제 서버 경로의 일부"로 보아 보존할
# 확장자 화이트리스트 — 첫 "/" 앞 조각에 "."이 있어도 이 확장자로 끝나면(예: "gateway.do")
# this/멤버식 잔재가 아니라 진짜 경로 세그먼트로 판단해 제거하지 않는다.
_PATH_SEGMENT_EXT_WHITELIST = frozenset({
    "do", "jsp", "php", "action", "aspx", "asp", "html", "htm", "xml", "json", "cgi",
})

# 플레이스홀더 출처 주석(_placeholder_origins)에서 하나의 이름당 표시할 호출자 인자식
# 최대 개수 — 호출자가 매우 많은 공용 헬퍼 함수에서 목록이 과도하게 길어지는 것을 막는다.
_PLACEHOLDER_ORIGIN_ARGS_CAP = 8

# ── URL-형태 휴리스틱(candidate_endpoints) 탐지 상수 ──────────────────────────
#
# 이름 패턴으로 확정할 수 없는 커스텀 HTTP 래퍼(obj["a"].fetch(url)/obj.modify(url) 등,
# 프로덕션 minify 번들에서 흔함)를 위한 저신뢰 후보 탐지. callee 이름이 아니라 인자
# 문자열이 "URL/경로처럼 생겼는지"만으로 판별하므로 오탐 가능성이 확정 sink보다 높다 —
# candidate_endpoints로 별도 목록에 담고 확정 endpoints와 절대 섞지 않는다.
#
# 상대경로 형태(예: "users/me", "v4/self/groups")를 URL로 인정하되, 순수 문자열/배열
# 빌트인 메서드(.concat/.split 등)와 require()(모듈 경로를 URL로 오인하는 흔한 오탐
# 원인)는 callee 말단 이름으로 걸러낸다.
_URL_SHAPE_EXCLUDE_TAILS = frozenset({
    "concat", "split", "join", "replace", "slice", "substring", "substr",
    "match", "test", "startsWith", "endsWith", "includes", "indexOf",
    "lastIndexOf", "push", "toString", "trim", "repeat", "require",
})
# "a/b", "a/b/c" 형태의 상대경로 세그먼트(placeholder "{name}" 포함) — 절대경로(/로 시작)나
# http(s)://·//(프로토콜 상대) 는 별도로 접두사 검사하므로 이 정규식은 상대경로 전용이다.
_REL_PATH_SHAPE_RE = re.compile(r'^[\w.\-]+(?:/[\w.\-{}]+)+$')

# ── 재귀 한계 ────────────────────────────────────────────────────────────────
#
# visit()/convert() 등 AST 순회는 재귀 함수라 Python 기본 재귀 한계(1000)로는 난독화
# (제어흐름 평탄화 등)·기계생성 코드처럼 극단적으로 깊게 중첩된 구문(예: `a||b||c...`
# 수백~수천 항 체인)에서 RecursionError로 끝날 수 있다. analyze() 진입 시 이 값으로
# 상향한다(단, 실제 OS 스택이 이 깊이를 버텨야 안전 — app.py가 분석 스레드 생성 시
# 스택 크기도 함께 키운다. 그래도 넘는 경우는 analyze()의 유닛 단위 예외 격리가 흡수).
_RECURSION_LIMIT = 5000

# ── 제어흐름(CFG)·가드 체인 분석 상수 ────────────────────────────────────────────

_CFG_MAX_NODES = 150       # 함수 하나의 CFG 노드 상한 (그래프 폭발 방지)
_CFG_BLOCK_MAX_LINES = 6   # block 노드 하나에 표시할 최대 문장 수 (초과분은 "…(+N)"으로 축약)

# 파일 단위 CFG 다이어그램(to_mermaid_file_cfg) 한 페이지에 담을 함수(subgraph=클러스터) 수.
# 실제 프로덕션 minify 번들 2종(함수 수백~수천 개)으로 재현 실측: mermaid(10.9.1)의 dagre
# 레이아웃이 클러스터 180~200개 부근에서 "Cannot set properties of undefined (setting 'order')"로
# 깨짐(클러스터 수에 상관성, 노드/엣지 총량과는 무관 — 같은 노드수라도 클러스터가 적으면 통과).
# 80은 그 실측 임계 대비 넉넉한 안전 마진이자, 사람이 한 화면에서 식별 가능한 상한이기도 하다.
# 이전에는 "파일 전체 노드 총량 400개 예산 소진 시 이후 함수 생략(break)" 방식이었으나, 앞쪽의
# 큰 함수 하나가 예산을 다 쓰면 뒤쪽 작은 함수들이 전부 생략되는 결함이 있어(알려진 문제),
# 함수 개수 기준 고정 크기 페이지네이션으로 대체했다 — 모든 함수는 반드시 어느 한 페이지에는
# 나타난다(생략 없음, page 파라미터로 다음 페이지 조회).
_FILE_CFG_PAGE_SIZE = 80

# 클라이언트 측 인증/권한 가드로 추정되는 조건식 키워드(대소문자 무관 부분일치) —
# 클라이언트 단 인증우회·강제호출 가능 엔드포인트 파악을 위한 휴리스틱(오탐 가능, 참고용)
_AUTH_GUARD_KEYWORDS = (
    "admin", "auth", "login", "logged", "permission", "role", "token", "session",
    "권한", "관리자", "로그인", "인증",
)


# ── 인코딩 폴백 ────────────────────────────────────────────────────────────────

def _decode_bytes(data: bytes) -> str:
    """utf-8-sig → utf-8 → cp949 순으로 디코딩 시도, 모두 실패하면 손실 허용 디코딩.

    excel_merge.py의 CSV 인코딩 폴백 정책과 동일한 규칙(한글 EUC-KR/CP949 소스 대응).
    """
    for enc in ("utf-8-sig", "utf-8", "cp949"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return data.decode("utf-8", errors="replace")


# ── AST 헬퍼: 이름/패턴 추출 ──────────────────────────────────────────────────

def _pattern_names(node) -> List[str]:
    """매개변수 패턴(구조분해/기본값/rest 포함)에서 실제 바인딩되는 식별자명을 모두 평탄화."""
    if node is None:
        return []
    t = node.type
    if t == "Identifier":
        return [node.name]
    if t == "AssignmentPattern":  # 기본값: (a = 10)
        return _pattern_names(node.left)
    if t == "RestElement":  # ...rest
        return _pattern_names(node.argument)
    if t == "ObjectPattern":  # {a, b}
        names: List[str] = []
        for prop in node.properties:
            if prop.type == "RestElement":
                names += _pattern_names(prop.argument)
            else:
                names += _pattern_names(prop.value)
        return names
    if t == "ArrayPattern":  # [a, b]
        names = []
        for el in node.elements:
            if el is not None:
                names += _pattern_names(el)
        return names
    return []


def _key_name(key, computed: bool) -> str:
    """객체 리터럴/클래스 멤버의 key를 문자열로. 계산된 키([expr])는 추적 불가로 표시."""
    if computed:
        return "<computed>"
    t = getattr(key, "type", None)
    if t == "Identifier":
        return key.name
    if t == "Literal":
        return str(key.value)
    return "<computed>"


def _assignment_name(left) -> Optional[str]:
    """`x = ...` 또는 `obj.x = ...` / `this.x = ...` 형태의 좌변에서 이름 힌트 추출."""
    t = getattr(left, "type", None)
    if t == "Identifier":
        return left.name
    if t == "MemberExpression" and not left.computed:
        prop = left.property
        if getattr(prop, "type", None) == "Identifier":
            return prop.name
    return None


def _callee_name(node) -> str:
    """호출식의 callee를 이름으로 (obj.method() → 'method', 계산 접근은 '<computed>')."""
    t = getattr(node, "type", None)
    if t == "Identifier":
        return node.name
    if t == "MemberExpression" and not node.computed:
        prop = node.property
        return prop.name if getattr(prop, "type", None) == "Identifier" else "<computed>"
    return "<computed>"


def _call_root_name(node) -> Optional[str]:
    """호출식의 루트 객체 식별자명 (obj.foo() → 'obj', a.b.c() → 'a', foo() → None).

    import 네임스페이스(`import * as U`)나 `const m = require(...)` 바인딩으로 호출된
    `U.foo()` / `m.foo()` 형태를 파일 간 호출 해소 시 식별하는 데 쓰인다.
    """
    t = getattr(node, "type", None)
    if t != "MemberExpression":
        return None
    obj = node.object
    while getattr(obj, "type", None) == "MemberExpression":
        obj = obj.object
    return obj.name if getattr(obj, "type", None) == "Identifier" else None


def _slice(src: str, node, limit: int = 80) -> str:
    """원본 소스에서 노드의 원문 텍스트를 짧게 잘라 표시용으로 반환."""
    if not src or not getattr(node, "range", None):
        return ""
    start, end = node.range
    text = re.sub(r"\s+", " ", src[start:end]).strip()
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _is_auth_guard(cond_text: str) -> bool:
    """조건식 소스 텍스트에 인증/권한 관련 키워드가 포함되는지 휴리스틱 판별(대소문자 무관 부분일치).

    클라이언트 단 인증우회·강제호출 가능 엔드포인트 파악 목적의 참고 신호일 뿐이며,
    이름에 키워드가 없는 인증 검사(오탐 반대 방향)나 키워드는 있지만 인증과 무관한
    조건(예: "role" 필드가 UI 표시용)을 완벽히 구분하지 못한다(근사치)."""
    t = (cond_text or "").lower()
    return any(kw in t for kw in _AUTH_GUARD_KEYWORDS)


# ── 함수 내부 데이터플로우(def-use) 분석 ──────────────────────────────────────

def _collect_used(node, known: set, out: set) -> None:
    """표현식 서브트리에서 known(파라미터+지역변수) 집합에 속한 식별자 사용을 수집.

    중첩 함수 경계는 넘지 않는다(클로저 캡처 변수는 추적 대상 밖 — 알려진 한계).
    """
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _collect_used(item, known, out)
        return
    t = getattr(node, "type", None)
    if t is None:
        return
    if t in _FUNC_TYPES:
        return
    if t == "Identifier":
        if node.name in known:
            out.add(node.name)
        return
    if t == "MemberExpression":
        _collect_used(node.object, known, out)
        if node.computed:  # obj[expr] 형태만 property 쪽도 탐색 (obj.prop은 리터럴 이름)
            _collect_used(node.property, known, out)
        return
    if t == "Property":
        if node.computed:
            _collect_used(node.key, known, out)
        _collect_used(node.value, known, out)
        return
    for k, v in vars(node).items():
        if k in ("range", "loc", "type"):
            continue
        _collect_used(v, known, out)


# ── 엔드포인트(HTTP 요청 sink) 탐지 ─────────────────────────────────────────────
#
# fetch/XHR/jQuery.ajax/axios/sendBeacon/WebSocket·EventSource/Nexacro transaction 등
# 브라우저·프레임워크가 제공하는 "요청을 실제로 내보내는" 호출을 sink로 탐지하고,
# 그 인자(URL/설정 객체)를 최대한 사람이 읽을 수 있는 문자열로 재구성한다.
# 값이 함수 파라미터에 의존해 정적으로 확정되지 않으면 "{paramName}" 플레이스홀더로
# 표기하고(레거시/SPA의 action 단위 게이트웨이 패턴 대응), analyze() 마지막 단계에서
# 호출자(1-hop)의 실제 인자로 구체화(variants)를 시도한다.

def _callee_path(node) -> Optional[List[str]]:
    """호출식 callee를 점(.) 경로 목록으로 분해 (`$.ajax` → ['$','ajax'], `fetch` → ['fetch']).

    계산된 접근(obj[expr])이나 this 이외의 복잡한 표현은 이름을 특정할 수 없어 None.
    """
    if node is None:
        return None
    t = getattr(node, "type", None)
    if t == "Identifier":
        return [node.name]
    if t == "ThisExpression":
        return ["this"]
    if t == "MemberExpression" and not node.computed:
        base = _callee_path(node.object)
        if base is None:
            return None
        prop = node.property
        if getattr(prop, "type", None) != "Identifier":
            return None
        return base + [prop.name]
    return None


def _reconstruct_str(node, known_params: set, local_inits: Dict[str, Any], src: str,
                      _visiting: Optional[set] = None, _depth: int = 0,
                      this_props: Optional[Dict[str, Any]] = None) -> Tuple[str, bool]:
    """식을 사람이 읽을 수 있는 문자열로 최대한 정적 재구성 (텍스트, is_static) 반환.

    리터럴/템플릿 리터럴/문자열 `+` 연결/지역변수(1단계 인라인, 최초 대입값 기준)는 값을
    그대로 접어 넣는다. 함수 파라미터·해소 불가 식별자는 "{이름}" 플레이스홀더(1-hop 전파
    매칭 대상)로 표기한다. this_props가 주어지면(_collect_this_props, 엔드포인트 재구성
    경로에서만 주입) `this.PROP` 읽기도 정적 해소 가능하면 인라인, 아니면(예:
    `GO.contextRoot||this.getContextRoot()`처럼 복잡한 초기화) "{PROP}" 플레이스홀더로
    표기한다. 그 외 복잡한 표현식(멤버/호출/객체 리터럴 등)은 원문 슬라이스를 그대로(중괄호로
    감싸지 않고) 반환한다 — 객체 리터럴처럼 원문 자체에 중괄호가 포함된 경우 이중 래핑을
    피하고, "{이름}" 형태와 시각적으로 구분하기 위함. 두 경우 모두 is_static=False. 지역변수
    순환 참조는 _visiting 방문 집합으로, 과도한 재귀는 _depth 상한(6)으로 각각 차단한다.
    """
    if node is None:
        return ("", True)
    if _visiting is None:
        _visiting = set()
    if _depth > 6:
        return (_slice(src, node, limit=40), False)

    t = getattr(node, "type", None)

    if t == "Literal":
        val = node.value
        if val is None:
            return ("null", True)
        if isinstance(val, bool):
            return ("true" if val else "false", True)
        return (str(val), True)

    if t == "TemplateLiteral":
        parts: List[str] = []
        is_static = True
        exprs = list(node.expressions)
        for i, q in enumerate(node.quasis):
            parts.append(q.value.cooked if q.value and q.value.cooked is not None else "")
            if i < len(exprs):
                sub, sub_static = _reconstruct_str(exprs[i], known_params, local_inits, src,
                                                    _visiting, _depth + 1, this_props)
                parts.append(sub)
                is_static = is_static and sub_static
        return ("".join(parts), is_static)

    if t == "BinaryExpression" and node.operator == "+":
        left, ls = _reconstruct_str(node.left, known_params, local_inits, src, _visiting, _depth + 1, this_props)
        right, rs = _reconstruct_str(node.right, known_params, local_inits, src, _visiting, _depth + 1, this_props)
        return (left + right, ls and rs)

    if t == "Identifier":
        name = node.name
        if name in known_params:
            return ("{" + name + "}", False)  # 함수 파라미터 — 1-hop 전파 대상
        if name in local_inits and name not in _visiting:
            _visiting.add(name)
            result = _reconstruct_str(local_inits[name], known_params, local_inits, src,
                                       _visiting, _depth + 1, this_props)
            _visiting.discard(name)
            return result
        return ("{" + name + "}", False)  # 해소 불가 식별자(외부 스코프/전역/import 등) — best-effort

    if t == "ConditionalExpression":
        # 흐름 비민감 근사치: consequent를 대표값으로 표기하되, 분기가 있었다는 사실을
        # 잃지 않도록 is_static은 항상 False로 강제한다. (URL 노드 자체가 이 형태면
        # _enumerate_url_node_variants가 별도로 양쪽 분기를 모두 열거한다.)
        text, _ = _reconstruct_str(node.consequent, known_params, local_inits, src,
                                    _visiting, _depth + 1, this_props)
        return (text, False)

    if t == "MemberExpression" and not node.computed \
            and getattr(node.object, "type", None) == "ThisExpression" \
            and getattr(node.property, "type", None) == "Identifier":
        # `this.PROP` — this_props(유닛 전체에서 수집된 인스턴스 속성 대입)로 정적 해소를
        # 시도하고, 값이 없거나 비정적이면(복잡한 초기화 표현식) "{PROP}" 플레이스홀더로
        # 표기해 최소한 값이 손실되지 않았음을 남긴다(1-hop 전파 매칭 대상은 아님).
        prop_name = node.property.name
        if this_props and prop_name in this_props and prop_name not in _visiting:
            entry = this_props[prop_name]
            if entry["static"]:
                return (entry["value"], True)
        return ("{" + prop_name + "}", False)

    # MemberExpression/CallExpression/ObjectExpression 등 그 외 표현식은 원문 슬라이스 그대로 표기
    return (_slice(src, node, limit=40), False)


def _resolve_object_literal(node, local_inits: Dict[str, Any], _visiting: Optional[set] = None):
    """노드가 객체 리터럴이거나(직접) 객체 리터럴로 초기화된 지역변수(간접, 1단계)면 그 ObjectExpression 노드를 반환."""
    if node is None:
        return None
    t = getattr(node, "type", None)
    if t == "ObjectExpression":
        return node
    if t == "Identifier":
        if _visiting is None:
            _visiting = set()
        if node.name in local_inits and node.name not in _visiting:
            _visiting.add(node.name)
            return _resolve_object_literal(local_inits[node.name], local_inits, _visiting)
    return None


def _get_prop_value(obj_node, names: Tuple[str, ...], local_inits: Dict[str, Any]):
    """ObjectExpression에서 names 중 첫 일치 key(계산되지 않은 key만)의 value 노드를 반환."""
    if obj_node is None:
        return None
    for prop in getattr(obj_node, "properties", []):
        if getattr(prop, "type", None) != "Property":
            continue
        key = _key_name(prop.key, prop.computed)
        if key in names:
            return prop.value
    return None


# ── 설정 객체 조립 패턴: 리터럴 vs 속성-대입 병합 ───────────────────────────────
#
# `$.ajax({url: "..."})`처럼 인자에 객체 리터럴을 직접 넣는 관례뿐 아니라, 프로덕션
# 코드에서 흔한 `var t={}; t.url="..."; $.ajax(t);`(빈 객체 후 속성 대입으로 조립) 패턴도
# 동일하게 인식해야 sink 자체가 통째로 누락되지 않는다. local_props(_analyze_dataflow가
# AssignmentExpression 방문 중 `obj.key = value` / `obj["key"] = value` 형태를 누적한
# 변수명 → {key: value_node} 테이블)를 객체 리터럴 속성과 병합해 하나의 키→값 매핑으로 다룬다.

def _member_key_name(member_node) -> Optional[str]:
    """MemberExpression(this 제외)의 속성명을 얻는다. `obj.key`(비-computed Identifier)와
    `obj["key"]`(computed 문자열 리터럴) 두 형태만 지원 — 그 외 계산된 키(변수 인덱싱 등)는
    정적으로 알 수 없어 None(추적 대상에서 제외, 오탐 방지)."""
    prop = member_node.property
    if not member_node.computed:
        return prop.name if getattr(prop, "type", None) == "Identifier" else None
    if getattr(prop, "type", None) == "Literal" and isinstance(prop.value, str):
        return prop.value
    return None


def _is_object_like(node, local_inits: Dict[str, Any], local_props: Dict[str, Dict[str, Any]]) -> bool:
    """node가 설정 객체 인자로 쓰일 수 있는 형태인지 판별 — 객체 리터럴(직접/1단계 변수
    간접, 속성이 0개인 빈 `{}` 포함)이거나, 속성-대입으로 하나 이상의 키가 기록된
    지역변수면 True. `$.ajax(url, settings)`처럼 "이 인자가 URL 문자열인가 설정 객체인가"
    를 구분하는 게이트로 쓰인다(_merged_object_props와 달리 빈 결과와 "객체가 아님"을
    구분해야 하므로 별도 함수)."""
    if _resolve_object_literal(node, local_inits) is not None:
        return True
    name = node.name if getattr(node, "type", None) == "Identifier" else None
    return bool(name and name in local_props)


def _merged_object_props(node, local_inits: Dict[str, Any],
                          local_props: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """설정 객체 인자에서 키 → 값 노드 매핑을 만든다. 객체 리터럴(직접/1단계 변수 간접)의
    속성을 우선 반영하고, node가(또는 그 지역변수가) 이후 속성-대입(`obj.key=value`,
    `obj["key"]=value`)으로 추가한 키가 있으면 리터럴에 없는 키에 한해 보강한다(동일 키가
    리터럴과 속성-대입 양쪽에 있으면 리터럴이 우선 — "최초 대입만 기록"인 다른 dataflow
    추적과 동일한 흐름 비민감 근사치)."""
    out: Dict[str, Any] = {}
    resolved = _resolve_object_literal(node, local_inits)
    if resolved is not None:
        for prop in resolved.properties:
            if getattr(prop, "type", None) != "Property":
                continue
            key = _key_name(prop.key, prop.computed)
            if key != "<computed>" and key not in out:
                out[key] = prop.value
    name = node.name if getattr(node, "type", None) == "Identifier" else None
    if name and name in local_props:
        for key, val in local_props[name].items():
            out.setdefault(key, val)
    return out


def _parse_querystring_params(text: str, in_label: str) -> List[Dict[str, Any]]:
    """"a=1&b=2" / "a=1 b=2"(공백 구분, Nexacro 인자 문자열) 형태에서 키/값 쌍 추출.

    값에 "{"가 남아있으면(파라미터 의존) static=False로 표기한다.
    """
    if not text or "=" not in text:
        return []
    pairs = _QS_PAIR_RE.findall(text)
    if not pairs:
        return []
    return [{"name": k, "value": v, "in": in_label, "static": "{" not in v} for k, v in pairs]


def _split_url_query(url_text: str) -> List[Dict[str, Any]]:
    """재구성된 URL 문자열의 쿼리스트링 부분만 파라미터 목록으로 분리 (URL 본문은 그대로 유지)."""
    if "?" not in url_text:
        return []
    _, qs = url_text.split("?", 1)
    return _parse_querystring_params(qs, "query")


def _extract_data_params(node, params: set, local_inits: Dict[str, Any], src: str,
                          in_label: str, this_props: Optional[Dict[str, Any]] = None,
                          local_props: Optional[Dict[str, Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """요청 바디/데이터 인자 노드에서 전달 파라미터 목록을 추출.

    객체 리터럴(직접 또는 지역변수 간접, `var t={}; t.data=...`처럼 속성-대입으로 조립된
    경우 포함, JSON.stringify(obj) 언랩 포함)이면 키별로 분해하고, 그렇지 않으면 문자열로
    재구성해 쿼리스트링 형식("a=1&b=2")으로 재시도하며, 그마저 실패하면 통째로 하나의
    "(body)" 파라미터로 표기한다(값을 완전히 버리지 않는 best-effort 정책).
    """
    if node is None:
        return []
    local_props = local_props or {}
    is_obj = _is_object_like(node, local_inits, local_props)
    if not is_obj and getattr(node, "type", None) == "CallExpression":
        path = _callee_path(node.callee)
        if path and path[-1] == "stringify" and node.arguments:
            inner = node.arguments[0]
            if _is_object_like(inner, local_inits, local_props):
                node = inner
                is_obj = True
    if is_obj:
        out: List[Dict[str, Any]] = []
        for name, value_node in _merged_object_props(node, local_inits, local_props).items():
            value, is_static = _reconstruct_str(value_node, params, local_inits, src, this_props=this_props)
            out.append({"name": name, "value": value, "in": in_label, "static": is_static})
        return out
    text, is_static = _reconstruct_str(node, params, local_inits, src, this_props=this_props)
    parsed = _parse_querystring_params(text, in_label)
    if parsed:
        return parsed
    return [{"name": "(body)", "value": text, "in": in_label, "static": is_static}] if text else []


def _is_create_call_with_baseurl(node):
    """node가 `<expr>.create({baseURL: ...})` 형태의 CallExpression이면 baseURL value 노드를 반환.

    axios 자체의 minify된 별칭 이름(ns, Or 등)은 알 수 없으므로 이름으로 판별하지 않고,
    설정 객체에 `baseURL` 키가 있는지로 axios 인스턴스 팩토리 호출을 식별한다(axios 관례).
    """
    if getattr(node, "type", None) != "CallExpression":
        return None
    callee = node.callee
    if getattr(callee, "type", None) != "MemberExpression" or callee.computed:
        return None
    prop = callee.property
    if getattr(prop, "type", None) != "Identifier" or prop.name != "create":
        return None
    if not node.arguments:
        return None
    cfg = node.arguments[0]
    if getattr(cfg, "type", None) != "ObjectExpression":
        return None
    return _get_prop_value(cfg, ("baseURL",), {})


def _collect_axios_instances(program, src: str) -> Dict[str, Dict[str, Any]]:
    """유닛(파일 전체) 트리를 스캔해 axios 인스턴스 변수명 → {url, static} 매핑을 만든다.

    두 형태를 인식한다(둘 다 실전 번들에서 흔한 패턴):
      1) 직접 생성 — `V = <expr>.create({baseURL: "..."})`
      2) 팩토리 경유 — `F = p => <expr>.create({baseURL: `...${p}...`})` 로 팩토리를 먼저
         인식한 뒤, `V = F(argExpr)` 호출을 만나면 팩토리의 baseURL 템플릿에서 파라미터 p를
         argExpr로 1-hop 치환해 V의 baseURL을 재구성한다.

    함수 경계를 넘어 트리 전체를 순회한다(모듈 최상위에서 정의되고 다른 함수 내부에서
    사용되는 것이 실전 패턴이라, _analyze_dataflow와 달리 함수 경계에서 멈추지 않는다).
    동일 이름이 여러 번 발견되면 최초 발견만 채택한다(다른 dataflow 추적과 동일한
    "최초 대입만 기록" 흐름 비민감 근사치). 파일(유닛) 단위로만 유효하며, 크로스 파일로
    정의/사용이 나뉜 인스턴스는 대응하지 않는다(설계 합의 범위).
    """
    factories: Dict[str, Dict[str, Any]] = {}  # 팩토리명 → {"param": 파라미터명, "url_node": baseURL 노드}
    instances: Dict[str, Dict[str, Any]] = {}  # 인스턴스명 → {"url": 재구성된 baseURL, "static": bool}

    def visit(node) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        t = getattr(node, "type", None)
        if t is None:
            return

        if t == "VariableDeclarator" and getattr(node.id, "type", None) == "Identifier" \
                and node.init is not None:
            name = node.id.name
            init = node.init

            base_node = _is_create_call_with_baseurl(init)
            if base_node is not None:  # 1) 직접 생성
                if name not in instances:
                    url, is_static = _reconstruct_str(base_node, set(), {}, src)
                    instances[name] = {"url": url, "static": is_static}
                visit(init)
                return

            if getattr(init, "type", None) == "ArrowFunctionExpression" and len(init.params) == 1 \
                    and getattr(init.params[0], "type", None) == "Identifier":
                body_node = init.body
                candidates = []
                if getattr(body_node, "type", None) == "BlockStatement":
                    for stmt in body_node.body:
                        if getattr(stmt, "type", None) == "ReturnStatement" and stmt.argument is not None:
                            candidates.append(stmt.argument)
                else:
                    candidates.append(body_node)  # 화살표 축약형 본문(p => expr)
                for cand in candidates:
                    fac_base = _is_create_call_with_baseurl(cand)
                    if fac_base is not None:  # 2) 팩토리 정의
                        if name not in factories:
                            factories[name] = {"param": init.params[0].name, "url_node": fac_base}
                        break
                visit(init)
                return

            if getattr(init, "type", None) == "CallExpression":
                callee = init.callee
                if getattr(callee, "type", None) == "Identifier" and callee.name in factories \
                        and init.arguments and name not in instances:  # 3) 팩토리 호출
                    fac = factories[callee.name]
                    url, is_static = _reconstruct_str(fac["url_node"], set(),
                                                        {fac["param"]: init.arguments[0]}, src)
                    instances[name] = {"url": url, "static": is_static}
                    visit(init)
                    return

            visit(init)
            return

        for k, v in vars(node).items():
            if k in ("range", "loc", "type"):
                continue
            visit(v)

    visit(program)
    return instances


def _collect_this_props(program, src: str) -> Dict[str, Dict[str, Any]]:
    """유닛(파일 전체) 트리를 스캔해 `this.PROP = <값>` 대입에서 PROP → {value, static}
    매핑을 만든다(예: `initialize(){ this.contextRoot = ...; }`에서 설정한 값을 다른
    메서드가 나중에 읽는 패턴 — 같은 클래스/객체의 메서드들은 흔히 같은 인스턴스를
    공유하므로 _collect_axios_instances와 동일하게 함수 경계를 넘어 유닛 전체에서 수집한다.

    이름이 같은 속성이 서로 무관한 클래스에 있어도 구분하지 않고 하나로 합친다(동일 이름은
    최초 발견만 채택 — 다른 dataflow 추적과 동일한 흐름 비민감 근사치, axios_instances와
    같은 트레이드오프). 우변 재구성 시 this_props를 넘기지 않으므로(자기 자신을 가리키는
    `this.x = this.x || ...` 같은 순환 없이) 원문 슬라이스로만 폴백된다 — _reconstruct_str
    쪽 this.PROP 특수 처리가 여기서는 비활성 상태로 안전하게 남는다.
    """
    props: Dict[str, Dict[str, Any]] = {}

    def visit(node) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        t = getattr(node, "type", None)
        if t is None:
            return

        if t == "AssignmentExpression" and node.operator == "=":
            left = node.left
            if getattr(left, "type", None) == "MemberExpression" and not left.computed \
                    and getattr(left.object, "type", None) == "ThisExpression" \
                    and getattr(left.property, "type", None) == "Identifier":
                name = left.property.name
                if name not in props:
                    text, is_static = _reconstruct_str(node.right, set(), {}, src)
                    props[name] = {"value": text, "static": is_static}
            visit(node.right)
            return

        for k, v in vars(node).items():
            if k in ("range", "loc", "type"):
                continue
            visit(v)

    visit(program)
    return props


def _join_url(base: str, path: str) -> str:
    """axios 인스턴스 baseURL과 상대 경로를 결합(이중 슬래시 정리).

    path가 이미 절대 URL/프로토콜 상대 URL(`http://`·`https://`·`//`로 시작)이면 axios의
    실제 동작과 동일하게 baseURL을 무시하고 path 그대로 사용한다.
    """
    if not base:
        return path
    if re.match(r"^([a-zA-Z][\w+.-]*:)?//", path):
        return path
    if not path:
        return base
    return base.rstrip("/") + "/" + path.lstrip("/")


def _match_sink_kind(callee_node, axios_instances: Optional[Dict[str, Any]] = None,
                      shadowed: Optional[set] = None,
                      axios_aliases: Optional[Dict[str, Any]] = None) -> Optional[Tuple[str, str]]:
    """CallExpression의 callee가 HTTP 요청 sink 패턴과 일치하면 (kind, 기본 method)를 반환.

    axios_instances가 주어지면(같은 유닛에서 `_collect_axios_instances`로 수집된 axios
    인스턴스 테이블) 그 인스턴스 변수에 대한 `.get`/`.post`/`.put`/`.delete`/`.patch`/`.request`
    호출도 axios/axios-short sink로 인식한다. shadowed(현재 스코프에서 파라미터·지역변수로
    이미 쓰인 이름 집합)에 포함된 이름은 인스턴스 테이블보다 우선해 오탐을 방지한다
    (지역 스코프가 같은 이름을 다른 값으로 가리는 경우).

    axios_aliases가 주어지면(같은 유닛에서 `_collect_axios_aliases`로 수집된 import/require
    별칭 정보) `import ax from 'axios'`/`const n = require('axios')`로 받은 로컬 변수명을
    "axios"로 정규화해 위 axios 패턴에 그대로 매칭시키고("roots"), `import {get} from 'axios'`
    처럼 메서드 하나만 구조분해 임포트한 경우의 단독 호출(`get(...)`)도 axios-short sink로
    인식한다("methods"). 둘 다 shadowed에 포함된 이름은 제외(지역 스코프 우선).

    HTTP 요청이 아니라 화면 내비게이션·콘텐츠 로딩이지만 코드가 프로그램적으로 서버
    URL을 요청 가능한 형태로 조립한다는 점에서 동일한 공격표면으로 취급하는 sink도
    이름 패턴으로 함께 인식한다: `window.open(url)`류(kind="window-open"),
    `location.replace/assign(url)`류(kind="navigate"), iframe/팝업 컨트롤 로더 메서드
    (kind="content-url", `_IFRAME_CONTENT_URL_METHODS`). `location.href = url` 대입과
    `<formRef>.action = url; ...; <formRef>.submit()` 폼 변조는 CallExpression이 아니라
    AssignmentExpression 기반이라 `_analyze_dataflow`에서 별도로 처리한다.
    """
    path = _callee_path(callee_node)
    if not path:
        return None
    if axios_aliases and axios_aliases.get("roots") and path[0] in axios_aliases["roots"] \
            and (not shadowed or path[0] not in shadowed):
        path = ["axios"] + path[1:]  # import/require 별칭을 리터럴 axios 호출과 동일하게 취급
    if path == ["fetch"]:
        return ("fetch", "GET")
    # window.open(url) 등 새 창 내비게이션 — 아래 일반 `.open` xhr 판정보다 먼저 검사해야
    # arg0가 HTTP 메서드 리터럴이 아니라는 이유로 xhr 판정에서 조용히 폐기되지 않는다.
    if len(path) == 2 and path[0] in _WINDOW_OPEN_ROOTS and path[1] == "open":
        return ("window-open", "GET")
    if len(path) >= 2 and path[-1] == "open":
        return ("xhr", "")  # 실제 method는 arg0 리터럴 검증 후 확정 (extraction 단계)
    if len(path) == 2 and path[0] in _JQUERY_ROOTS and path[1] == "ajax":
        return ("jquery-ajax", "GET")
    if len(path) == 2 and path[0] in _JQUERY_ROOTS and path[1] in _JQUERY_SHORT_METHODS:
        return ("jquery-short", _JQUERY_SHORT_METHODS[path[1]])
    if path == ["axios"] or path == ["axios", "request"]:
        return ("axios", "GET")
    if len(path) == 2 and path[0] == "axios" and path[1] in _AXIOS_SHORT_METHODS:
        return ("axios-short", _AXIOS_SHORT_METHODS[path[1]])
    if axios_instances and len(path) == 2 and path[0] in axios_instances \
            and (not shadowed or path[0] not in shadowed):
        if path[1] == "request":
            return ("axios", "GET")
        if path[1] in _AXIOS_SHORT_METHODS:
            return ("axios-short", _AXIOS_SHORT_METHODS[path[1]])
    if axios_aliases and axios_aliases.get("methods") and len(path) == 1 \
            and path[0] in axios_aliases["methods"] and (not shadowed or path[0] not in shadowed):
        # import {get} from 'axios' 처럼 메서드 하나만 구조분해 임포트한 경우의 단독 호출
        return ("axios-short", axios_aliases["methods"][path[0]])
    if path == ["navigator", "sendBeacon"]:
        return ("beacon", "POST")
    # location.replace(url)/location.assign(url) — window.location/document.location 등
    # 접두 경로가 붙어도 마지막 두 세그먼트만으로 판별한다. 인자 개수(1개) 검증은 URL
    # 인자에 접근 가능한 _extract_endpoint_info 단계에서 한다(String.replace(pattern, repl)
    # 같은 무관 호출과의 구분은 "객체 경로가 정확히 location으로 끝나는지"로 충분히 좁혀진다).
    if len(path) >= 2 and path[-2] == "location" and path[-1] in ("replace", "assign"):
        return ("navigate", "GET")
    if path[-1] in ("transaction", "gfnTransaction"):
        # this.gfnTransaction(...)(멤버 호출) / gfnTransaction(...)(단독 호출) / obj.transaction(...) 모두 포함
        return ("nexacro", "POST")  # 투비소프트 Nexacro 관례상 POST로 간주
    if path[-1] in _IFRAME_CONTENT_URL_METHODS:
        # iframe/팝업 컨트롤에 URL을 로드하는 프레임워크 메서드(예: DevExpress
        # ASPxClientPopupControl.SetContentUrl) — 객체 변수명과 무관하게 메서드명으로 판별
        # (위 nexacro와 동일한 방식).
        return ("content-url", "GET")
    return None


def _match_new_sink_kind(callee_node) -> Optional[Tuple[str, str]]:
    """NewExpression(`new WebSocket(url)` 등)의 callee가 sink 패턴과 일치하면 (kind, method) 반환."""
    path = _callee_path(callee_node)
    if path == ["WebSocket"]:
        return ("websocket", "WS")
    if path == ["EventSource"]:
        return ("eventsource", "SSE")
    return None


def _looks_like_url_shape(text: str) -> bool:
    """재구성된 문자열이 URL/경로처럼 생겼는지 판별(이름 무관 휴리스틱).

    절대경로(`/...`)·프로토콜(`http://`/`https://`)·프로토콜 상대(`//...`)는 접두사만으로,
    그 외에는 "word/word" 형태의 상대경로 세그먼트 구조(`_REL_PATH_SHAPE_RE`)로 판별한다.
    공백이 섞이면(문장·설명 텍스트) URL이 아닌 것으로 간주한다.

    선행하는 `{name}` 플레이스홀더(레거시 코드의 `var rootURL; rootURL = '/'+...+'/';`처럼
    해소하지 못한 전역 베이스경로 등, `_reconstruct_str`이 미해소 식별자에 붙이는 표기)는
    `_normalize_display_path`와 동일한 규칙으로 무시하고 그 뒤 나머지로 형태를 판별한다 —
    `{rootURL}Pages/.../x.aspx`처럼 베이스경로만 미해소인 경로도 후보로 인정해, 이름 패턴이
    없는 커스텀 HTTP 래퍼가 전역 베이스경로를 쓴다는 이유만으로 후보에서 누락되지 않게 한다.
    """
    if not text or any(c.isspace() for c in text):
        return False
    m = _PLACEHOLDER_RE.match(text)
    body = text[m.end():] if m else text
    if body.startswith(("/", "http://", "https://", "//")):
        return True
    return bool(_REL_PATH_SHAPE_RE.match(body))


def _is_url_shape_source_node(node) -> bool:
    """이 노드가 _reconstruct_str에서 실제로 문자열 값을 조립하는 노드 타입인지 판별
    (Literal/TemplateLiteral/문자열 '+' 연결/식별자). 그 외 타입(산술식 등)은 원문
    슬라이스로 폴백되는데, 이 원문에 우연히 '/'가 섞이면(예: `a/8` 나눗셈) URL-형태
    휴리스틱이 이를 경로로 오인할 수 있어 애초에 URL 후보 판정 대상에서 제외한다."""
    t = getattr(node, "type", None)
    if t in ("Literal", "TemplateLiteral", "Identifier"):
        return True
    return t == "BinaryExpression" and getattr(node, "operator", None) == "+"


def _match_url_shape_candidate(node, params: set, local_inits: Dict[str, Any], src: str,
                                this_props: Optional[Dict[str, Any]] = None,
                                local_props: Optional[Dict[str, Dict[str, Any]]] = None):
    """CallExpression이 확정 sink는 아니지만 URL-형태 인자를 가진 커스텀 sink 후보인지 판별.

    확정 sink(`_match_sink_kind`)가 이름 패턴으로 실패한 경우에만 호출된다(호출자 쪽에서
    상호 배타 보장). callee 말단이 순수 문자열/배열 빌트인이거나 `require`면 제외
    (`_URL_SHAPE_EXCLUDE_TAILS`). 인자를 앞에서부터 훑어 실제 문자열 조립 노드
    (`_is_url_shape_source_node`) 중 첫 URL-형태 인자를 URL로 채택하고, 나머지 인자 중
    객체 리터럴(속성-대입으로 조립된 것 포함)이 있으면 best-effort로 전달 파라미터를 추출한다.

    반환: (url_node, extra_params) 또는 후보가 아니면 None.
    """
    local_props = local_props or {}
    if _callee_name(node.callee) in _URL_SHAPE_EXCLUDE_TAILS:
        return None
    url_node = None
    for a in node.arguments:
        if not _is_url_shape_source_node(a):
            continue
        text, _ = _reconstruct_str(a, params, local_inits, src, this_props=this_props)
        if _looks_like_url_shape(text):
            url_node = a
            break
    if url_node is None:
        return None
    extra: List[Dict[str, Any]] = []
    for a in node.arguments:
        if a is url_node or getattr(a, "type", None) in _FUNC_TYPES:
            continue
        if _is_object_like(a, local_inits, local_props):
            extra += _extract_data_params(a, params, local_inits, src, "body", this_props, local_props)
    return (url_node, extra)


# ── 동적 <form> 문자열 조립 탐지 (JS로 조립되는 결제/SSO 리다이렉트 폼 등) ─────────────
#
# `_ScriptCollector`(HTML 파서, 아래 "파일 어댑터: HTML" 절)는 소스 문서에 실제로 존재하는
# 정적 `<form action="...">`만 본다. 하지만 실무 코드에서는
# `$("<form action='"+url+"'>...</form>")`처럼 JS 문자열로 HTML을 조립해 DOM에 붙이고
# `.submit()`하는 관용구가 흔하다(예: 결제/SSO 리다이렉트 폼) — 이 문자열은 HTML 파서
# 단계에 아예 나타나지 않아(순수 JS 문자열 리터럴) 정적 form 탐지가 놓친다. 그래서 AST
# 레벨에서 `$(...)`/`jQuery(...)` 단독 호출의 문자열 인자를 재구성해 `<form action=...>`
# 마크업이 포함됐는지 별도로 검사한다. `.submit()` 호출 여부는 추적하지 않는다(문장 간
# 흐름 추적이 이 모듈의 단일 패스 구조와 맞지 않고, `<form action=...>` 마크업을 문자열로
# 조립하는 것 자체가 이미 충분히 구체적인 신호라 오탐 위험이 낮다 — 값을 잃는 것보다
# 여분의 후보가 남는 쪽을 택하는 이 모듈의 기존 정책과 동일).

class _InlineFormParser(_htmlparser.HTMLParser):
    """완전한 HTML 문서가 아닌 임의 문자열 조각에서 첫 <form> 하나만 관대하게 추출.

    `_ScriptCollector`와 달리 <script>/인라인 이벤트 핸들러는 다루지 않고 form 하나만 본다.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.form: Optional[Dict[str, Any]] = None
        self._active: Optional[Dict[str, Any]] = None

    def _start(self, tag: str, attrs) -> None:
        if self.form is not None:
            return  # 문자열 안에 form이 여러 개여도 첫 번째만 채택(관례상 흔치 않은 경우)
        tag_l = tag.lower()
        attrs_d = dict(attrs)
        if tag_l == "form" and self._active is None:
            self._active = {
                "action": (attrs_d.get("action") or "").strip(),
                "method": (attrs_d.get("method") or "GET").strip().upper() or "GET",
                "params": [],
            }
        elif tag_l in _HTML_FORM_FIELD_TAGS and self._active is not None:
            name = (attrs_d.get("name") or "").strip()
            if name:
                self._active["params"].append(
                    {"name": name, "value": attrs_d.get("value") or "", "in": "form", "static": True})

    def handle_starttag(self, tag, attrs) -> None:
        self._start(tag, attrs)

    def handle_startendtag(self, tag, attrs) -> None:
        self._start(tag, attrs)  # 자기 종료 태그(<form .../>, 비표준이지만 관대하게 허용)
        if tag.lower() == "form":
            self.handle_endtag(tag)

    def handle_endtag(self, tag) -> None:
        if tag.lower() == "form" and self._active is not None:
            self.form = self._active
            self._active = None


def _parse_inline_form_html(text: str) -> Optional[Dict[str, Any]]:
    """문자열 조각 안의 첫 `<form action=...>`을 {action, method, params}로 추출.

    action이 비어있거나 `javascript:` 의사 URL이면(현재 페이지 제출/JS가 직접 처리) None
    — `_ScriptCollector`의 정적 form 처리(위 참고)와 동일 기준.
    """
    parser = _InlineFormParser()
    try:
        parser.feed(text)
    except Exception:
        pass
    form = parser.form or parser._active  # 닫는 태그가 소스에 없어도(잘린 슬라이스 등) 열린 폼은 활용
    if not form:
        return None
    action = form["action"]
    if not action or action.lower().startswith("javascript:"):
        return None
    return form


def _match_dynamic_form_sink(node, params: set, local_inits: Dict[str, Any], src: str,
                              this_props: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """CallExpression이 `$(...)`/`jQuery(...)` 단독 호출로 문자열을 조립하며 그 안에
    `<form action=...>` 마크업이 포함된 경우를 탐지한다(동적 조립 <form> — 위 설명 참고).

    확정 sink(`_match_sink_kind`)가 실패한 경우에만 호출자 쪽에서 시도한다 — bare `$(...)`
    (경로 길이 1)는 fetch/xhr/jquery-ajax 등 기존 sink 패턴(모두 길이 ≥2 요구)과 애초에
    겹치지 않아 상호 배타는 구조적으로 보장된다.

    반환: {action, method, params, url_expr, static} 또는 매치 아니면 None.
    """
    path = _callee_path(node.callee)
    if not path or len(path) != 1 or path[0] not in _JQUERY_ROOTS:
        return None
    if not node.arguments:
        return None
    arg0 = node.arguments[0]
    if not _is_url_shape_source_node(arg0):  # Literal/TemplateLiteral/문자열 '+' 연결/식별자만
        return None
    text, static = _reconstruct_str(arg0, params, local_inits, src, this_props=this_props)
    if "<form" not in text.lower():
        return None  # 사전 필터 — 대다수의 평범한 $("<div>...") 호출을 파싱 없이 배제
    form = _parse_inline_form_html(text)
    if form is None:
        return None
    form["url_expr"] = _slice(src, arg0)
    form["static"] = static  # 조립 문자열 전체의 정적 여부(action/params 값도 이 텍스트에서 나옴)
    return form


def _extract_endpoint_info(kind: str, default_method: str, node, params: set,
                            local_inits: Dict[str, Any], src: str,
                            this_props: Optional[Dict[str, Any]] = None,
                            local_props: Optional[Dict[str, Dict[str, Any]]] = None):
    """sink 종류별로 (method, url_node, 추가 전달 파라미터 목록)을 추출. 유효하지 않으면 None.

    URL 노드를 확정할 수 없거나(설정 객체에 url 키가 없음 등) XHR의 arg0가 실제 HTTP 메서드
    리터럴이 아니면(예: window.open()·dialog.open() 오탐 방지) None을 반환해 sink 판정을 취소한다.

    설정 객체(config/opts) 인자는 `_merged_object_props`로 조회한다 — 객체 리터럴 속성뿐
    아니라 `var t={}; t.url=...` 같은 속성-대입 조립 패턴(local_props)도 함께 인식하므로,
    이 형태만으로 인해 sink 판정 자체가 취소되던 미탐이 해소된다.
    """
    args = node.arguments
    local_props = local_props or {}

    if kind == "fetch":
        if not args:
            return None
        url_node = args[0]
        method = default_method
        extra: List[Dict[str, Any]] = []
        if len(args) > 1:
            opts = _merged_object_props(args[1], local_inits, local_props)
            m = opts.get("method")
            if m is not None:
                mv, _ = _reconstruct_str(m, params, local_inits, src, this_props=this_props)
                if mv:
                    method = mv.upper()
            body = opts.get("body")
            if body is not None:
                extra = _extract_data_params(body, params, local_inits, src, "body", this_props, local_props)
        return (method, url_node, extra)

    if kind == "xhr":
        if len(args) < 2:
            return None
        m_node = args[0]
        if getattr(m_node, "type", None) != "Literal" or not isinstance(m_node.value, str):
            return None
        method = m_node.value.upper()
        if method not in _HTTP_METHODS:
            return None
        return (method, args[1], [])

    if kind == "jquery-ajax":
        # $.ajax(settings) 또는 $.ajax(url, settings) 두 형태 모두 지원
        cfg_node = args[0] if args else None
        url_node = None
        if cfg_node is not None and not _is_object_like(cfg_node, local_inits, local_props):
            url_node = args[0]
            cfg_node = args[1] if len(args) > 1 else None
        cfg = _merged_object_props(cfg_node, local_inits, local_props) if cfg_node is not None else {}
        if "url" in cfg:
            url_node = cfg["url"]
        if url_node is None:
            return None
        method = default_method
        extra = []
        m = cfg.get("type", cfg.get("method"))
        if m is not None:
            mv, _ = _reconstruct_str(m, params, local_inits, src, this_props=this_props)
            if mv:
                method = mv.upper()
        data = cfg.get("data")
        if data is not None:
            extra = _extract_data_params(data, params, local_inits, src, "body", this_props, local_props)
        return (method, url_node, extra)

    if kind == "jquery-short":
        if not args:
            return None
        url_node = args[0]
        extra = []
        if len(args) > 1 and getattr(args[1], "type", None) not in _FUNC_TYPES:
            extra = _extract_data_params(args[1], params, local_inits, src, "body", this_props, local_props)
        return (default_method, url_node, extra)

    if kind == "axios":
        if not args or not _is_object_like(args[0], local_inits, local_props):
            return None
        cfg = _merged_object_props(args[0], local_inits, local_props)
        url_node = cfg.get("url")
        if url_node is None:
            return None
        method = default_method
        m = cfg.get("method")
        if m is not None:
            mv, _ = _reconstruct_str(m, params, local_inits, src, this_props=this_props)
            if mv:
                method = mv.upper()
        extra = []
        p = cfg.get("params")
        if p is not None:
            extra += _extract_data_params(p, params, local_inits, src, "query", this_props, local_props)
        d = cfg.get("data")
        if d is not None:
            extra += _extract_data_params(d, params, local_inits, src, "body", this_props, local_props)
        return (method, url_node, extra)

    if kind == "axios-short":
        if not args:
            return None
        url_node = args[0]
        extra = []
        if len(args) > 1:
            if default_method == "GET":
                if _is_object_like(args[1], local_inits, local_props):
                    p = _merged_object_props(args[1], local_inits, local_props).get("params")
                    if p is not None:
                        extra = _extract_data_params(p, params, local_inits, src, "query", this_props, local_props)
            else:
                extra = _extract_data_params(args[1], params, local_inits, src, "body", this_props, local_props)
        return (default_method, url_node, extra)

    if kind == "beacon":
        if not args:
            return None
        url_node = args[0]
        extra = []
        if len(args) > 1:
            extra = _extract_data_params(args[1], params, local_inits, src, "body", this_props, local_props)
        return (default_method, url_node, extra)

    if kind == "nexacro":
        # 관례: transaction(id, url, inDataset, outDataset, argument, callback, ...)
        if len(args) < 2:
            return None
        url_node = args[1]
        extra = []
        if len(args) > 4:
            extra = _extract_data_params(args[4], params, local_inits, src, "body", this_props, local_props)
        for idx, label in ((2, "inDataset"), (3, "outDataset")):
            if len(args) > idx:
                v, is_static = _reconstruct_str(args[idx], params, local_inits, src, this_props=this_props)
                if v:
                    extra.append({"name": label, "value": v, "in": "dataset", "static": is_static})
        return (default_method, url_node, extra)

    if kind == "window-open":
        # window.open(url, target?, features?) — url 외 인자는 요청 파라미터가 아니므로 무시.
        if not args:
            return None
        return (default_method, args[0], [])

    if kind == "navigate":
        # location.replace(url)/location.assign(url) — 인자가 정확히 1개일 때만 신뢰한다
        # (오탐 방지: "객체 경로가 location으로 끝남" 조건과 함께 걸어 이중으로 좁힌다).
        if len(args) != 1:
            return None
        return (default_method, args[0], [])

    if kind == "content-url":
        # iframe/팝업 컨트롤 로더(예: SetContentUrl). 'about:blank'로 리셋하는 관용구(팝업
        # 닫힘 처리 등)는 정적 form과 동일 기준으로 제외한다.
        if not args:
            return None
        url_node = args[0]
        if getattr(url_node, "type", None) == "Literal" and isinstance(url_node.value, str):
            v = url_node.value.strip().lower()
            if v in ("", "about:blank") or v.startswith("javascript:"):
                return None
        return (default_method, url_node, [])

    return None


def _dedup_keep_order(pairs: List[Tuple[str, bool]]) -> List[Tuple[str, bool]]:
    """(text, static) 목록에서 text 기준 중복 제거(첫 등장 순서 유지)."""
    seen: set = set()
    out: List[Tuple[str, bool]] = []
    for text, static in pairs:
        if text in seen:
            continue
        seen.add(text)
        out.append((text, static))
    return out


def _guard_paths_compatible(a: List[Dict[str, Any]], b: List[Dict[str, Any]]) -> bool:
    """두 가드 경로가 같은 실행에서 동시에 성립할 수 있는지(모순되지 않는지) 판별.

    같은 결정 지점(if/삼항의 (cond, line) 짝, 또는 switch의 같은 group)에서 kind/cond가
    다르면(if vs else, 서로 다른 case) 상호배타적인 형제 분기이므로 모순(False) — 삼항
    체인의 서로 다른 갈래에서 나온 재대입이 하나의 실행 경로에서 잘못 겹쳐 결합되는
    교차오염을 막는 핵심 판별이다. 겹치는 지점이 전혀 없거나 완전히 같은 kind로만
    겹치면 호환(True, 같은 경로거나 서로 무관한 독립 조건)."""
    for ga in a:
        for gb in b:
            if ga["kind"] == "case" and gb["kind"] == "case":
                if ga.get("group") == gb.get("group") and ga["cond"] != gb["cond"]:
                    return False
            elif ga["cond"] == gb["cond"] and ga["line"] == gb["line"] and ga["kind"] != gb["kind"]:
                return False
    return True


def _reassignment_variants_for_identifier(node, params: set, local_inits: Dict[str, Any],
                                           var_events: Dict[str, List[Dict[str, Any]]], src: str,
                                           this_props: Optional[Dict[str, Any]]) -> List[Tuple[str, bool]]:
    """식별자 노드(Identifier) `node`가 선언 이후 조건부(if/삼항/논리연산/switch 등,
    guard_stack 기준) 재대입(`=`/`+=`)을 거쳤다면 가능한 최종 값을 모두 열거한다(레거시
    로그인 폼의 `e=base; cond ? e+="a" : e+="b";` 같은 분기별 URL 조립 패턴 대응 — G2/G3).

    각 후보를 (텍스트, static, 그 값이 성립하는 가드 경로) 3-튜플로 관리하며, 재대입
    이벤트를 프로그램 순서대로 적용한다:
      - 가드 없는(무조건) 이벤트는 현재 후보 전체에 적용한다(`+=`는 접미사 결합, `=`는 완전
        대체 후 단일화 — 무조건 실행되므로 이전 대안들을 모두 덮어써도 안전하다).
      - 가드가 있는(조건부) 이벤트는 자신의 가드 경로와 모순되지 않는(`_guard_paths_compatible`)
        기존 후보에서만 분기해 새 후보를 추가하고, 기존 후보는 그대로 남긴다("그 분기를
        타지 않았을 때의 값"). 모순되는 형제 분기의 값 위에는 절대 겹쳐 적용하지 않으므로
        삼항 체인처럼 여러 개의 상호배타 분기가 있어도 값이 뒤섞이지 않는다.
    변수에 재대입 이벤트가 전혀 없으면(가장 흔한 경우 — 이 함수 스코프에 선언이 없는
    외부 스코프 식별자 포함) node 자체를 `_reconstruct_str`에 그대로 위임해 기존과 동일한
    단일 값(1-hop 전파용 "{name}" 플레이스홀더 포함)을 반환해 호환성을 유지한다. 결과는
    `_URL_BRANCH_CAP`으로 상한을 두고 중복은 제거한다.
    """
    name = node.name
    events = var_events.get(name) or []
    if not events:
        return [_reconstruct_str(node, params, local_inits, src, this_props=this_props)]

    base_text, base_static = _reconstruct_str(events[0]["right"], params, local_inits, src, this_props=this_props)
    plain_base = (base_text, base_static, events[0]["guards"])
    values: List[Tuple[str, bool, List[Dict[str, Any]]]] = [plain_base]
    saw_guarded = False

    def _dedup3(triples):
        seen: set = set()
        out = []
        for text, static, gp in triples:
            if text in seen:
                continue
            seen.add(text)
            out.append((text, static, gp))
        return out

    for ev in events[1:]:
        ev_text, ev_static = _reconstruct_str(ev["right"], params, local_inits, src, this_props=this_props)
        ev_guards = ev["guards"]
        if not ev_guards:
            # 무조건 재대입 — 이전까지의 모든 후보에 적용(+=는 결합, =는 완전 대체 후 단일화).
            if ev["op"] == "+=":
                values = [(vt + ev_text, vs and ev_static, gp) for vt, vs, gp in values]
            else:
                values = [(ev_text, ev_static, [])]
                plain_base = values[0]
        else:
            saw_guarded = True
            compatible = [v for v in values if _guard_paths_compatible(v[2], ev_guards)] or [values[0]]
            branched = [
                (vt + ev_text, vs and ev_static, gp + ev_guards) if ev["op"] == "+="
                else (ev_text, ev_static, ev_guards)
                for vt, vs, gp in compatible
            ]
            values = _dedup3(values + branched)
        if len(values) >= _URL_BRANCH_CAP:
            break

    if saw_guarded and len(values) > 1:
        # 분기 전 값(plain_base)이 경로 형태가 아니면(예: "{contextRoot}"만 남아 경로가 전혀
        # 없음) 실제 엔드포인트로서 의미가 없는 잡음이므로, 경로를 포함하는 다른 후보가
        # 있으면 제거한다(어느 분기도 예외 없이 재대입하는 완전분기인지 증명하지는 않는
        # 대신, 값을 잃지 않는 선에서의 잡음 억제).
        plain_text = plain_base[0]
        if not (plain_text.startswith(("/", "http://", "https://", "//")) or "/" in plain_text):
            values = [v for v in values if v != plain_base] or values

    return [(t, s) for t, s, _ in _dedup3(values)][:_URL_BRANCH_CAP]


def _cross_join_variants(parts: List[List[Tuple[str, bool]]]) -> List[Tuple[str, bool]]:
    """여러 자리(각각 (text, static) 후보 목록)를 순서대로 이어붙인 데카르트 곱을 만든다
    (문자열 `+` 연결·템플릿 리터럴처럼 URL이 여러 조각을 순서대로 결합해 만들어질 때, 그
    중 한 조각만 분기해도 전체 조합을 놓치지 않도록 함). 자리가 하나도 분기하지 않으면
    (모든 자리가 1개짜리) 결과도 정확히 1개 — 기존 동작과 100% 호환된다. `_URL_BRANCH_CAP`
    에서 즉시 멈춰 조합 폭발을 막는다(자리 개수·자리별 분기 수가 많아도 상한 안에서 정지)."""
    combos: List[Tuple[str, bool]] = [("", True)]
    for part in parts:
        if len(combos) >= _URL_BRANCH_CAP:
            break
        next_combos: List[Tuple[str, bool]] = []
        for pt, ps in combos:
            for vt, vs in part:
                next_combos.append((pt + vt, ps and vs))
                if len(next_combos) >= _URL_BRANCH_CAP:
                    break
            if len(next_combos) >= _URL_BRANCH_CAP:
                break
        combos = next_combos
    return _dedup_keep_order(combos)[:_URL_BRANCH_CAP]


def _enumerate_url_node_variants(url_node, params: set, local_inits: Dict[str, Any],
                                  var_events: Dict[str, List[Dict[str, Any]]], src: str,
                                  this_props: Optional[Dict[str, Any]],
                                  _depth: int = 0) -> List[Tuple[str, bool]]:
    """URL 인자 노드 자체에서 분기(삼항/논리연산/변수 재대입)를 재귀적으로 열거해
    (text, static) 목록을 반환한다. 분기가 전혀 없으면 항상 정확히 1개짜리 목록(기존
    `_reconstruct_str` 결과와 동일)이라 기존 동작과 100% 호환된다. `_URL_BRANCH_CAP`·재귀
    깊이 상한(6, 다른 _reconstruct_str류와 동일)으로 조합 폭발을 막는다.

    `+` 연결/템플릿 리터럴처럼 여러 조각을 이어붙이는 노드는 각 조각을 재귀적으로 열거한
    뒤 `_cross_join_variants`로 조합한다 — 분기 변수가 `this.contextRoot + n`처럼 URL의
    일부에만 묻혀 있어도(삼항/변수 재대입이 최상위 노드가 아니어도) 값이 유실되지 않는다.
    """
    if _depth > 6 or url_node is None:
        return [_reconstruct_str(url_node, params, local_inits, src, this_props=this_props)]

    t = getattr(url_node, "type", None)

    if t == "ConditionalExpression":
        # 삼항은 문법상 반드시 둘 중 하나만 실행되므로(else 누락 불가) 두 분기의 열거
        # 결과만 합치면 그대로 완전(exhaustive)하다 — 별도의 "분기 전 값"이 존재하지 않는다.
        left = _enumerate_url_node_variants(url_node.consequent, params, local_inits, var_events,
                                             src, this_props, _depth + 1)
        right = _enumerate_url_node_variants(url_node.alternate, params, local_inits, var_events,
                                              src, this_props, _depth + 1)
        return _dedup_keep_order(left + right)[:_URL_BRANCH_CAP]

    if t == "LogicalExpression" and url_node.operator in ("&&", "||"):
        # 참/거짓을 정확히 평가하지 않고 양쪽 다 URL 후보로 안전하게 포함(과다포함 방향 근사).
        left = _enumerate_url_node_variants(url_node.left, params, local_inits, var_events,
                                             src, this_props, _depth + 1)
        right = _enumerate_url_node_variants(url_node.right, params, local_inits, var_events,
                                              src, this_props, _depth + 1)
        return _dedup_keep_order(left + right)[:_URL_BRANCH_CAP]

    if t == "BinaryExpression" and url_node.operator == "+":
        left = _enumerate_url_node_variants(url_node.left, params, local_inits, var_events,
                                             src, this_props, _depth + 1)
        right = _enumerate_url_node_variants(url_node.right, params, local_inits, var_events,
                                              src, this_props, _depth + 1)
        return _cross_join_variants([left, right])

    if t == "TemplateLiteral":
        slots: List[List[Tuple[str, bool]]] = []
        exprs = list(url_node.expressions)
        for i, q in enumerate(url_node.quasis):
            qtext = q.value.cooked if q.value and q.value.cooked is not None else ""
            slots.append([(qtext, True)])
            if i < len(exprs):
                slots.append(_enumerate_url_node_variants(exprs[i], params, local_inits, var_events,
                                                            src, this_props, _depth + 1))
        return _cross_join_variants(slots)

    if t == "Identifier" and url_node.name not in params:
        # 함수 파라미터는 제외(기존 "{name}" 플레이스홀더 표기를 그대로 유지) — 지역변수만
        # 재대입 이벤트(var_events)를 열거 대상으로 삼는다.
        return _reassignment_variants_for_identifier(url_node, params, local_inits,
                                                       var_events, src, this_props)

    return [_reconstruct_str(url_node, params, local_inits, src, this_props=this_props)]


def _build_endpoints(kind: str, method: str, url_node, extra_params: List[Dict[str, Any]],
                      params: set, local_inits: Dict[str, Any], src: str, line: int,
                      file: str, unit_label: str, func_id: Optional[str],
                      base_url: Optional[Tuple[str, bool]] = None,
                      guards: Optional[List[Dict[str, Any]]] = None,
                      this_props: Optional[Dict[str, Any]] = None,
                      var_events: Optional[Dict[str, List[Dict[str, Any]]]] = None) -> List[Dict[str, Any]]:
    """URL 노드와 추가 파라미터로부터 엔드포인트 레코드를 조립.

    URL 노드 자체(또는 그것이 가리키는 변수)가 조건부로 여러 값을 가질 수 있으면(삼항/
    논리연산/변수 재대입 분기) `_enumerate_url_node_variants`로 열거해 URL별로 레코드를
    하나씩 발행한다 — 분기가 없으면(압도적 다수) 기존과 완전히 동일하게 정확히 1개만
    반환해 하위 호환된다.

    base_url이 주어지면(axios 인스턴스 sink) 재구성된 각 경로 앞에 `_join_url`로 결합해
    풀 URL을 만든다 — 인스턴스의 baseURL이 정적이 아니면(플레이스홀더 포함) static 판정에도 반영된다.

    guards가 주어지면(호출 시점의 가드 스택 스냅샷) 이 엔드포인트가 어떤 조건 하에서만
    도달 가능한지를 기록한다 — 클라이언트 단 인증우회·강제호출 가능 엔드포인트 판단 근거.
    """
    var_events = var_events or {}
    url_variants = _enumerate_url_node_variants(url_node, params, local_inits, var_events, src, this_props)
    url_expr = _slice(src, url_node)
    out: List[Dict[str, Any]] = []
    for url_text, url_static in url_variants:
        if base_url is not None:
            base_text, base_static = base_url
            url_text = _join_url(base_text, url_text)
            url_static = url_static and base_static
        query_params = _split_url_query(url_text)
        all_params = query_params + extra_params
        static = url_static and all(p["static"] for p in all_params)
        out.append({
            "method": method, "url": url_text, "url_expr": url_expr,
            "kind": kind, "file": file, "unit": unit_label, "line": line,
            "func_id": func_id, "static": static, "params": all_params, "variants": [],
            "guards": guards or [],
        })
    return out


def _normalize_display_path(url: str) -> str:
    """엔드포인트 url(원문 재구성 결과, `_reconstruct_str`/`_build_endpoints`가 만든 값)에서
    화면 표시에 혼란을 주는 앞쪽 잔재를 제거한 표시용 경로를 반환한다.

    `url` 필드 자체는 절대 변경하지 않는다(회귀 테스트·N-hop 파라미터 전파 모두 원문
    기준으로 동작) — 이 함수는 순수 문자열 변환이며 결과는 별도 필드(`path`)에만 쓰인다.

    처리하는 잔재는 정확히 두 가지, 앞에서부터 반복 적용한다:
      1) 맨 앞 "{placeholder}" — `this.contextRoot` 등 정적으로 못 푼 값이
         `_reconstruct_str`에서 플레이스홀더로 표기된 경우. 실제 값(슬래시 포함 가능)을
         알 수 없으므로 제거하고 그 뒤의 확정 경로만 남긴다.
      2) 첫 "/" 앞 조각이 "ident.ident2" 형태(멤버식 잔재) — minify 코드의 `i.contextRoot`처럼
         `this.`가 아닌 일반 멤버 접근은 플레이스홀더로 못 감싸져 원문 슬라이스 그대로
         남는다(`_reconstruct_str` 최종 폴백). 단 "gateway.do/x"처럼 알려진 서버 경로
         확장자(`_PATH_SEGMENT_EXT_WHITELIST`)로 끝나면 실제 경로로 보아 보존한다.

    아무 것도 제거하지 않았으면(순수 리터럴 상대/절대경로 — 압도적 다수) 원문을 그대로
    반환한다. 스킴 URL(`http://`/`https://`/`//`)은 첫 "/"가 스킴 구분자 안에 있어 앞
    조각에 "."이 섞이지 않으므로 이 규칙에 자연히 영향받지 않는다.

    한계: 스킴 없이 통짜로 적힌 도메인처럼 보이는 리터럴 조각(예: "cdn.example.com/x")도
    같은 모양이라 잘못 제거될 수 있다 — 표시 전용 필드이고 원문 `url`은 그대로 보존되므로
    데이터 손실은 없다(candidate_endpoints의 URL-형태 판별과 같은 성격의 휴리스틱 트레이드오프).
    """
    if not url:
        return url
    text = url
    changed = False

    while True:
        m = _PLACEHOLDER_RE.match(text)
        if not m:
            break
        text = text[m.end():]
        changed = True

    if not text.startswith(("http://", "https://", "//")):
        slash_idx = text.find("/")
        if slash_idx > 0:
            head = text[:slash_idx]
            if "." in head and head.rsplit(".", 1)[-1].lower() not in _PATH_SEGMENT_EXT_WHITELIST:
                text = text[slash_idx:]
                changed = True

    if changed and text and not text.startswith(("/", "http://", "https://")):
        text = "/" + text

    return text


def _placeholder_origins(ep: Dict[str, Any], by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """엔드포인트의 url/params에 남은 "{name}" 플레이스홀더 각각의 출처를 표기.

    리터럴로 확정 가능한 경우는 이미 `_propagate_endpoint_params`(variants)가 값을 직접
    치환해 보여주므로, 여기서는 "이 이름이 어디서 왔는가"라는 설명 정보만 부가한다
    (치환 자체는 하지 않음 — url/params 원문은 불변).

    name이 대상 함수(ep의 func_id)의 매개변수와 일치하면 "param" 출처로 표기하고, 그
    함수를 호출하는 모든 호출자가 해당 위치에 실제로 넘기는 인자식(재구성된 문자열,
    리터럴이 아니어도 표시 — 예: `row.uid`)을 `_PLACEHOLDER_ORIGIN_ARGS_CAP`개까지 중복
    없이 모아 `from_args`로 담는다. func_id가 없거나 이름이 그 함수의 매개변수가
    아니면(지역/전역/외부 식별자로 끝내 해소되지 않은 경우) "unresolved" 출처로 표기한다.
    """
    names: set = set()
    for m in _PLACEHOLDER_RE.finditer(ep.get("url", "")):
        names.add(m.group(1))
    for p in ep.get("params", []):
        for m in _PLACEHOLDER_RE.finditer(p.get("value", "")):
            names.add(m.group(1))
    if not names:
        return []

    fn = by_id.get(ep.get("func_id")) if ep.get("func_id") else None
    fn_params = fn["params"] if fn else []
    out: List[Dict[str, Any]] = []
    for name in sorted(names):
        if fn and name in fn_params:
            idx = fn_params.index(name)
            from_args: List[str] = []
            seen: set = set()
            for caller_id in fn.get("called_by", []):
                if len(from_args) >= _PLACEHOLDER_ORIGIN_ARGS_CAP:
                    break
                caller = by_id.get(caller_id)
                if not caller:
                    continue
                for call in caller["out_calls"]:
                    if fn["id"] not in call.get("resolved_ids", []):
                        continue
                    if idx < len(call["args"]) and call["args"][idx].get("kind") == "expr":
                        val = call["args"][idx]["value"]
                        if val not in seen:
                            seen.add(val)
                            from_args.append(val)
                            if len(from_args) >= _PLACEHOLDER_ORIGIN_ARGS_CAP:
                                break
            out.append({"name": name, "origin": "param", "func_id": fn["id"], "from_args": from_args})
        else:
            out.append({"name": name, "origin": "unresolved"})
    return out


def _analyze_dataflow(body, params: List[str], src: str, line_offset: int,
                       file: str, unit_label: str, func_id: Optional[str],
                       is_concise_arrow: bool = False,
                       axios_instances: Optional[Dict[str, Any]] = None,
                       axios_aliases: Optional[Dict[str, Any]] = None,
                       this_props: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """함수 본문 하나를 스캔해 지역변수 정의(defs)/반환(returns)/외부호출(out_calls)을 추출.

    axios_instances가 주어지면(같은 유닛에서 수집된 axios.create() 인스턴스 테이블)
    그 인스턴스 변수에 대한 HTTP 메서드 호출도 axios/axios-short sink로 함께 탐지한다.
    axios_aliases가 주어지면(같은 유닛에서 수집된 axios import/require 별칭 테이블)
    그 별칭을 통한 호출도 axios/axios-short sink로 함께 탐지한다(`_match_sink_kind` 참고).
    this_props가 주어지면(같은 유닛에서 수집된 `this.PROP` 대입 테이블, _collect_this_props)
    URL/파라미터 재구성 시 `this.PROP` 읽기도 정적으로 해소한다.

    확정 sink(endpoints)로 이름 패턴이 매칭되지 않은 호출은 URL-형태 휴리스틱
    (_match_url_shape_candidate)으로 저신뢰 후보를 시도해 candidate_endpoints에 담는다
    (이름을 알 수 없는 커스텀 HTTP 래퍼 대응 — 확정 sink와 상호 배타).

    흐름 비민감 근사치: if/else·루프 분기를 모두 순회하되 상호배타성은 구분하지 않는다.
    중첩 함수 정의(FunctionDeclaration/Expression/Arrow)는 경계로 삼아 내려가지 않는다
    — 그 함수는 별도 인벤토리 항목으로 자기 자신의 dataflow를 갖는다.

    설정 객체 조립은 리터럴 인자뿐 아니라 `var t={}; t.url=...`처럼 속성-대입으로
    누적되는 패턴도 local_props(변수명 → {key: value_node})로 함께 추적하고(sink 판정
    자체가 빈 객체로 인해 취소되던 미탐 방지), URL/변수가 조건부(`if`/삼항/논리연산)로
    재대입되면 var_events(변수명 → 재대입 이벤트 목록)를 근거로 도달 가능한 URL을 모두
    열거해(`_build_endpoints`) 분기당 하나씩 별도 엔드포인트로 발행한다.

    HTTP 요청 sink 외에, 코드가 프로그램적으로 서버 URL을 요청 가능한 형태로 조립하는
    화면 내비게이션·폼 제출도 동일한 공격표면으로 보아 확정 endpoints에 함께 담는다:
    `window.open(url)`(kind="window-open")·`location.href=`/`.replace`/`.assign`
    (kind="navigate")·iframe/팝업 컨트롤 로더(kind="content-url", `_match_sink_kind` 참고)는
    이름 패턴으로, `<formRef>.action=url; ...; <formRef>.submit()`처럼 여러 문장에 걸쳐
    기존 DOM 폼을 변조해 제출하는 관용구(kind="form")는 form_action_refs(참조 원문 텍스트 →
    최근 action 대입)로 문장 간 상태를 이어 붙여 탐지한다. 이들 모두 func_id가 있으면
    다른 kind와 동일하게 N-hop 파라미터 전파가 자동 적용된다.
    """
    known = set(params)
    params_set = set(params)  # known과 달리 함수 진입 시 파라미터로 고정(1-hop 전파 대상 판별용)
    local_inits: Dict[str, Any] = {}  # 지역변수명 → 최초 대입 초기값 노드 (URL/파라미터 재구성용, 1단계 인라인)
    # 변수명 → {속성키: 값 노드} — `obj.key=value`/`obj["key"]=value` 형태의 속성-대입 조립
    # 추적(리터럴 없이 빈 객체로 시작해 나중에 채워지는 설정 객체 패턴 대응, _merged_object_props).
    local_props: Dict[str, Dict[str, Any]] = {}
    # 변수명 → 재대입 이벤트 목록({"op": "="|"+=", "right": node, "guards": 가드 스택 스냅샷})
    # — 선언 이후의 모든 대입을 프로그램 순서대로 기록(local_inits와 달리 "최초 대입만"이
    # 아니라 전부 기록). guards 전체 경로를 남기는 이유는 서로 다른 분기(예: 삼항 체인의
    # 세 갈래)에 있는 재대입들이 상호배타적임을 판별해(_guard_paths_compatible) 값이 잘못
    # 교차 결합되는 것을 막기 위함이다. URL 분기 열거(_reassignment_variants_for_identifier)
    # 에서만 사용한다.
    var_events: Dict[str, List[Dict[str, Any]]] = {}
    # 폼 DOM 참조(원문 텍스트로 정규화한 키 — 단순 식별자 `theForm`뿐 아니라 계산 접근이
    # 섞인 `document.forms[0]`도 지원) → 가장 최근 `.action = url` 대입 노드. 여러 문장에
    # 걸쳐 조립되는 `formRef.action = url; ...; formRef.submit()` 관용구(기존 공유 DOM 폼을
    # 재활용하는 레거시 패턴)를 잇는 데 쓰인다 — 마크업을 새로 조립하는 _match_dynamic_form_sink
    # 와 달리 기존 폼의 상태를 변조하는 패턴이 대상이다. local_props와 마찬가지로 흐름
    # 비민감(같은 텍스트 키는 같은 참조로 간주)·함수 스코프 한정(이 함수 밖으로 전파되지 않음).
    form_action_refs: Dict[str, Dict[str, Any]] = {}
    defs: List[Dict[str, Any]] = []
    returns: List[Dict[str, Any]] = []
    out_calls: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    # 확정 sink는 아니지만 URL-형태 인자를 가진 저신뢰 후보(커스텀 HTTP 래퍼 추정) — endpoints와
    # 절대 섞이지 않는 별도 목록(analyze()의 candidate_endpoints로 취합).
    candidate_endpoints: List[Dict[str, Any]] = []
    # 현재 방문 위치를 감싸는 조건 체인(가드) 스택 — if/삼항/논리 AND·OR/switch case 진입 시
    # push, 벗어나면 pop. 호출·엔드포인트 기록 시점의 스냅샷을 guards로 남겨 "이 호출이
    # 어떤 조건에서만 도달 가능한가"(클라이언트 단 인증우회·강제호출 가능 엔드포인트 판단 근거)를 노출한다.
    guard_stack: List[Dict[str, Any]] = []

    def _line(node) -> int:
        return (node.loc.start.line + line_offset) if getattr(node, "loc", None) else 0

    def visit(node) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        t = getattr(node, "type", None)
        if t is None:
            return
        if t in _FUNC_TYPES:  # 중첩 함수 경계 — 내려가지 않음
            return

        if t == "CallExpression":
            # 호출 1건당 정확히 1회만 out_calls에 기록(단일 visit() 통합 — 중복 기록 버그 방지)
            callee = _callee_name(node.callee)
            args = []
            for a in node.arguments:
                if getattr(a, "type", None) in _FUNC_TYPES:
                    args.append({"kind": "function_literal"})
                else:
                    dep: set = set()
                    _collect_used(a, known, dep)
                    # value: 재구성된 문자열 — 1-hop 전파 시 호출자 스코프에서의 인자값으로 사용
                    value, _ = _reconstruct_str(a, params_set, local_inits, src, this_props=this_props)
                    args.append({"kind": "expr", "depends_on": sorted(dep), "value": value})
            out_calls.append({"callee": callee, "obj": _call_root_name(node.callee), "args": args,
                               "line": _line(node), "expr": _slice(src, node),
                               "guards": list(guard_stack)})

            # HTTP 요청 sink(fetch/XHR/jQuery/axios/axios 인스턴스/beacon/Nexacro transaction) 탐지
            sink = _match_sink_kind(node.callee, axios_instances, known, axios_aliases)
            if sink is not None:
                kind, default_method = sink
                info = _extract_endpoint_info(kind, default_method, node, params_set, local_inits, src,
                                               this_props, local_props)
                if info is not None:
                    method, url_node, extra_params = info
                    base_url = None
                    if axios_instances and kind in ("axios", "axios-short"):
                        root = _call_root_name(node.callee)
                        if root in axios_instances and root not in known:
                            inst = axios_instances[root]
                            base_url = (inst["url"], inst["static"])
                    endpoints.extend(_build_endpoints(kind, method, url_node, extra_params, params_set,
                                                       local_inits, src, _line(node), file, unit_label, func_id,
                                                       base_url=base_url, guards=list(guard_stack),
                                                       this_props=this_props, var_events=var_events))
            else:
                # 이름 패턴 확정 sink가 아닐 때 순서대로 시도한다 — 셋 다 서로 및 위 확정
                # sink와 구조적으로 배타적(같은 호출이 두 목록 이상에 동시에 들어가지 않는다):
                # ① `<formRef>.action = url; ...; <formRef>.submit()`처럼 여러 문장에 걸쳐
                #    action을 조립한 뒤 기존 DOM 폼을 제출하는 관용구(form_action_refs에서
                #    조회) — 매치되면 kind="form" 확정 엔드포인트로 즉시 발행.
                # ② 동적 <form> 문자열 조립(`$("<form action=...>")`) — 매치되면 kind="form"
                #    확정 엔드포인트로 바로 발행(정적 HTML form과 동일 취급, N-hop 전파도
                #    func_id가 있으면 다른 kind와 동일하게 자동 적용됨).
                # ③ ①·②도 아니면 URL-형태 휴리스틱(candidate_endpoints, 저신뢰 후보).
                submitted = False
                if _callee_name(node.callee) in ("submit", "fireSubmit") \
                        and getattr(node.callee, "type", None) == "MemberExpression":
                    ref_key = _slice(src, node.callee.object, limit=200)
                    tracked = form_action_refs.get(ref_key) if ref_key else None
                    if tracked is not None:
                        endpoints.extend(_build_endpoints(
                            "form", "GET", tracked["value"], [], params_set, local_inits, src,
                            _line(node), file, unit_label, func_id, guards=list(guard_stack),
                            this_props=this_props, var_events=var_events))
                        submitted = True
                dyn_form = None if submitted else \
                    _match_dynamic_form_sink(node, params_set, local_inits, src, this_props)
                if dyn_form is not None:
                    static = dyn_form["static"] and all(p["static"] for p in dyn_form["params"])
                    endpoints.append({
                        "method": dyn_form["method"], "url": dyn_form["action"],
                        "url_expr": dyn_form["url_expr"], "kind": "form",
                        "file": file, "unit": unit_label, "line": _line(node), "func_id": func_id,
                        "static": static, "params": dyn_form["params"], "variants": [],
                        "guards": list(guard_stack),
                    })
                elif not submitted:
                    cand = _match_url_shape_candidate(node, params_set, local_inits, src, this_props, local_props)
                    if cand is not None:
                        url_node, extra_params = cand
                        url_text, url_static = _reconstruct_str(url_node, params_set, local_inits, src,
                                                                 this_props=this_props)
                        candidate_endpoints.append({
                            "url": url_text, "url_expr": _slice(src, url_node),
                            "callee": _slice(src, node.callee, limit=60),
                            "method": "?", "kind": "heuristic",
                            "file": file, "unit": unit_label, "line": _line(node),
                            "func_id": func_id,
                            "static": url_static and all(p["static"] for p in extra_params),
                            "params": extra_params, "guards": list(guard_stack),
                        })

            for a in node.arguments:  # 중첩 호출 f(g(x)) 지원
                visit(a)
            visit(node.callee)
            return

        if t == "NewExpression":
            # WebSocket/EventSource sink — out_calls(호출 그래프)에는 영향 없음(기존 동작 유지)
            new_sink = _match_new_sink_kind(node.callee)
            if new_sink is not None and node.arguments:
                kind, method = new_sink
                url_node = node.arguments[0]
                endpoints.extend(_build_endpoints(kind, method, url_node, [], params_set,
                                                   local_inits, src, _line(node), file, unit_label, func_id,
                                                   guards=list(guard_stack), this_props=this_props,
                                                   var_events=var_events))
            for a in node.arguments:
                visit(a)
            visit(node.callee)
            return

        if t == "VariableDeclarator":
            names = _pattern_names(node.id)
            dep = set()
            if node.init is not None:
                _collect_used(node.init, known, dep)
            for n in names:
                known.add(n)  # 선언 즉시 known에 등록 → 이후 문장에서 참조 가능
                if node.init is not None:
                    if n not in local_inits:
                        local_inits[n] = node.init  # 최초 대입만 기록 (흐름 비민감 근사치)
                    # 선언 시점의 초기값도 재대입 이벤트 0번으로 기록(_reassignment_variants_for_
                    # identifier가 "base"로 사용) — 이후 조건부 재대입이 없으면 events는 이거 하나뿐.
                    var_events.setdefault(n, []).append(
                        {"op": "=", "right": node.init, "guards": list(guard_stack)})
                defs.append({"var": n, "depends_on": sorted(dep),
                             "expr": _slice(src, node.init) if node.init is not None else "",
                             "line": _line(node)})
            if node.init is not None:
                visit(node.init)
            return

        if t == "AssignmentExpression":
            left = node.left
            if node.operator in ("=", "+=") and getattr(left, "type", None) == "Identifier":
                name = left.name
                dep = set()
                _collect_used(node.right, known, dep)
                known.add(name)
                if node.operator == "=" and name not in local_inits:
                    local_inits[name] = node.right  # 최초 대입만 기록 (흐름 비민감 근사치)
                defs.append({"var": name, "depends_on": sorted(dep),
                             "expr": _slice(src, node.right), "line": _line(node)})
                # G2/G3(복합대입·분기 재대입) 대응 — 최초 대입만이 아니라 모든 재대입을 순서대로
                # 기록해 _reassignment_variants_for_identifier가 조건부 분기별 URL을 열거하게 한다.
                var_events.setdefault(name, []).append(
                    {"op": node.operator, "right": node.right, "guards": list(guard_stack)})
            elif node.operator == "=" and getattr(left, "type", None) == "MemberExpression":
                prop_name = _member_key_name(left)
                # location.href = url / window.location.href = url 등 — 계산 접근이 아닌
                # 멤버 경로를 점(.) 리스트로 분해해 마지막 세그먼트가 "location"으로
                # 끝나는지로 판별한다(계산 접근이 섞이면 _callee_path가 None을 반환해 자동 제외).
                obj_path = _callee_path(left.object)
                if prop_name == "href" and obj_path is not None and obj_path[-1] == "location":
                    endpoints.extend(_build_endpoints(
                        "navigate", "GET", node.right, [], params_set, local_inits, src,
                        _line(node), file, unit_label, func_id, guards=list(guard_stack),
                        this_props=this_props, var_events=var_events))
                elif prop_name == "action":
                    # <formRef>.action = url — 폼 필드/제출이 여러 문장에 걸쳐 조립되는
                    # 관용구 대응. object 원문 텍스트를 키로 써서 `document.forms[0]`처럼
                    # 계산 접근이 섞인 참조도 지원한다(local_props와 달리 Identifier 한정 아님).
                    ref_key = _slice(src, left.object, limit=200)
                    if ref_key:
                        form_action_refs[ref_key] = {"value": node.right, "line": _line(node)}
                if prop_name is not None and getattr(left.object, "type", None) == "Identifier":
                    # G1/G5(속성-대입 객체 조립) 대응 — `obj.key=value` / `obj["key"]=value`를
                    # local_props에 누적(최초 대입만, 리터럴 속성과 동일한 흐름 비민감 근사치).
                    # href/action도 여기 함께 쌓이지만 설정 객체 조립에서만 조회되므로 무해하다.
                    local_props.setdefault(left.object.name, {}).setdefault(prop_name, node.right)
            visit(node.right)
            visit(node.left)
            return

        if t == "ReturnStatement":
            dep = set()
            if node.argument is not None:
                _collect_used(node.argument, known, dep)
            returns.append({"depends_on": sorted(dep),
                             "expr": _slice(src, node.argument) if node.argument is not None else "undefined",
                             "line": _line(node)})
            if node.argument is not None:
                visit(node.argument)
            return

        # ── 가드 체인 추적: 아래 4종은 "이 자식을 방문하는 동안에만 유효한 조건"을
        # guard_stack에 push/pop한다 — 그 구간에서 기록되는 out_calls/endpoints가
        # 이 조건 하에서만 도달 가능함을 나타낸다. known/defs/returns 수집 자체는
        # 기존 제네릭 순회와 동일하게 모든 자식을 방문하므로(흐름 비민감 근사치 유지)
        # 이 4종을 특별 처리해도 그 외 분석 결과는 바뀌지 않는다.
        if t == "IfStatement":
            visit(node.test)
            cond_text = _slice(src, node.test)
            guard_stack.append({"kind": "if", "cond": cond_text, "line": _line(node),
                                 "auth_hint": _is_auth_guard(cond_text)})
            visit(node.consequent)
            guard_stack.pop()
            if node.alternate is not None:
                guard_stack.append({"kind": "else", "cond": cond_text, "line": _line(node),
                                     "auth_hint": _is_auth_guard(cond_text)})
                visit(node.alternate)
                guard_stack.pop()
            return

        if t == "ConditionalExpression":
            visit(node.test)
            cond_text = _slice(src, node.test)
            guard_stack.append({"kind": "if", "cond": cond_text, "line": _line(node),
                                 "auth_hint": _is_auth_guard(cond_text)})
            visit(node.consequent)
            guard_stack.pop()
            guard_stack.append({"kind": "else", "cond": cond_text, "line": _line(node),
                                 "auth_hint": _is_auth_guard(cond_text)})
            visit(node.alternate)
            guard_stack.pop()
            return

        if t == "LogicalExpression" and node.operator in ("&&", "||"):
            visit(node.left)
            cond_text = _slice(src, node.left)
            kind = "and" if node.operator == "&&" else "or"
            guard_stack.append({"kind": kind, "cond": cond_text, "line": _line(node),
                                 "auth_hint": _is_auth_guard(cond_text)})
            visit(node.right)
            guard_stack.pop()
            return

        if t == "SwitchStatement":
            visit(node.discriminant)
            disc_text = _slice(src, node.discriminant)
            switch_line = _line(node)  # 같은 switch의 case들을 상호배타 그룹으로 묶는 키
            for case in node.cases:
                if case.test is not None:
                    visit(case.test)
                cond_text = "default" if case.test is None else f"{disc_text} === {_slice(src, case.test)}"
                guard_stack.append({"kind": "case", "cond": cond_text, "line": _line(case),
                                     "auth_hint": _is_auth_guard(cond_text), "group": switch_line})
                visit(case.consequent)
                guard_stack.pop()
            return

        for k, v in vars(node).items():
            if k in ("range", "loc", "type"):
                continue
            visit(v)

    if is_concise_arrow:
        # 화살표 함수 축약형 본문(x => expr)은 암묵적 return과 동일하게 취급
        dep = set()
        _collect_used(body, known, dep)
        returns.append({"depends_on": sorted(dep), "expr": _slice(src, body), "line": _line(body)})
        visit(body)
    else:
        visit(body)

    return {"defs": defs, "returns": returns, "out_calls": out_calls, "endpoints": endpoints,
            "candidate_endpoints": candidate_endpoints}


# ── 함수 내부 제어흐름 그래프(CFG) ────────────────────────────────────────────
#
# IDA 스타일의 분기 그래프를 목표로 하되, basic-block 정밀도 대신 AST 구조(if/switch/
# 루프/try)를 그대로 결정 노드로 매핑하는 구조 기반(structural) 근사치를 택한다 —
# 연속된 단순 문장은 하나의 block 노드로 묶고, 분기가 시작되는 지점만 결정(마름모)
# 노드로 분리한다. endpoints(HTTP sink) 라인과 겹치는 문장을 포함한 노드는
# has_sink=True로 표시해 그래프에서 강조한다(강제호출 가능 엔드포인트 위치 식별용).

def _cfg_stmt_list(node) -> List[Any]:
    """단일 문장 또는 BlockStatement를 균일하게 문장 리스트로 변환.

    If/For/While 등의 본문은 ESTree상 블록({ ... })일 수도 단일 문장일 수도 있어
    이 차이를 흡수한다."""
    if node is None:
        return []
    if getattr(node, "type", None) == "BlockStatement":
        return list(node.body)
    return [node]


class _CfgLoopCtx:
    """루프/switch 중첩 상태 — break/continue 대상 결정용.

    레이블(labeled break/continue)은 구분하지 않고 항상 가장 가까운 루프/switch를
    대상으로 하는 근사치다(설계 합의: 구조 기반 CFG는 basic-block 정밀도를 포기)."""
    __slots__ = ("continue_target", "break_sink")

    def __init__(self, continue_target: Optional[str], break_sink: List[Tuple[str, Optional[str]]]) -> None:
        self.continue_target = continue_target  # continue 시 되돌아갈 노드 id(보통 루프 조건 노드)
        self.break_sink = break_sink             # break 시 이 리스트에 현재 exits를 합류시킴


def _build_cfg(body, src: str, line_offset: int, is_concise_arrow: bool,
               sink_lines: set) -> Dict[str, Any]:
    """함수 본문 하나로부터 구조 기반 제어흐름 그래프를 생성.

    한계(설계 단계 합의 — js_analysis.md 참고):
      - 레이블 붙은 break/continue는 레이블을 구분하지 않고 가장 가까운 루프/switch를 대상으로 한다
      - try 블록 전체에서 예외가 발생할 수 있다고 근사한다(문장 단위 정밀 추적 없음)
      - switch case의 fallthrough는 break 유무로만 판단한다
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    truncated = [False]

    def _line(n) -> int:
        return (n.loc.start.line + line_offset) if getattr(n, "loc", None) else 0

    def _in_sink_lines(n) -> bool:
        loc = getattr(n, "loc", None)
        if loc is None or not sink_lines:
            return False
        start = loc.start.line + line_offset
        end = (loc.end.line + line_offset) if getattr(loc, "end", None) else start
        return any(start <= s <= end for s in sink_lines)

    def new_node(kind: str, label: str, line: int, has_sink: bool = False) -> Optional[str]:
        if len(nodes) >= _CFG_MAX_NODES:
            truncated[0] = True
            return None
        nid = f"c{len(nodes)}"
        nodes.append({"id": nid, "kind": kind, "label": label, "line": line, "has_sink": has_sink})
        return nid

    def add_edge(src_id: Optional[str], dst_id: Optional[str], label: Optional[str] = None) -> None:
        if src_id is None or dst_id is None:
            return
        edges.append({"from": src_id, "to": dst_id, "label": label})

    def build(stmts: List[Any], ctx: Optional[_CfgLoopCtx]
              ) -> Tuple[Optional[str], List[Tuple[str, Optional[str]]]]:
        """문장 리스트 하나를 순회해 (진입 노드 id, [(탈출 노드 id, 다음 엣지 라벨)]) 반환.

        탈출 목록이 비면 이 경로가 return/throw/break/continue로 종결되어 뒤가
        이어지지 않음을 뜻한다."""
        entry_id: Optional[str] = None
        exits: List[Tuple[str, Optional[str]]] = []
        pending: List[Tuple[str, int, bool]] = []  # (문장 라벨, 라인, has_sink) 축적 중인 단순 문장들

        def flush() -> None:
            nonlocal pending, exits, entry_id
            if not pending:
                return
            shown = pending[:_CFG_BLOCK_MAX_LINES]
            label = "<br/>".join(_mmd_escape(t, 80) for t, _, _ in shown)
            if len(pending) > _CFG_BLOCK_MAX_LINES:
                label += f"<br/>…(+{len(pending) - _CFG_BLOCK_MAX_LINES})"
            has_sink = any(s for _, _, s in pending)
            line = pending[0][1]
            pending = []
            nid = new_node("block", label, line, has_sink)
            if nid is None:
                return
            for eid, elabel in exits:
                add_edge(eid, nid, elabel)
            if entry_id is None:
                entry_id = nid
            exits = [(nid, None)]

        for stmt in stmts:
            while getattr(stmt, "type", None) == "LabeledStatement":  # 레이블은 무시(최근접 루프 타깃 근사)
                stmt = stmt.body
            t = getattr(stmt, "type", None)

            if t == "IfStatement":
                flush()
                cond_text = _slice(src, stmt.test, 60)
                dec_id = new_node("decision", cond_text, _line(stmt))
                if entry_id is None:
                    entry_id = dec_id
                for eid, elabel in exits:
                    add_edge(eid, dec_id, elabel)
                cons_entry, cons_exits = build(_cfg_stmt_list(stmt.consequent), ctx)
                if cons_entry:
                    add_edge(dec_id, cons_entry, "true")
                else:
                    cons_exits = [(dec_id, "true")] if dec_id else []
                if stmt.alternate is not None:
                    alt_entry, alt_exits = build(_cfg_stmt_list(stmt.alternate), ctx)
                    if alt_entry:
                        add_edge(dec_id, alt_entry, "false")
                    else:
                        alt_exits = [(dec_id, "false")] if dec_id else []
                else:
                    alt_exits = [(dec_id, "false")] if dec_id else []
                exits = cons_exits + alt_exits
                continue

            if t in ("ForStatement", "WhileStatement", "DoWhileStatement", "ForInStatement", "ForOfStatement"):
                flush()
                if t == "WhileStatement":
                    cond_text = _slice(src, stmt.test, 60)
                elif t == "DoWhileStatement":
                    cond_text = "do…while(" + _slice(src, stmt.test, 40) + ")"
                elif t == "ForStatement":
                    cond_text = "for(" + (_slice(src, stmt.test, 40) if stmt.test is not None else "") + ")"
                else:  # ForInStatement / ForOfStatement
                    kw = "in" if t == "ForInStatement" else "of"
                    cond_text = f"for({_slice(src, stmt.left, 20)} {kw} {_slice(src, stmt.right, 30)})"
                dec_id = new_node("decision", cond_text, _line(stmt))
                if entry_id is None:
                    entry_id = dec_id
                for eid, elabel in exits:
                    add_edge(eid, dec_id, elabel)
                break_exits: List[Tuple[str, Optional[str]]] = []
                loop_ctx = _CfgLoopCtx(continue_target=dec_id, break_sink=break_exits)
                body_entry, body_exits = build(_cfg_stmt_list(stmt.body), loop_ctx)
                if body_entry and dec_id:
                    add_edge(dec_id, body_entry, "loop")
                for eid, _elabel in body_exits:  # 루프 본문이 정상 종료되면 조건으로 되돌아감(back-edge)
                    add_edge(eid, dec_id, None)
                exits = ([(dec_id, "exit")] if dec_id else []) + break_exits
                continue

            if t == "SwitchStatement":
                flush()
                disc_text = _slice(src, stmt.discriminant, 40)
                disc_id = new_node("decision", f"switch({disc_text})", _line(stmt))
                if entry_id is None:
                    entry_id = disc_id
                for eid, elabel in exits:
                    add_edge(eid, disc_id, elabel)
                switch_break: List[Tuple[str, Optional[str]]] = []
                switch_ctx = _CfgLoopCtx(continue_target=ctx.continue_target if ctx else None,
                                          break_sink=switch_break)
                fallthrough: List[Tuple[str, Optional[str]]] = []
                for case in stmt.cases:
                    case_label = "default" if case.test is None else f"case {_slice(src, case.test, 30)}"
                    case_entry, case_exits = build(list(case.consequent), switch_ctx)
                    if case_entry:
                        if disc_id:
                            add_edge(disc_id, case_entry, case_label)
                        for eid, _elabel in fallthrough:  # 이전 case가 break 없이 이어짐(fallthrough)
                            add_edge(eid, case_entry, None)
                        fallthrough = case_exits
                    # 빈 case 본문(즉시 다음 case로 낙하)은 개별 라벨 엣지 없이 다음 case의
                    # fallthrough 처리에 자연히 흡수되는 근사치를 허용한다.
                exits = fallthrough + switch_break
                continue

            if t == "TryStatement":
                flush()
                try_entry, try_exits = build(list(stmt.block.body), ctx)
                for eid, elabel in exits:
                    add_edge(eid, try_entry, elabel)
                if entry_id is None:
                    entry_id = try_entry
                merged_exits = list(try_exits)
                if stmt.handler is not None:
                    catch_entry, catch_exits = build(list(stmt.handler.body.body), ctx)
                    if try_entry and catch_entry:
                        add_edge(try_entry, catch_entry, "exception")
                    merged_exits += catch_exits
                if getattr(stmt, "finalizer", None) is not None:
                    fin_entry, fin_exits = build(list(stmt.finalizer.body), ctx)
                    if fin_entry:
                        for eid, _elabel in merged_exits:
                            add_edge(eid, fin_entry, None)
                        merged_exits = fin_exits
                exits = merged_exits
                continue

            if t in ("BreakStatement", "ContinueStatement"):
                # break/continue를 명시적 노드로 만든다 — 분기 본문이 break/continue
                # 단 하나뿐인 경우(예: if(x){ continue; }) entry_id가 여전히 None이면
                # 호출부(IfStatement 등)가 "빈 본문"과 구분하지 못해 오탐(마치 그냥
                # 통과하는 것처럼 그려짐)이 나므로, 항상 노드를 만들어 연결을 보장한다.
                flush()
                label = "break" if t == "BreakStatement" else "continue"
                nid = new_node("terminal", label, _line(stmt))
                for eid, elabel in exits:
                    add_edge(eid, nid, elabel)
                if entry_id is None:
                    entry_id = nid
                if ctx is not None and nid is not None:
                    if t == "BreakStatement":
                        ctx.break_sink.append((nid, None))
                    elif ctx.continue_target is not None:
                        add_edge(nid, ctx.continue_target, None)
                exits = []
                continue

            # 단순 문장(선언/식/return/throw 등) — block 노드에 누적
            pending.append((_slice(src, stmt, 80), _line(stmt), _in_sink_lines(stmt)))
            if t in ("ReturnStatement", "ThrowStatement"):
                flush()
                exits = []  # 이후 문장은 이 경로로 도달 불가

        flush()
        return entry_id, exits

    if is_concise_arrow:
        # 화살표 함수 축약형 본문(x => expr)은 암묵적 return 하나뿐인 단일 노드로 표현
        line = (body.loc.start.line + line_offset) if getattr(body, "loc", None) else 0
        label = _mmd_escape("return " + _slice(src, body, 70), 90)
        nid = new_node("block", label, line, _in_sink_lines(body))
        return {"nodes": nodes, "edges": edges, "entry": nid, "truncated": truncated[0]}

    entry, _final_exits = build(_cfg_stmt_list(body), None)
    return {"nodes": nodes, "edges": edges, "entry": entry, "truncated": truncated[0]}


# ── 함수 인벤토리 (파일 전체 재귀 탐색) ────────────────────────────────────────

def _collect_functions(program, file: str, unit_label: str, line_offset: int,
                        src: str,
                        axios_instances: Optional[Dict[str, Any]] = None,
                        axios_aliases: Optional[Dict[str, Any]] = None,
                        this_props: Optional[Dict[str, Any]] = None
                        ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """유닛(파일 전체 또는 script 블록) 하나에서 모든 함수(중첩 포함)를 찾아 인벤토리 생성.

    이름 없는 함수 표현식은 대입 위치(변수/속성/this.x/클래스 메서드)에서 이름 힌트를
    끌어온다 (const login = function(){} → 'login', Foo.bar(){} → 'Foo.bar').

    반환: (함수 인벤토리 목록, 함수 내부에서 발견된 확정 엔드포인트 목록, URL-형태 휴리스틱
    후보 목록) — 둘 다 각 함수의 dataflow에서 나온 것을 취합만 할 뿐 함수 레코드에는 중복
    보관하지 않는다(analyze()의 전역 목록이 유일한 출처 — 파라미터 전파 시 두 곳을 동기화할
    필요 없음).
    """
    functions: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    candidate_endpoints: List[Dict[str, Any]] = []
    counter = [0]

    def visit(node, hint=None, class_ctx=None) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                visit(item, None, class_ctx)
            return
        t = getattr(node, "type", None)
        if t is None:
            return

        if t in _FUNC_TYPES:
            explicit = node.id.name if getattr(node, "id", None) else None
            if explicit:
                name = explicit
            elif hint:
                name = hint
            else:
                counter[0] += 1
                name = f"<anonymous#{counter[0]}>"
            full_name = f"{class_ctx}.{name}" if (class_ctx and not explicit) else name
            line = node.loc.start.line + line_offset if getattr(node, "loc", None) else 0
            params: List[str] = []
            for p in node.params:
                params.extend(_pattern_names(p))
            body_node = node.body
            is_concise = (t == "ArrowFunctionExpression" and getattr(body_node, "type", None) != "BlockStatement")
            fid = f"{file}::{full_name}@{line}"  # dataflow 호출 전에 확정 — 엔드포인트 func_id로 필요
            dataflow = _analyze_dataflow(body_node, params, src, line_offset, file, unit_label, fid,
                                          is_concise_arrow=is_concise, axios_instances=axios_instances,
                                          axios_aliases=axios_aliases, this_props=this_props)
            # CFG는 dataflow가 이미 찾은 엔드포인트(sink) 라인 집합을 받아 해당 문장을 포함한
            # block 노드에 has_sink 표시를 한다 — sink 판정 로직을 중복 구현하지 않고
            # dataflow의 endpoints를 유일한 출처로 재사용(js_analysis.md 설계 원칙과 일치).
            sink_lines = {e["line"] for e in dataflow["endpoints"]}
            cfg = _build_cfg(body_node, src, line_offset, is_concise, sink_lines)
            functions.append({
                "id": fid, "file": file, "unit": unit_label, "name": full_name,
                "line": line, "params": params,
                "defs": dataflow["defs"], "returns": dataflow["returns"],
                "out_calls": dataflow["out_calls"],
                "calls": sorted(set(c["callee"] for c in dataflow["out_calls"])),
                "called_by": [],  # analyze()에서 전체 파일 취합 후 역인덱스로 채움
                "cfg": cfg,
            })
            endpoints.extend(dataflow["endpoints"])
            candidate_endpoints.extend(dataflow["candidate_endpoints"])
            for p in node.params:  # 매개변수 기본값 표현식 안의 중첩 함수도 탐색
                visit(p, None, class_ctx)
            visit(node.body, None, class_ctx)
            return

        if t in ("ClassDeclaration", "ClassExpression"):
            cname = node.id.name if getattr(node, "id", None) else (hint or f"<anonclass#{counter[0]+1}>")
            visit(node.body, None, cname)
            return

        if t == "ExportDefaultDeclaration":
            # `export default function(){}` 같은 익명 선언은 "default"를 이름 힌트로 사용
            visit(node.declaration, "default", class_ctx)
            return

        if t == "MethodDefinition":
            key_name = _key_name(node.key, node.computed)
            visit(node.value, key_name, class_ctx)
            return

        if t == "VariableDeclarator":
            name_hint = node.id.name if getattr(node.id, "type", None) == "Identifier" else None
            visit(node.init, name_hint, class_ctx)
            return

        if t == "AssignmentExpression":
            name_hint = _assignment_name(node.left)
            visit(node.left, None, class_ctx)
            visit(node.right, name_hint, class_ctx)
            return

        if t == "Property":
            if node.computed:
                visit(node.key, None, class_ctx)
            visit(node.value, _key_name(node.key, node.computed), class_ctx)
            return

        for k, v in vars(node).items():
            if k in ("range", "loc", "type"):
                continue
            visit(v, None, class_ctx)

    visit(program)
    return functions, endpoints, candidate_endpoints


# ── 파일 어댑터: HTML ─────────────────────────────────────────────────────────

# <form> 하위에서 전달 파라미터로 취급할 필드 태그 (submit 버튼의 name/value도 action 판별에 흔히 쓰임)
_HTML_FORM_FIELD_TAGS = frozenset({"input", "select", "textarea", "button"})


class _ScriptCollector(_htmlparser.HTMLParser):
    """HTMLParser 서브클래스 — <script> 블록 텍스트 + 인라인 이벤트 핸들러 속성 + <form action> 수집.

    stdlib html.parser는 관대한(lenient) 파서라 깨진 HTML도 최대한 진행한다
    (이 프로젝트의 '실용적 근사치 분석' 방침과 일치).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.units: List[Dict[str, Any]] = []
        self.external_refs: List[str] = []
        self.form_endpoints: List[Dict[str, Any]] = []
        self._in_script = False
        self._script_start_line = 0
        self._script_buf: List[str] = []
        self._script_is_js = True
        self._current_form: Optional[Dict[str, Any]] = None  # 진행 중인 <form>~</form> 파싱 상태

    def handle_starttag(self, tag, attrs) -> None:
        tag_l = tag.lower()
        attrs_d = dict(attrs)
        if tag_l == "script":
            src = attrs_d.get("src")
            script_type = (attrs_d.get("type") or "").strip().lower()
            if src:
                self.external_refs.append(src)  # 외부 스크립트는 URL만 기록, fetch하지 않음
                self._script_is_js = False
            else:
                self._script_is_js = script_type in _JS_SCRIPT_TYPES
            self._in_script = True
            self._script_start_line = self.getpos()[0]
            self._script_buf = []
            return

        if tag_l == "form":
            action = (attrs_d.get("action") or "").strip()
            self._current_form = {
                "action": action, "method": (attrs_d.get("method") or "GET").strip().upper() or "GET",
                "line": self.getpos()[0], "params": [],
            }
        elif tag_l in _HTML_FORM_FIELD_TAGS and self._current_form is not None:
            name = (attrs_d.get("name") or "").strip()
            if name:
                self._current_form["params"].append(
                    {"name": name, "value": attrs_d.get("value") or "", "in": "form", "static": True})

        # 인라인 이벤트 핸들러: onclick="..." 등 (data-*/커스텀 속성은 화이트리스트로 오탐 방지)
        for name, value in attrs:
            if name and name.lower() in HTML_EVENT_ATTRS and value:
                line = self.getpos()[0]
                self.units.append({"label": f"inline:{name}@L{line}", "code": value, "line_offset": line - 1})

    def handle_data(self, data) -> None:
        if self._in_script:
            self._script_buf.append(data)

    def handle_endtag(self, tag) -> None:
        tag_l = tag.lower()
        if tag_l == "script" and self._in_script:
            if self._script_is_js and self._script_buf:
                code = "".join(self._script_buf)
                if code.strip():
                    self.units.append({"label": f"<script>@L{self._script_start_line}", "code": code,
                                        "line_offset": self._script_start_line - 1})
            self._in_script = False
            self._script_buf = []
        elif tag_l == "form" and self._current_form is not None:
            form = self._current_form
            self._current_form = None
            action = form["action"]
            # 빈 action(현재 페이지로 제출, 대상 불명)·javascript: 의사 URL(JS가 직접 처리)은 제외
            if action and not action.lower().startswith("javascript:"):
                self.form_endpoints.append({
                    "method": form["method"], "url": action, "url_expr": action, "kind": "form",
                    "unit": f"<form>@L{form['line']}", "line": form["line"], "func_id": None,
                    "static": True, "params": form["params"], "variants": [],
                    "guards": [],  # HTML 마크업 자체가 게이트이며 JS 조건 가드 개념이 없음
                })


def _extract_from_html(text: str) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    """HTML 텍스트에서 (분석 유닛 목록, 외부 스크립트 URL 목록, <form action> 엔드포인트 목록) 추출."""
    parser = _ScriptCollector()
    try:
        parser.feed(text)
    except Exception:
        pass  # 깨진 HTML도 그때까지 수집된 것은 반환 (관대한 파싱 정책)
    return parser.units, parser.external_refs, parser.form_endpoints


# ── 파일 어댑터: XML 계열 (XFDL/XADL/XJS/XML, 투비소프트 Nexacro/XPlatform) ─────

# XML 1.0 사양상 금지된 제어문자(0x00~0x1F 중 tab(0x09)/LF(0x0A)/CR(0x0D) 제외)
_XML_ILLEGAL_BYTES = bytes(b for b in range(0x20) if b not in (0x09, 0x0A, 0x0D))
_XML_BYTE_TRANS = bytes.maketrans(_XML_ILLEGAL_BYTES, b" " * len(_XML_ILLEGAL_BYTES))


def _strip_illegal_xml_bytes(raw: bytes) -> bytes:
    """XML 금지 제어문자를 동일 바이트 수의 공백으로 치환(길이 보존 → 오프셋 불변).

    UTF-8/CP949 등 ASCII 호환 인코딩에서는 0x20 미만 바이트가 멀티바이트 시퀀스의
    일부로 나타나지 않으므로 무조건 안전하다. _extract_from_xml()에서 원본 파싱이
    실패했을 때만 재시도용으로 호출되므로, UTF-16처럼 원본이 정상 파싱되는 인코딩에는
    이 함수가 아예 적용되지 않는다(적용 시 바이트 정렬이 깨져 파괴적).
    """
    return raw.translate(_XML_BYTE_TRANS)


def _extract_from_xml(raw: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Nexacro/XPlatform 계열 XML(XFDL/XADL/XJS/XML) 문서에서 <Script> 엘리먼트의
    CDATA 스크립트를 모두 추출.

    라인 번호는 Script 블록 내부 상대 라인이다(파일 전체 절대 매핑 미구현 — 알려진 한계).
    """
    try:
        root = ET.fromstring(raw)  # 1차: bytes 그대로 → XML 선언의 encoding 속성을 ET가 존중
    except ET.ParseError:
        try:
            # 2차: 금지 제어문자가 섞인 소스만 스크럽 후 재시도 (실제 Nexacro 샘플에서 발견됨)
            root = ET.fromstring(_strip_illegal_xml_bytes(raw))
        except ET.ParseError as e:
            raise ValueError(f"XML 파싱 실패: {e}")
    units: List[Dict[str, Any]] = []
    idx = 0
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]  # 네임스페이스 접두사 제거
        if tag == "Script" and elem.text and elem.text.strip():
            idx += 1
            comp_id = elem.get("id") or elem.get("name") or f"#{idx}"
            units.append({"label": f"Script[{comp_id}]", "code": elem.text, "line_offset": 0})
    return units, []


# ── JS 파싱 ───────────────────────────────────────────────────────────────────

# xscript(투비소프트 Nexacro) include 지시문: `include "lib::common.xjs";`
_INCLUDE_RE = re.compile(r'^([ \t]*)include[ \t]+(["\'])[^"\'\r\n]*\2[ \t]*;?', re.M)

# 함수 매개변수 타입 어노테이션: `obj:Form`, `e:LoadEventInfo` (콜론 뒤 식별자/점표기)
_PARAM_TYPE_RE = re.compile(r':\s*[A-Za-z_$][A-Za-z0-9_$.]*')

# "function" 키워드와 여는 괄호 사이에 이름만 있는지 검증(익명 함수는 공백만 허용)
_FUNC_NAME_GAP_RE = re.compile(r'\A\s*([A-Za-z_$][\w$]*)?\s*\Z')


def _blank(text: str) -> str:
    """개행(\\r\\n)은 보존하고 나머지 문자만 공백으로 치환 — 라인/컬럼 번호가 그대로 유지된다."""
    return re.sub(r'[^\r\n]', ' ', text)


def _strip_param_types(code: str) -> str:
    """`function name(obj:Form, e:LoadEventInfo)` 형태의 매개변수 타입 어노테이션만 제거.

    "function" 키워드 뒤 첫 번째 여는 괄호~그에 대응하는 닫는 괄호 구간만 대상으로 하여
    객체 리터럴({x:1})·삼항연산자(a?b:c) 등 다른 문맥의 콜론은 건드리지 않는다.
    """
    out = list(code)
    for m in re.finditer(r'\bfunction\b', code):
        paren_start = code.find("(", m.end())
        if paren_start < 0:
            continue
        gap = code[m.end():paren_start]
        if not _FUNC_NAME_GAP_RE.match(gap):
            continue  # "function" 뒤에 예상 밖 구조(식별자 이외) → 건드리지 않음
        depth = 0
        j = paren_start
        while j < len(code):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        else:
            continue  # 괄호가 닫히지 않음 → 건드리지 않음
        for tm in _PARAM_TYPE_RE.finditer(code, paren_start, j):
            out[tm.start():tm.end()] = _blank(tm.group(0))
    return "".join(out)


def _sanitize_xscript(code: str) -> str:
    """xscript 전용 확장 문법 3종을 esprima가 파싱 가능한 형태로 무력화(길이 보존).

    _parse_unit()에서 원본 파싱이 실패했을 때만 재시도용으로 호출된다 — 표준 JS는
    1차 파싱에서 이미 성공하므로 이 함수를 아예 타지 않는다.
    """
    code = _INCLUDE_RE.sub(lambda m: _blank(m.group(0)), code)
    code = code.replace("<>", "!=")  # xscript 부등호(Pascal/VB 스타일) → JS, 길이 동일(2자)
    code = _strip_param_types(code)
    return code


def _try_parse(code: str):
    """3단 백엔드 체인으로 스크립트 파싱.

    1차: esprima classic script. 2차: esprima ES module 문법(import/export). 두 esprima
    시도가 모두 실패하면(ES2020+ 문법 등 esprima가 지원하지 않는 경우) 3차로
    tree-sitter-javascript 어댑터(_js_ts_adapter)로 재시도한다. 어댑터는 esprima와 동일한
    ESTree 노드 모양으로 변환해 반환하므로 이후 다운스트림(_collect_functions/
    _analyze_dataflow/_collect_module_info 등)은 어느 백엔드가 파싱했는지 구분하지 않는다.
    세 백엔드 모두 실패하면 예외가 그대로 전파되어 _parse_unit()의 xscript 재시도로 이어진다.
    """
    import esprima
    try:
        return esprima.parseScript(code, options={"loc": True, "range": True, "tolerant": True})
    except Exception:
        try:
            return esprima.parseModule(code, options={"loc": True, "range": True, "tolerant": True})
        except Exception:
            return _js_ts_adapter.parse(code)


def _parse_unit(code: str) -> Tuple[Any, str]:
    """코드를 파싱해 (AST, 실제로 파싱에 성공한 코드 문자열)을 반환.

    1차: 원본 그대로 시도. 실패하면 2차로 xscript 확장 문법을 무력화한 뒤 재시도한다.
    반환되는 코드 문자열은 _collect_functions()의 src로 그대로 전달되어 _slice() 표시
    텍스트가 실제 파싱 대상과 항상 일치하도록 한다.
    """
    try:
        return _try_parse(code), code
    except Exception:
        sanitized = _sanitize_xscript(code)
        return _try_parse(sanitized), sanitized


# ── 파일 간 모듈 의존 관계 분석 (ESM import/export · CommonJS require · Nexacro include · script src) ──
#
# 업로드는 <input type="file" multiple> / 드래그&드롭 기반이라 폴더 구조가 보존되지 않고
# 파일명(basename)만 남는다. 따라서 지정자("./a", "../lib/b", "lib::common.xjs")는 전체
# 상대경로가 아니라 basename만 추출해 업로드된 파일명 집합과 매칭한다(_normalize_specifier).
# 동일 basename이 여러 번 업로드되면 "ambiguous"로 남기고 호출 해소는 이름 매칭 폴백에 맡긴다.

_INCLUDE_TARGET_RE = re.compile(r'\binclude[ \t]+(["\'])([^"\'\r\n]*)\1')


def _extract_includes(code: str) -> List[str]:
    """xscript `include "...";` 지시문에서 대상 지정자만 추출.

    파싱 성공 여부와 무관하게 원본 코드를 직접 정규식으로 스캔한다 — include 문은 표준
    JS 구문이 아니라 esprima 1차 파싱이 대개 실패해 _sanitize_xscript가 이를 공백으로
    무력화해 버리므로, 그 전에 원본에서 별도로 뽑아둬야 한다.
    """
    return [m.group(2) for m in _INCLUDE_TARGET_RE.finditer(code) if m.group(2)]


def _normalize_specifier(spec: str) -> str:
    """지정자에서 쿼리/해시 제거, 구분자 통일 후 basename만 추출."""
    spec = spec.split("?", 1)[0].split("#", 1)[0]
    spec = spec.replace("\\", "/").replace("::", "/")  # Nexacro "lib::common.xjs" 스타일도 처리
    return spec.rsplit("/", 1)[-1]


def _exported_decl_names(decl) -> List[str]:
    """`export function foo(){}` / `export const {a,b} = ...` 등 인라인 선언에서 노출되는 이름 전체."""
    t = getattr(decl, "type", None)
    if t in ("FunctionDeclaration", "ClassDeclaration") and getattr(decl, "id", None):
        return [decl.id.name]
    if t == "VariableDeclaration":
        names: List[str] = []
        for d in decl.declarations:
            names.extend(_pattern_names(d.id))
        return names
    return []


def _is_require_call(node) -> bool:
    """`require('literal')` 형태의 CommonJS require 호출인지 판별 (동적 인자는 추적 불가로 제외)."""
    return bool(
        node is not None and getattr(node, "type", None) == "CallExpression"
        and getattr(node.callee, "type", None) == "Identifier" and node.callee.name == "require"
        and len(node.arguments) == 1 and getattr(node.arguments[0], "type", None) == "Literal"
        and isinstance(node.arguments[0].value, str)
    )


def _bind_require_pattern(id_node, source: str, add_import) -> None:
    """`const m = require('./m')`(네임스페이스) / `const {a} = require('./m')`(명시 바인딩) 처리."""
    t = getattr(id_node, "type", None)
    if t == "Identifier":
        add_import(id_node.name, source, "*", "require")
    elif t == "ObjectPattern":
        for prop in id_node.properties:
            if getattr(prop, "type", None) == "RestElement":
                continue
            key_name = _key_name(prop.key, prop.computed)
            if key_name == "<computed>":
                continue
            for local_name in _pattern_names(prop.value):
                add_import(local_name, source, key_name, "require")


def _bind_cjs_export_value(rhs, add_export, forced_name: Optional[str] = None) -> None:
    """`module.exports = ...` / `exports.foo = ...` 우변에서 (exported, local) 쌍을 등록.

    익명 함수 리터럴은 _assignment_name()의 기존 힌트 규칙과 동일하게 명명되므로(예:
    `module.exports = function(){}` → 힌트 "exports") 그 이름을 그대로 local로 사용한다.
    """
    if forced_name is not None:
        local = rhs.name if getattr(rhs, "type", None) == "Identifier" else forced_name
        add_export(forced_name, local)
        return
    rt = getattr(rhs, "type", None)
    if rt == "Identifier":
        add_export("default", rhs.name)
    elif rt == "ObjectExpression":
        for prop in rhs.properties:
            if getattr(prop, "type", None) != "Property":
                continue
            exported_name = _key_name(prop.key, prop.computed)
            if exported_name == "<computed>":
                continue
            vt = getattr(prop.value, "type", None)
            local = prop.value.name if vt == "Identifier" else exported_name
            add_export(exported_name, local)
    else:
        add_export("default", "exports")  # module.exports = function(){} 등 — "exports" 힌트와 일치


def _collect_module_info(program, unit_code: str) -> Dict[str, List[Dict[str, Any]]]:
    """유닛 하나의 AST에서 ESM import/export + CommonJS require/module.exports를 추출.

    imports:   [{local, source, imported, kind}]  kind는 "import"(ESM) 또는 "require"(CJS).
               imported는 원본 export 이름, "default", 또는 네임스페이스 전체를 뜻하는 "*".
    exports:   [{exported, local}]  local은 이 유닛 안에서 실제로 정의된 이름.
    reexports: [{source, imported, exported}]  `export ... from './x'` / `export * from './x'` 계열.
    """
    imports: List[Dict[str, Any]] = []
    exports: List[Dict[str, Any]] = []
    reexports: List[Dict[str, Any]] = []

    def add_import(local, source, imported, kind):
        imports.append({"local": local, "source": source, "imported": imported, "kind": kind})

    def add_export(exported, local):
        if local:
            exports.append({"exported": exported, "local": local})

    for stmt in getattr(program, "body", []) or []:
        t = getattr(stmt, "type", None)
        if t == "ImportDeclaration":
            source = stmt.source.value
            for spec in stmt.specifiers:
                st = spec.type
                if st == "ImportDefaultSpecifier":
                    add_import(spec.local.name, source, "default", "import")
                elif st == "ImportNamespaceSpecifier":
                    add_import(spec.local.name, source, "*", "import")
                elif st == "ImportSpecifier":
                    imported_name = (spec.imported.name if getattr(spec.imported, "type", None) == "Identifier"
                                     else getattr(spec.imported, "value", None))
                    if imported_name:
                        add_import(spec.local.name, source, imported_name, "import")
        elif t == "ExportAllDeclaration":
            source = stmt.source.value if getattr(stmt, "source", None) else None
            if source:
                reexports.append({"source": source, "imported": "*", "exported": "*"})
        elif t == "ExportNamedDeclaration":
            source = stmt.source.value if getattr(stmt, "source", None) else None
            for spec in getattr(stmt, "specifiers", []) or []:
                local_name = (spec.local.name if getattr(spec.local, "type", None) == "Identifier"
                              else getattr(spec.local, "value", None))
                exported_name = (spec.exported.name if getattr(spec.exported, "type", None) == "Identifier"
                                 else getattr(spec.exported, "value", None))
                if not local_name or not exported_name:
                    continue
                if source:
                    reexports.append({"source": source, "imported": local_name, "exported": exported_name})
                else:
                    add_export(exported_name, local_name)
            decl = getattr(stmt, "declaration", None)
            if decl is not None:
                for name in _exported_decl_names(decl):
                    add_export(name, name)
        elif t == "ExportDefaultDeclaration":
            decl = stmt.declaration
            dt = getattr(decl, "type", None)
            if dt == "Identifier":
                add_export("default", decl.name)
            elif dt in _FUNC_TYPES or dt in ("ClassDeclaration", "ClassExpression"):
                explicit = getattr(decl, "id", None)
                add_export("default", explicit.name if explicit else "default")

    def walk_cjs(node) -> None:
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                walk_cjs(item)
            return
        t = getattr(node, "type", None)
        if t is None:
            return
        if t == "VariableDeclarator" and _is_require_call(node.init):
            source = node.init.arguments[0].value
            _bind_require_pattern(node.id, source, add_import)
        elif t == "AssignmentExpression":
            left = node.left
            if getattr(left, "type", None) == "MemberExpression" and not left.computed:
                obj_name = getattr(left.object, "name", None)
                prop = left.property
                prop_name = prop.name if getattr(prop, "type", None) == "Identifier" else None
                if obj_name == "module" and prop_name == "exports":
                    _bind_cjs_export_value(node.right, add_export)
                elif obj_name == "exports" and prop_name:
                    _bind_cjs_export_value(node.right, add_export, forced_name=prop_name)
        for k, v in vars(node).items():
            if k in ("range", "loc", "type"):
                continue
            walk_cjs(v)

    walk_cjs(program)

    return {"imports": imports, "exports": exports, "reexports": reexports}


def _collect_axios_aliases(imports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """`_collect_module_info()`가 뽑은 imports 목록에서 'axios' 패키지 별칭만 걸러
    `_match_sink_kind()`가 바로 쓸 수 있는 {"roots": set, "methods": dict} 형태로 정리.

    roots:   `import ax from 'axios'`/`const n = require('axios')` 처럼 axios 모듈 전체를
             받은 로컬 변수명 — ax.get(...) 등을 리터럴 axios 호출과 동일하게 취급.
    methods: `import {get} from 'axios'`(또는 `const {get} = require('axios')`) 처럼 메서드
             하나만 구조분해 임포트한 로컬 변수명 → HTTP 메서드 — get(...) 단독 호출 인식용.

    다른 HTTP 클라이언트 패키지(ky/got/superagent 등)는 메서드명·인자 형태가 axios와 달라
    이 범위에 포함하지 않는다(오탐 방지 — 필요 시 별도 sink kind로 확장).
    """
    roots: set = set()
    methods: Dict[str, str] = {}
    for imp in imports:
        if imp.get("source") != "axios":
            continue
        imported = imp.get("imported")
        local = imp.get("local")
        if not local:
            continue
        if imported in ("default", "*"):
            roots.add(local)
        elif imported in _AXIOS_SHORT_METHODS:
            methods[local] = _AXIOS_SHORT_METHODS[imported]
    return {"roots": roots, "methods": methods}


def _resolve_export_chain(files_exports: Dict[str, Dict[str, str]],
                           files_reexports: Dict[str, List[Dict[str, Any]]],
                           specifier_resolution: Dict[Tuple[str, str], Optional[str]],
                           file: str, name: str,
                           _visited: Optional[set] = None) -> Optional[Tuple[str, str]]:
    """export 이름 하나를 재수출(`export ... from`) 체인을 따라가 실제 정의 (파일, 로컬이름)으로 해소.

    (파일, 이름) 방문 집합으로 순환 재수출(A가 B를, B가 A를 재수출)에서도 종료를 보장한다.
    """
    visited = _visited if _visited is not None else set()
    key = (file, name)
    if key in visited:
        return None
    visited.add(key)

    local = files_exports.get(file, {}).get(name)
    if local is not None:
        return file, local

    for reexp in files_reexports.get(file, []):
        if reexp["exported"] != name and reexp["imported"] != "*":
            continue
        target = specifier_resolution.get((file, reexp["source"]))
        if not target:
            continue
        hop_name = name if reexp["imported"] == "*" else reexp["imported"]
        result = _resolve_export_chain(files_exports, files_reexports, specifier_resolution,
                                        target, hop_name, visited)
        if result:
            return result
    return None


def _build_module_graph(files_module_raw: Dict[str, Dict[str, List[Any]]],
                         uploaded_names: List[str]) -> Dict[str, Any]:
    """파일별 import/require/include/script-src 정보를 모아 파일 간 의존 엣지와 호출 해소용
    바인딩 테이블을 구성한다.
    """
    by_basename: Dict[str, List[str]] = {}
    for name in uploaded_names:
        by_basename.setdefault(_normalize_specifier(name).lower(), []).append(name)

    def resolve_specifier(spec: str) -> Tuple[Optional[str], str]:
        base = _normalize_specifier(spec).lower()
        candidates = by_basename.get(base, [])
        if not candidates and "." not in base:
            for ext in SUPPORTED_EXTS:
                candidates = by_basename.get(base + ext, [])
                if candidates:
                    break
        if len(candidates) == 1:
            return candidates[0], "resolved"
        if len(candidates) > 1:
            return None, "ambiguous"
        return None, "unresolved"

    files_exports: Dict[str, Dict[str, str]] = {}
    files_reexports: Dict[str, List[Dict[str, Any]]] = {}
    for filename, info in files_module_raw.items():
        files_exports[filename] = {e["exported"]: e["local"] for e in info["exports"] if e["local"]}
        files_reexports[filename] = info["reexports"]

    specifier_resolution: Dict[Tuple[str, str], Optional[str]] = {}
    edges: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []

    def record(filename: str, spec: str, kind: str) -> None:
        key = (filename, spec)
        if key in specifier_resolution:
            return
        if "!" in spec:
            # AMD/RequireJS 로더 플러그인 지정자(예: "i18n!nls/commons", "text!template.html")다.
            # "!" 앞은 파일 경로가 아니라 플러그인 이름이라 업로드 파일 집합에 대응 대상이 없는 게
            # 정상이므로, 미해소 참조로 보고하지 않고 완전히 무시한다(엣지도 만들지 않음).
            specifier_resolution[key] = None
            return
        target, status = resolve_specifier(spec)
        specifier_resolution[key] = target
        if target:
            edges.append({"from": filename, "to": target, "kind": kind, "specifier": spec})
        else:
            unresolved.append({"from": filename, "specifier": spec, "kind": kind, "reason": status})

    for filename, info in files_module_raw.items():
        for imp in info["imports"]:
            record(filename, imp["source"], imp["kind"])
        for reexp in info["reexports"]:
            record(filename, reexp["source"], "reexport")
        for inc in info["includes"]:
            record(filename, inc, "include")
        for ref in info["script_refs"]:
            record(filename, ref, "script")

    seen_edges: set = set()
    dedup_edges: List[Dict[str, Any]] = []
    for e in edges:
        key = (e["from"], e["to"], e["kind"])
        if key not in seen_edges:
            seen_edges.add(key)
            dedup_edges.append(e)

    # 호출 해소용 바인딩: 로컬 이름 → 재수출 체인까지 따라간 최종 (파일, 로컬이름)
    file_bindings: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for filename, info in files_module_raw.items():
        bindings: Dict[str, Dict[str, Any]] = {}
        for imp in info["imports"]:
            target = specifier_resolution.get((filename, imp["source"]))
            if imp["imported"] == "*":
                bindings[imp["local"]] = {"file": target, "name": None, "namespace": True, "kind": imp["kind"]}
            elif target:
                resolved = _resolve_export_chain(files_exports, files_reexports, specifier_resolution,
                                                  target, imp["imported"])
                if resolved:
                    rf, rname = resolved
                    bindings[imp["local"]] = {"file": rf, "name": rname, "namespace": False, "kind": imp["kind"]}
        file_bindings[filename] = bindings

    # include/script src로 연결된 파일은 전역 스코프를 공유하는 것으로 간주(단방향: 포함하는 쪽만 접근 가능)
    shared_scope: Dict[str, List[str]] = {}
    for e in dedup_edges:
        if e["kind"] in ("include", "script"):
            shared_scope.setdefault(e["from"], []).append(e["to"])

    return {
        "edges": dedup_edges,
        "unresolved": unresolved,
        "file_bindings": file_bindings,
        "shared_scope": shared_scope,
        "files_exports": files_exports,
        "files_reexports": files_reexports,
        "specifier_resolution": specifier_resolution,
    }


def _resolve_call_targets(caller_file: str, call: Dict[str, Any], module_graph: Dict[str, Any],
                           by_file_name: Dict[Tuple[str, str], List[str]],
                           by_name: Dict[str, List[str]]) -> Tuple[List[str], str]:
    """호출 1건의 대상 함수 id 목록과 해소 등급을 반환.

    우선순위: import/require 바인딩("import"/"require") > 같은 파일 지역 함수("local")
    > include/script 공유 스코프("include") > 전역 이름 매칭(기존 방식, "name" — 폴백).
    """
    callee = call["callee"]
    obj = call.get("obj")
    bindings = module_graph["file_bindings"].get(caller_file, {})

    target_file = None
    target_name = None
    kind = None

    if obj and obj in bindings:
        b = bindings[obj]
        if b.get("namespace") and b.get("file"):
            resolved = _resolve_export_chain(module_graph["files_exports"], module_graph["files_reexports"],
                                              module_graph["specifier_resolution"], b["file"], callee)
            if resolved:
                target_file, target_name = resolved
                kind = b["kind"]
    elif obj is None and callee in bindings:
        b = bindings[callee]
        if not b.get("namespace") and b.get("file") and b.get("name"):
            target_file, target_name = b["file"], b["name"]
            kind = b["kind"]

    if target_file and target_name:
        ids = by_file_name.get((target_file, target_name), [])
        if ids:
            return ids, kind

    same_file_ids = by_file_name.get((caller_file, callee), [])
    if same_file_ids:
        return same_file_ids, "local"

    for shared_file in module_graph["shared_scope"].get(caller_file, []):
        ids = by_file_name.get((shared_file, callee), [])
        if ids:
            return ids, "include"

    name_ids = by_name.get(callee, [])
    if name_ids:
        return name_ids, "name"

    return [], "unresolved"


# ── 오케스트레이션 ─────────────────────────────────────────────────────────────

def _find_placeholder_candidates(url: str, params_map: Dict[str, str], fn_params: List[str]) -> set:
    """url/params 값에 남은 "{paramName}" 플레이스홀더 중 fn_params(대상 함수 매개변수)와
    이름이 일치하는 것만 골라 반환 — N-hop 전파 각 단계에서 "이번 hop에 치환을 시도할
    대상"을 좁히는 데 쓰인다."""
    fn_params_set = set(fn_params)
    names: set = set()
    for m in _PLACEHOLDER_RE.finditer(url):
        if m.group(1) in fn_params_set:
            names.add(m.group(1))
    for v in params_map.values():
        for m in _PLACEHOLDER_RE.finditer(v):
            if m.group(1) in fn_params_set:
                names.add(m.group(1))
    return names


def _propagate_one(fid: str, url: str, params_map: Dict[str, str], by_id: Dict[str, Dict[str, Any]],
                    chain: List[str], visited: set, hops: int, out: List[Dict[str, Any]],
                    seen_keys: set) -> bool:
    """fid(현재 hop에서 살펴볼 함수)의 매개변수와 일치하는 플레이스홀더를, fid를 호출하는
    함수(들)의 실제 인자값으로 1단계 구체화한 뒤 재귀적으로 그 호출자의 호출자로 더 거슬러
    올라간다. 더 못 가는 갈래(hop 상한/순환/호출자 없음/구체화할 이름 없음)마다 그 시점까지
    구체화된 값을 variant로 확정해 out에 추가한다(부분 구체화도 버리지 않는 best-effort).

    seen_keys(엔드포인트 하나당 공유하는 집합)로 최종 (url, params) 조합 기준 중복을
    제거한다 — url만으로 키를 잡으면 "URL은 정적이고 params만 갈리는" 흔한 게이트웨이
    패턴(예: `/gateway.do`에 cmd=USER_LIST/cmd=USER_DELETE처럼 action이 body로만 전달되는
    경우)에서 서로 다른 값의 variant가 같은 url이라는 이유만으로 잘못 병합된다 — 반드시
    url과 params를 함께 묶은 키로 dedup해야 한다. 같은 (url, params) 조합이 서로 다른
    호출자 경로로 여러 번 도달해도 variant는 한 번만 남고, _VARIANT_CAP은(raw 발행
    건수가 아니라) "서로 다른 (url, params) 조합 수"에 적용된다. 이름 매칭 과다연결
    (resolution="name") 등으로 생기는 동일/유사 조합 노이즈는 이 dedup으로 자연히 접혀
    상한을 낭비하지 않고, 하나의 sink에 정당하게 몰리는 대량의 서로 다른 url(레거시 팝업
    게이트웨이 등)은 상한을 온전히 채운다.

    반환값(bool)은 "이 호출에서 하나 이상 더 깊이 전개했는지" — 상위 프레임이 자기 자신의
    변형을 append할지(더 못 감) 재귀에 맡길지(더 감) 판단하는 데만 쓰인다.
    """
    if len(out) >= _VARIANT_CAP or hops >= _HOP_MAX:
        return False
    fn = by_id.get(fid)
    if not fn or not fn["params"]:
        return False
    candidate_names = _find_placeholder_candidates(url, params_map, fn["params"])
    if not candidate_names:
        return False
    param_idx = {name: fn["params"].index(name) for name in candidate_names}

    expanded = False
    for caller_id in fn.get("called_by", []):
        if caller_id in visited or len(out) >= _VARIANT_CAP:
            continue
        caller = by_id.get(caller_id)
        if not caller:
            continue
        for call in caller["out_calls"]:
            if fid not in call.get("resolved_ids", []):
                continue
            subst: Dict[str, str] = {}
            for name, idx in param_idx.items():
                if idx < len(call["args"]) and call["args"][idx].get("kind") == "expr":
                    subst[name] = call["args"][idx].get("value", "")
            if not subst:
                continue
            v_url = url
            v_params = dict(params_map)
            for name, val in subst.items():
                placeholder = "{" + name + "}"
                v_url = v_url.replace(placeholder, val)
                for k in list(v_params.keys()):
                    v_params[k] = v_params[k].replace(placeholder, val)
            new_chain = chain + [caller_id]
            expanded = True
            recursed = _propagate_one(caller_id, v_url, v_params, by_id, new_chain,
                                       visited | {caller_id}, hops + 1, out, seen_keys)
            if not recursed and len(out) < _VARIANT_CAP:
                dedup_key = (v_url, tuple(sorted(v_params.items())))
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    out.append({"from": caller_id, "chain": new_chain, "hops": hops + 1,
                                "url": v_url, "path": _normalize_display_path(v_url), "params": v_params})
    return expanded


def _propagate_endpoint_params(endpoints: List[Dict[str, Any]], by_id: Dict[str, Dict[str, Any]]) -> None:
    """엔드포인트의 url/params 값에 남은 "{paramName}" 플레이스홀더를 호출자 체인을 따라
    최대 _HOP_MAX(4)단계까지 거슬러 올라가며 실제 인자값으로 구체화해 variants에 채운다
    (N-hop 파라미터 전파, `_propagate_one`이 재귀로 수행).

    action/cmd 파라미터로 분기하는 레거시 게이트웨이 패턴, 그리고 래퍼가 래퍼를 감싼 다단
    HTTP 헬퍼 체인(`http(path)` → `getUser(id){http("/users/"+id)}` → `load(){getUser(cur)}`
    같은 구조)을 겨냥한다. 한 hop의 구체화 결과에 다음 hop 함수 자신의 매개변수 이름과
    일치하는 플레이스홀더가 남아 있으면 그 호출자의 호출자로 계속 전개하고, 더 못 가면
    (호출자 없음/hop 상한/순환/구체화 대상 소진) 그 시점까지의 값을 variant로 확정한다
    (부분 구체화도 버리지 않는 best-effort). 순환은 방문 집합(visited)으로, 무한 확산은
    hop 상한과, 엔드포인트당 서로 다른 (url, params) 조합 수 상한(_VARIANT_CAP=300,
    dedup 후 카운트)으로 차단한다. 호출자 인자가 리터럴이 아니면 치환 결과에도
    플레이스홀더가 남을 수 있다(원본을 억지로 리터럴화하지 않음).
    """
    for ep in endpoints:
        fid = ep.get("func_id")
        if not fid or fid not in by_id:
            ep["variants"] = []
            continue
        params_map = {p["name"]: p["value"] for p in ep["params"]}
        variants: List[Dict[str, Any]] = []
        _propagate_one(fid, ep["url"], params_map, by_id, [], set(), 0, variants, set())
        ep["variants"] = variants


# 유닛 하나를 처리하는 5단계의 실측 비중 기반 가중치(합계 100) — 대용량 단일 .js 파일
# 기준 실측(파싱이 전체 시간의 절반 이상을 차지)을 반영해 진행률 점프가 실제 체감과
# 어긋나지 않도록 한다. 순서는 실제 처리 순서와 동일.
_UNIT_STAGE_WEIGHTS: Tuple[Tuple[str, int], ...] = (
    ("파일 파싱 중", 60),
    ("모듈 의존관계 분석 중", 6),
    ("axios 인스턴스 분석 중", 5),
    ("함수 인벤토리 구성 중", 25),
    ("모듈 최상위 스캔 중", 4),
)


def analyze(sources: List[Tuple[str, bytes]],
            progress_cb: Optional[Callable[[int, str], None]] = None,
            stop_event: Optional[Any] = None) -> Dict[str, Any]:
    """업로드된 (파일명, 바이트) 목록을 받아 파일별 추출 → 유닛별 파싱 → 함수 인벤토리 →
    파일 간 모듈 의존 관계(import/require/include/script src) → 전역 호출 그래프(called_by
    역인덱스) → 엔드포인트(HTTP 요청 sink) 추출·N-hop 파라미터 전파 → URL-형태 휴리스틱
    후보(candidate_endpoints) 취합까지 구성한 종합 분석 결과를 반환.

    progress_cb(pct, stage)가 주어지면 파일·유닛 개수 기준 진행률(0~99, 대용량 단일 파일은
    유닛 내부 5단계 가중치로 보간)과 현재 단계 라벨을 통지한다. stop_event(threading.Event)가
    주어지면 파일/유닛 루프 경계 및 유닛 내부 5단계 각각에서 협조적 중단을 검사해 즉시
    ScanCancelled(modules/_cancel.py)를 던진다 — 단일 파일의 파싱처럼 원자적으로 오래 걸리는
    구간(run_cancellable)에서도 중단이 지연되지 않는다. 두 인자 모두 생략하면 기존과 완전히
    동일하게 동작한다(오버헤드 없음).

    반환 dict:
      files:     파일별 처리 통계 (kind, units, parse_errors, external_refs)
      functions: 전체 함수 인벤토리. out_calls 각 항목에 resolved_ids(해소된 대상 함수 id 목록)·
                 resolution(해소 등급: import/require/local/include/name/unresolved)·
                 args[].value(재구성된 인자 문자열)가 추가됨. 파일 경계를 넘어
                 import/require/include/script src로 우선 연결하고, 해소 실패 시에만
                 이름 매칭(name)으로 폴백한다.
      modules:   파일 간 의존 관계 {edges: [...], unresolved: [...]}
      endpoints: HTTP 요청 sink(fetch/XHR/jQuery/axios/beacon/WebSocket/EventSource/
                 Nexacro transaction/HTML form action)에 더해, 코드가 프로그램적으로
                 서버 URL을 요청 가능한 형태로 조립하는 화면 내비게이션·폼 제출(window.open/
                 location.href·replace·assign/iframe·팝업 컨트롤 로더/여러 문장에 걸쳐
                 조립되는 DOM 폼 action+submit)도 동일한 공격표면으로 보아 함께 담는
                 목록. 함수 내부에서 발견된 것은
                 func_id로 소속 함수와 연결되며, url/params 값이 그 함수의 파라미터에
                 의존하면(action 단위로 나뉜 레거시 게이트웨이 패턴, 래퍼가 래퍼를 감싼
                 다단 호출 등) called_by 호출자 체인을 따라 최대 4단계까지 구체화한
                 variants가 채워진다(N-hop 파라미터 전파). sink 설정 객체가 리터럴이 아닌
                 속성-대입으로 조립되었거나(`t={}; t.url=...`) URL 자체가 조건부(삼항/
                 if-else/논리연산/switch/변수 재대입)로 여러 값을 가지면, 그 분기마다
                 하나씩 별도 레코드로 발행된다(_build_endpoints — 분기가 없는 압도적
                 다수의 경우는 기존과 동일하게 정확히 1개).
      candidate_endpoints: 확정 sink 이름 패턴과 일치하지 않지만 인자가 URL/경로처럼
                 생긴 호출(이름을 알 수 없는 커스텀 HTTP 래퍼 등)을 별도로 모은 저신뢰
                 후보 목록. method는 항상 "?"(미상), kind는 항상 "heuristic"이며
                 endpoints와 절대 섞이지 않는다(파라미터 전파 없음). 상세 필드는
                 modules/js_analysis.md 참고.
    """
    def _report(pct: float, stage: str) -> None:
        if progress_cb is not None:
            progress_cb(min(99, int(pct)), stage)

    # 깊게 중첩된 코드의 RecursionError를 줄이기 위해 재귀 한계를 상향(_RECURSION_LIMIT
    # 정의부 참고). 다른 스캔이 동시에 이미 더 높은 값을 설정했을 수 있으므로 낮추지는
    # 않는다(여러 분석 job이 동시에 실행돼도 서로 안전).
    if sys.getrecursionlimit() < _RECURSION_LIMIT:
        sys.setrecursionlimit(_RECURSION_LIMIT)

    files_info: List[Dict[str, Any]] = []
    all_functions: List[Dict[str, Any]] = []
    all_endpoints: List[Dict[str, Any]] = []
    all_candidate_endpoints: List[Dict[str, Any]] = []
    files_module_raw: Dict[str, Dict[str, List[Any]]] = {}

    # 파일/유닛 루프에 0~95%를 배분하고, 마지막 전역 단계(모듈 그래프·호출 해소·전파)에 95~99%를 배분한다.
    total_files = len(sources) or 1
    file_span = 95.0 / total_files

    for file_idx, (filename, raw_bytes) in enumerate(sources):
        wait_or_cancel(stop_event, 0)  # 파일 경계 — 즉시 중단 검사(대기 없음)
        file_base = file_idx * file_span
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in SUPPORTED_EXTS:
            files_info.append({"name": filename, "kind": "unsupported", "units": 0,
                                "parse_errors": [f"지원하지 않는 확장자입니다 ({ext or '없음'})"],
                                "external_refs": []})
            continue

        form_eps: List[Dict[str, Any]] = []
        try:
            if ext in (".js", ".axd"):
                # .axd(ASP.NET WebResource/ScriptResource 핸들러 출력)는 확장자만 다를 뿐
                # 내용은 순수 JS라 .js와 동일하게 단일 스크립트로 파싱한다.
                units = [{"label": filename, "code": _decode_bytes(raw_bytes), "line_offset": 0}]
                ext_refs: List[str] = []
            elif ext in (".html", ".htm"):
                units, ext_refs, form_eps = _extract_from_html(_decode_bytes(raw_bytes))
            elif ext == ".xjs":
                # .xjs는 <Script> 루트 XML(Nexacro) 또는 순수 JS로 저장되는 두 형태가 모두
                # 존재한다 — 먼저 XML로 시도하고, 실패하면 파일 전체를 JS 1유닛으로 폴백.
                try:
                    units, ext_refs = _extract_from_xml(raw_bytes)
                except ValueError:
                    units = [{"label": filename, "code": _decode_bytes(raw_bytes), "line_offset": 0}]
                    ext_refs = []
            else:  # .xfdl / .xadl / .xml
                units, ext_refs = _extract_from_xml(raw_bytes)
        except Exception as e:
            files_info.append({"name": filename, "kind": ext, "units": 0,
                                "parse_errors": [f"소스 추출 실패: {e}"], "external_refs": []})
            continue

        for ep in form_eps:  # _extract_from_html은 파일명을 모르므로 여기서 채운다
            ep["file"] = filename
        all_endpoints.extend(form_eps)

        parse_errors: List[str] = []
        unit_ok = 0
        mod_raw: Dict[str, List[Any]] = {"imports": [], "exports": [], "reexports": [],
                                          "includes": [], "script_refs": ext_refs}
        total_units = len(units) or 1
        unit_span = file_span / total_units
        for unit_idx, unit in enumerate(units):
            wait_or_cancel(stop_event, 0)  # 유닛 경계 — 즉시 중단 검사(대기 없음)
            unit_base = file_base + unit_idx * unit_span
            stage_base = unit_base  # 유닛 내부 5단계 가중치 누적 기준점

            if ext in (".xjs", ".xfdl", ".xadl", ".xml"):
                # include는 표준 JS 구문이 아니라 파싱 실패 시 무력화되므로, 파싱 성공 여부와
                # 무관하게 원본에서 직접 추출해둔다.
                mod_raw["includes"].extend(_extract_includes(unit["code"]))
            _report(stage_base, _UNIT_STAGE_WEIGHTS[0][0])
            try:
                tree, used_code = run_cancellable(lambda: _parse_unit(unit["code"]), stop_event)
            except ScanCancelled:
                raise
            except Exception as e:
                # 유닛 하나가 파싱 실패해도 나머지 유닛/파일은 계속 진행 (배치 중단 안 함)
                parse_errors.append(f"{unit['label']}: 파싱 실패 - {e}")
                stage_base += unit_span * _UNIT_STAGE_WEIGHTS[0][1] / 100
                continue
            unit_ok += 1
            stage_base += unit_span * _UNIT_STAGE_WEIGHTS[0][1] / 100

            # 파싱 이후 4단계(모듈정보 → axios인스턴스 → 함수인벤토리 → 모듈최상위)는 한 유닛
            # 안에서 서로 의존하므로(axios import/require 별칭이 함수 인벤토리·top-level의 sink
            # 매칭에 필요) 하나의 try/except로 묶어 실패 시 이 유닛만 건너뛰고 나머지 유닛/파일은
            # 계속 진행한다 — 파싱 실패 격리와 동일한 정책(이전엔 이 구간이 무방비라 유닛 하나의
            # 예외가 배치 전체를 중단시켰다). 성공한 유닛만 결과를 취합하도록 extend는 모두
            # try 블록 밖(성공 후)에서 수행해 부분 취합을 방지한다.
            try:
                # import/require 별칭(axios 등) — 아래 두 단계의 sink 매칭에 필요하므로 먼저 수집.
                _report(stage_base, _UNIT_STAGE_WEIGHTS[1][0])
                unit_mod_info = run_cancellable(lambda: _collect_module_info(tree, used_code), stop_event)
                axios_aliases = _collect_axios_aliases(unit_mod_info["imports"])
                stage_base += unit_span * _UNIT_STAGE_WEIGHTS[1][1] / 100

                # axios.create()/팩토리 경유 인스턴스 테이블과 `this.PROP` 대입 테이블 — 둘 다
                # 함수 경계를 넘어 유닛 전체에서 수집해야 한다(모듈 최상위/다른 메서드에서
                # 정의되고 별개 함수 내부에서 쓰이는 것이 실전 패턴이라 사전 수집 필요). 가벼운
                # 트리 스캔 2개라 같은 진행률 단계로 묶는다(별도 가중치 배분 없이 이 단계 안에서 처리).
                _report(stage_base, _UNIT_STAGE_WEIGHTS[2][0])
                axios_instances = run_cancellable(lambda: _collect_axios_instances(tree, used_code), stop_event)
                this_props = run_cancellable(lambda: _collect_this_props(tree, used_code), stop_event)
                stage_base += unit_span * _UNIT_STAGE_WEIGHTS[2][1] / 100

                _report(stage_base, _UNIT_STAGE_WEIGHTS[3][0])
                funcs, func_eps, func_cands = run_cancellable(
                    lambda: _collect_functions(tree, filename, unit["label"], unit["line_offset"],
                                                used_code, axios_instances, axios_aliases, this_props),
                    stop_event)
                stage_base += unit_span * _UNIT_STAGE_WEIGHTS[3][1] / 100

                # 함수 밖(모듈 최상위) 코드의 sink 호출도 스캔 — _analyze_dataflow는 함수 경계에서
                # 멈추므로 이 호출은 각 함수 내부와 중복되지 않는다. defs/returns/out_calls는 버린다.
                _report(stage_base, _UNIT_STAGE_WEIGHTS[4][0])
                top_level = run_cancellable(
                    lambda: _analyze_dataflow(tree, [], used_code, unit["line_offset"], filename,
                                               unit["label"], None, axios_instances=axios_instances,
                                               axios_aliases=axios_aliases, this_props=this_props),
                    stop_event)
                stage_base += unit_span * _UNIT_STAGE_WEIGHTS[4][1] / 100
            except ScanCancelled:
                raise
            except Exception as e:
                parse_errors.append(f"{unit['label']}: 분석 실패 - {type(e).__name__}: {e}")
                continue

            all_functions.extend(funcs)
            all_endpoints.extend(func_eps)
            all_candidate_endpoints.extend(func_cands)
            all_endpoints.extend(top_level["endpoints"])
            all_candidate_endpoints.extend(top_level["candidate_endpoints"])
            mod_raw["imports"].extend(unit_mod_info["imports"])
            mod_raw["exports"].extend(unit_mod_info["exports"])
            mod_raw["reexports"].extend(unit_mod_info["reexports"])

        files_module_raw[filename] = mod_raw
        files_info.append({"name": filename, "kind": ext, "units": unit_ok,
                            "parse_errors": parse_errors, "external_refs": ext_refs})

    wait_or_cancel(stop_event, 0)
    _report(95, "호출 그래프 구성 중")
    module_graph = _build_module_graph(files_module_raw, [name for name, _ in sources])

    by_id = {f["id"]: f for f in all_functions}
    by_name: Dict[str, List[str]] = {}
    for f in all_functions:
        by_name.setdefault(f["name"], []).append(f["id"])
    by_file_name: Dict[Tuple[str, str], List[str]] = {}
    for f in all_functions:
        by_file_name.setdefault((f["file"], f["name"]), []).append(f["id"])

    # 호출마다 해소 등급을 매기고(import > local > include > name 폴백), 해소된 대상으로
    # called_by 역인덱스를 구성한다 (동일 caller→callee 쌍은 한 번만 기록).
    for f in all_functions:
        called_targets: set = set()
        for call in f["out_calls"]:
            ids, resolution = _resolve_call_targets(f["file"], call, module_graph, by_file_name, by_name)
            call["resolved_ids"] = ids
            call["resolution"] = resolution
            called_targets.update(ids)
        for callee_id in called_targets:
            if callee_id != f["id"]:
                by_id[callee_id]["called_by"].append(f["id"])

    # called_by가 확정된 뒤에만 1-hop 파라미터 전파가 가능 (호출자 목록에 의존)
    _report(99, "파라미터 전파 중")
    _propagate_endpoint_params(all_endpoints, by_id)

    # 표시용 정규화 경로(path)·플레이스홀더 출처 주석(placeholders) — url/params 원문은
    # 그대로 두고 화면 표시를 돕는 필드만 추가한다(확정 endpoints·저신뢰 candidate 모두).
    for ep in all_endpoints:
        ep["path"] = _normalize_display_path(ep["url"])
        ep["placeholders"] = _placeholder_origins(ep, by_id)
    for cand in all_candidate_endpoints:
        cand["path"] = _normalize_display_path(cand["url"])
        cand["placeholders"] = _placeholder_origins(cand, by_id)

    return {
        "files": files_info,
        "functions": all_functions,
        "modules": {"edges": module_graph["edges"], "unresolved": module_graph["unresolved"]},
        "endpoints": all_endpoints,
        "candidate_endpoints": all_candidate_endpoints,
    }


# ── 스캐너 연동(모듈화) ─────────────────────────────────────────────────────────
# 크롤러(_crawl.py)·SQLi/경로순회 입력 포인트 수집(_sqli_util.py)이 정규식 대신
# AST 기반으로 엔드포인트를 발견하는 데 쓰는 경량 진입점. "탐지"(무엇이 엔드포인트인가/
# URL·파라미터 재구성)는 이 함수 하나가 유일한 출처가 되도록 한다 — 여기(analyze()의
# sink 탐지 로직)가 좋아지면 JS 분석 화면과 모든 스캐너가 동시에 좋아진다. 실제 요청
# 가능 여부 판정(동일 도메인/로그아웃 경로/미해소 플레이스홀더 등 "게이트")은 스캐너
# 쪽 공유 모듈 `_endpoint_extract.py`가 별도로 담당한다(분석 화면은 게이트를 거치지
# 않고 미해소 엔드포인트도 그대로 보여주는 것이 목적이므로 의도적으로 분리).

def extract_endpoints(name: str, data: bytes) -> List[Dict[str, Any]]:
    """단일 소스 하나(페이지 HTML 또는 JS 스크립트 본문)에서 확정 endpoints만 재구성해
    반환하는 경량 진입점.

    내부적으로 analyze()를 그대로 재사용한다(v1: 별도 경량 경로 없음 — CFG·함수
    인벤토리 등 분석 화면 전용 정보는 버리고 endpoints만 취한다). candidate_endpoints
    (저신뢰 URL-형태 휴리스틱)는 포함하지 않는다 — 스캐너가 실제 요청을 쏘기엔
    신뢰도가 부족하기 때문(analyze() 자체의 정책과 동일).

    esprima/tree-sitter 미설치·파싱 실패(TS/JSX 등 미지원 문법) 시에도 analyze()의
    기존 유닛 단위 격리(parse_errors에 기록 후 스킵)에 의해 예외 없이 endpoints가
    빈 리스트로 나온다 — 호출자는 이 결과를 정규식 결과와 병합(union)해 쓰는 것을
    전제로 한다. 네트워크 요청 없음(analyze()와 동일한 하드 룰 승계).

    stop_event/progress_cb를 받지 않는다 — 크롤 중 페이지 1개 단위의 짧은 호출이라
    협조적 중단 대상이 아니다(대용량 배치 분석 전용인 analyze()의 중단 인프라와 다른
    사용처).
    """
    try:
        return analyze([(name, data)]).get("endpoints", [])
    except Exception:
        # 예상 밖의 예외(예: 극단적으로 중첩된 코드의 RecursionError)까지 흡수해
        # 호출자의 정규식 폴백 경로를 보존한다.
        return []


# ── 검색/조회 ─────────────────────────────────────────────────────────────────

def search_functions(analysis: Dict[str, Any], name_query: str = "", file_query: str = "",
                      limit: int = 200) -> List[Dict[str, Any]]:
    """파일명·함수명 부분/대소문자 무관 일치로 함수 후보 목록 검색."""
    nq = (name_query or "").strip().lower()
    fq = (file_query or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for f in analysis["functions"]:
        if nq and nq not in f["name"].lower():
            continue
        if fq and fq not in f["file"].lower():
            continue
        out.append({"id": f["id"], "name": f["name"], "file": f["file"], "unit": f["unit"],
                    "line": f["line"], "params": f["params"], "calls": f["calls"],
                    "called_by_count": len(f["called_by"])})
        if len(out) >= limit:
            break
    return out


def list_files_with_functions(analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
    """함수가 하나 이상 있는 파일 목록을 업로드 순서대로 반환 (파일 별 분기 흐름 탭의 파일 선택 목록용).

    함수가 하나도 없는 파일(파싱 실패·정적 마크업뿐인 HTML 등)은 목록에서 제외한다. 동일한
    파일명이 여러 번 업로드된 경우(예: 같은 이름의 파일을 실수로 중복 선택) `analyze()`는
    파일명만으로 함수를 귀속시키므로 이미 두 파일의 함수가 합산되어 집계된다 — 이 함수는
    첫 등장 항목 하나만 남겨 중복 없이 표시한다(합산된 count는 그대로 유지)."""
    counts: Dict[str, int] = {}
    for f in analysis["functions"]:
        counts[f["file"]] = counts.get(f["file"], 0) + 1
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for fi in analysis.get("files", []):
        name = fi["name"]
        if name not in counts or name in seen:
            continue
        seen.add(name)
        out.append({"name": name, "count": counts[name]})
    return out


def get_function(analysis: Dict[str, Any], func_id: str) -> Optional[Dict[str, Any]]:
    """함수 id로 상세 레코드(defs/returns/out_calls/called_by 전체) 조회."""
    for f in analysis["functions"]:
        if f["id"] == func_id:
            return f
    return None


def list_endpoints(analysis: Dict[str, Any], method_query: str = "", url_query: str = "",
                    kind_query: str = "", limit: int = 500) -> List[Dict[str, Any]]:
    """엔드포인트 목록을 method(대소문자 무관 완전일치)·url(부분/대소문자 무관 일치)·
    kind(완전일치) 조건으로 필터링해 반환. url 검색어는 원문(url)·표시용 정규화 경로(path)
    양쪽 모두와 대조한다 — `{contextRoot}api/login`처럼 원문에는 없는 선행 "/"가 path에는
    붙어 있어(_normalize_display_path) 사용자가 화면에 보이는 대로("/api/login") 검색해도
    찾을 수 있어야 하기 때문."""
    mq = (method_query or "").strip().upper()
    uq = (url_query or "").strip().lower()
    kq = (kind_query or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for ep in analysis.get("endpoints", []):
        if mq and ep["method"].upper() != mq:
            continue
        if uq and uq not in ep["url"].lower() and uq not in ep.get("path", "").lower():
            continue
        if kq and ep["kind"].lower() != kq:
            continue
        out.append(ep)
        if len(out) >= limit:
            break
    return out


def list_candidate_endpoints(analysis: Dict[str, Any], url_query: str = "",
                              limit: int = 500) -> List[Dict[str, Any]]:
    """URL-형태 휴리스틱으로 탐지된 저신뢰 엔드포인트 후보 목록을 url(부분/대소문자 무관
    일치, 원문·표시용 정규화 경로 양쪽 대조 — list_endpoints와 동일한 이유)로 필터링해
    반환. 확정 엔드포인트(endpoints)와 별도 목록이며, method는 항상 "?"(미상)·kind는
    항상 "heuristic"이라 그 기준의 필터는 두지 않는다."""
    uq = (url_query or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for ep in analysis.get("candidate_endpoints", []):
        if uq and uq not in ep["url"].lower() and uq not in ep.get("path", "").lower():
            continue
        out.append(ep)
        if len(out) >= limit:
            break
    return out


# ── Mermaid 소스 생성 ──────────────────────────────────────────────────────────

# to_mermaid_file_cfg 전용: subgraph(클러스터)가 많은 그래프에서 mermaid(10.9.1) 기본 레이아웃
# 엔진인 dagre가 "Cannot set properties of undefined (setting 'order')"로 깨지는 것을 실제
# 프로덕션 minify 번들 2종(함수 수백~수천 개)으로 재현 확인했다 — 원인은 dagre 내부(클러스터
# 경계용 border 노드 재배선 추정)이며 우리 쪽 생성 결과에는 결함이 없음을 확인했다(미선언 노드
# 참조 없음). mermaid에 이미 번들된 ELK 레이아웃 엔진으로 바꾸면 문제의 dagre 클러스터 코드
# 경로 자체를 타지 않아 재현 실패한 페이지 전부(실제 번들 43페이지 기준)가 정상 렌더된다(실측,
# 속도도 동등). 이 지시문을 mermaid 소스 맨 앞에 두면 flowchart(=graph)류 다이어그램의 레이아웃
# 엔진이 dagre 대신 ELK로 바뀐다. subgraph를 쓰는 유일한 그래프인 파일 단위 CFG에만 적용한다
# (다른 그래프는 클러스터가 없어 dagre로도 문제가 없어 그대로 둔다 — 불필요한 회귀 위험 배제).
_MERMAID_ELK_INIT = '%%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%'


def _mmd_escape(s: str, limit: int = 50) -> str:
    """mermaid 노드 라벨에 안전하게 넣기 위한 이스케이프(따옴표 제거 + 개행 제거 + 길이 제한)."""
    s = (s or "").replace('"', "'").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _mmd_edge(src_id: str, dst_id: str, label: Optional[str], indent: str = "  ") -> str:
    """CFG 엣지 한 줄을 mermaid 소스로 생성.

    엣지 라벨(-->|label|)은 노드 라벨과 달리 소스 코드 원문이 그대로 들어가면 괄호/중괄호/
    대괄호/파이프/따옴표 등에서 파서가 깨진다(mermaid 10.9.1 실측 — 예: switch case 라벨에
    `case "AsyncGeneratorFunction"`처럼 따옴표가 섞인 경우). 라벨을 인용부호로 감싸면 이
    특수문자들이 모두 안전하게 통과하므로 항상 감싸고, 안쪽 따옴표·개행은 _mmd_escape로
    정리한다. 빈 인용부호(-->|""|)도 파서 오류이므로 라벨이 없거나 이스케이프 결과가 비면
    라벨 없는 엣지로 그린다.
    """
    text = _mmd_escape(label, 60) if label else ""
    if text:
        return f'{indent}{src_id} -->|"{text}"| {dst_id}'
    return f"{indent}{src_id} --> {dst_id}"


def to_mermaid_call_graph(analysis: Dict[str, Any], center_id: Optional[str] = None,
                           max_nodes: int = 120, depth: int = 1,
                           cross_file_only: bool = False) -> str:
    """전체 호출 그래프 또는 특정 함수(center_id) 중심의 N-hop 서브그래프를 mermaid 소스로 생성.

    center_id 지정 시: depth 홉 이내에서 도달 가능한 호출/피호출 함수만 남겨 그래프를 좁힌다
    (전체 그래프는 파일이 많으면 가독성이 떨어짐). 간선은 각 호출의 resolved_ids(analyze()가
    import/require/include 등을 우선순위로 미리 해소해둔 결과)를 그대로 따라가므로, depth>=2에서는
    파일 경계를 넘는 호출도 이어서 확장된다. cross_file_only=True면 서로 다른 파일 간 호출
    간선만 표시한다(동일 파일 내부 호출 간선은 숨겨 파일 간 관계에 집중할 수 있다).

    확장된 함수 집합(keep)이 max_nodes를 넘으면 center_id를 항상 우선 포함하고 나머지를
    id 정렬로 결정적으로 채운다(과거에는 keep이 set이라 슬라이싱 순서가 비결정적이었고,
    사용자가 선택한 center_id 자신이 잘려나가는 결함이 있었다 — 실제 대형 번들로 재현 시
    샘플 60개 중 23개(38%)에서 발생 확인).
    """
    functions = analysis["functions"]
    by_id = {f["id"]: f for f in functions}

    def callee_ids(fid: str) -> List[str]:
        return [callee_id for c in by_id[fid]["out_calls"] for callee_id in (c.get("resolved_ids") or [])]

    if center_id and center_id in by_id:
        keep = {center_id}
        frontier = {center_id}
        for _ in range(max(depth, 1)):
            nxt: set = set()
            for fid in frontier:
                nxt.update(callee_ids(fid))
                nxt.update(by_id[fid]["called_by"])
            nxt -= keep
            if not nxt:
                break
            keep.update(nxt)
            frontier = nxt
        # center_id는 항상 포함(사용자가 선택한 함수가 그래프에서 잘려나가면 안 됨), 나머지는
        # id 정렬로 결정적 순서를 만든 뒤 남은 자리만큼만 채운다.
        node_ids = [center_id] + sorted(keep - {center_id})[:max(0, max_nodes - 1)]
    else:
        node_ids = [f["id"] for f in functions[:max_nodes]]

    id_map = {fid: f"n{i}" for i, fid in enumerate(node_ids)}
    lines = ["graph LR"]
    for fid in node_ids:
        f = by_id[fid]
        label = _mmd_escape(f'{f["name"]} ({f["file"]})')
        lines.append(f'  {id_map[fid]}["{label}"]')
        if fid == center_id:
            lines.append(f"  style {id_map[fid]} fill:#f96,stroke:#333,stroke-width:2px")

    seen = set()
    for fid in node_ids:
        f = by_id[fid]
        for callee_id in callee_ids(fid):
            if callee_id not in id_map or (fid, callee_id) in seen:
                continue
            if cross_file_only and by_id[callee_id]["file"] == f["file"]:
                continue
            lines.append(f"  {id_map[fid]} --> {id_map[callee_id]}")
            seen.add((fid, callee_id))
    return "\n".join(lines)


def to_mermaid_dataflow(func: Dict[str, Any], analysis: Optional[Dict[str, Any]] = None,
                         expand: bool = False, max_nodes: int = 80) -> str:
    """함수 하나의 내부 데이터플로우(파라미터→지역변수→return/외부호출)를 mermaid 소스로 생성.

    좌→우 흐름: param 노드(둥근 모양) → 지역변수 정의 노드(사각) → return/call 노드(알약 모양).
    expand=True + analysis 지정 시: 각 호출의 resolved_ids(analyze()가 import/require/local
    우선순위로 미리 해소해둔 대상)가 있으면 그 함수의 데이터플로우까지 같은 그래프에 인라인
    전개한다 — 호출 인자가 콜리(callee)의 파라미터 노드로 그대로 이어져 파일 경계를 넘는
    데이터 흐름을 볼 수 있다. 재귀 호출·순환 참조는 방문 집합으로 차단하고, max_nodes로
    그래프 폭발을 막는다(기본값은 expand=False로, 기존 단일 함수 뷰와 동일하게 동작한다).
    """
    lines = ["graph LR"]
    node_id: Dict[str, str] = {}
    counter = [0]
    by_id = {f["id"]: f for f in analysis["functions"]} if (expand and analysis) else {}
    visiting: set = set()

    def new_node(key: str, label: str, shape: str = "rect") -> Optional[str]:
        if key in node_id:
            return node_id[key]
        if len(node_id) >= max_nodes:
            return None
        nid = f"d{counter[0]}"
        counter[0] += 1
        node_id[key] = nid
        safe = _mmd_escape(label, 60)
        if shape == "round":
            lines.append(f'  {nid}(["{safe}"])')
        elif shape == "stadium":
            lines.append(f'  {nid}{{{{"{safe}"}}}}')
        else:
            lines.append(f'  {nid}["{safe}"]')
        return nid

    def render(fn: Dict[str, Any], prefix: str, incoming: Dict[str, str]) -> None:
        """fn의 데이터플로우를 렌더링. incoming은 fn 파라미터명 → 호출부에서 이어받은 노드id."""
        param_nodes: Dict[str, str] = {}
        for p in fn["params"]:
            src = incoming.get(p)
            if src:
                param_nodes[p] = src  # 호출부 인자 노드를 그대로 파라미터 노드로 재사용
            else:
                nid = new_node(f"{prefix}param:{p}", f"param: {p}", "round")
                if nid:
                    param_nodes[p] = nid

        def_nodes: Dict[str, str] = {}

        def resolve(name: str) -> Optional[str]:
            return param_nodes.get(name) or def_nodes.get(name)

        for d in fn["defs"]:
            nid = new_node(f"{prefix}def:{d['var']}#{d['line']}", f"{d['var']} = {d['expr']}")
            if not nid:
                continue
            def_nodes[d["var"]] = nid
            for dep in d["depends_on"]:
                src = resolve(dep)
                if src:
                    lines.append(f"  {src} --> {nid}")

        for i, r in enumerate(fn["returns"]):
            rid = new_node(f"{prefix}return#{i}", f"return {r['expr']}", "stadium")
            if not rid:
                continue
            for dep in r["depends_on"]:
                src = resolve(dep)
                if src:
                    lines.append(f"  {src} --> {rid}")

        for i, c in enumerate(fn["out_calls"]):
            arg_srcs = [src for a in c["args"] for src in
                        (resolve(dep) for dep in a.get("depends_on", [])) if src]

            target_id = (c.get("resolved_ids") or [None])[0] if expand else None
            if target_id and target_id in by_id and target_id != fn["id"] and target_id not in visiting:
                callee = by_id[target_id]
                visiting.add(target_id)
                call_incoming = {p: arg_srcs[i] for i, p in enumerate(callee["params"]) if i < len(arg_srcs)}
                render(callee, f"{prefix}{target_id}:", call_incoming)
                visiting.discard(target_id)
                continue

            cid = new_node(f"{prefix}call#{i}", f"call: {c['expr']}", "stadium")
            if not cid:
                continue
            for src in arg_srcs:
                lines.append(f"  {src} --> {cid}")

    render(func, "", {})
    return "\n".join(lines)


def to_mermaid_module_graph(analysis: Dict[str, Any], max_nodes: int = 120) -> str:
    """analyze()가 구성한 파일 간 의존 관계(modules.edges)를 파일 단위 mermaid 그래프로 생성.

    노드는 업로드된 파일, 간선은 import/require/reexport/include/script 중 어떤 관계로
    연결됐는지 라벨로 표시한다. 파일이 많으면 max_nodes로 잘라 가독성을 유지한다.
    """
    files = analysis.get("files", [])
    edges = analysis.get("modules", {}).get("edges", [])

    node_names = [f["name"] for f in files][:max_nodes]
    id_map = {name: f"m{i}" for i, name in enumerate(node_names)}

    lines = ["graph LR"]
    for name in node_names:
        lines.append(f'  {id_map[name]}["{_mmd_escape(name)}"]')

    seen = set()
    for e in edges:
        src, dst, kind = e["from"], e["to"], e["kind"]
        if src not in id_map or dst not in id_map:
            continue
        key = (src, dst, kind)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {id_map[src]} -->|{kind}| {id_map[dst]}")
    return "\n".join(lines)


def to_mermaid_cfg(func: Dict[str, Any]) -> str:
    """함수 레코드 하나(get_function() 반환값)의 제어흐름 그래프(cfg)를 graph TD mermaid 소스로 생성.

    block 노드(사각)는 연속된 단순 문장 묶음, decision 노드(마름모)는 if/loop/switch의
    조건이다. has_sink=True인 노드(HTTP 요청 sink를 포함한 문장)는 주황색으로 강조해
    "이 sink에 도달하려면 어떤 분기를 거쳐야 하는지" IDA 스타일로 한눈에 보이게 한다.
    """
    cfg = func.get("cfg")
    if not cfg or not cfg.get("nodes"):
        return 'graph TD\n  empty["CFG 없음 (빈 함수 본문)"]'

    id_map = {n["id"]: f"g{i}" for i, n in enumerate(cfg["nodes"])}
    lines = ["graph TD"]
    for n in cfg["nodes"]:
        nid = id_map[n["id"]]
        label = _mmd_escape(n["label"], 260)
        if n["kind"] == "decision":
            lines.append(f'  {nid}{{"{label}"}}')
        else:
            lines.append(f'  {nid}["{label}"]')
        if n.get("has_sink"):
            lines.append(f"  style {nid} fill:#f96,stroke:#333,stroke-width:2px")

    for e in cfg.get("edges", []):
        if e["from"] not in id_map or e["to"] not in id_map:
            continue
        a, b = id_map[e["from"]], id_map[e["to"]]
        lines.append(_mmd_edge(a, b, e.get("label")))

    if cfg.get("truncated"):
        lines.append('  trunc["...(노드 상한 도달 — 이후 생략됨)"]')
    return "\n".join(lines)


# ── 파일 단위 CFG 그래프의 정렬·id 규칙 (그래프 생성과 위치 검색이 공유) ──────────────
# to_mermaid_file_cfg(그래프 생성)와 find_file_cfg_functions(함수 위치 검색)는 반드시 같은
# 정렬 순서·같은 페이지 분할·같은 노드 id 규칙을 봐야 한다. 검색 결과가 알려주는 페이지와
# 노드 id로 화면에서 그 함수를 찾아 스크롤하기 때문에, 한쪽만 바뀌면 "검색은 되는데 엉뚱한
# 곳으로 이동"하는 조용한 결함이 된다. 규칙을 아래 세 함수 한 곳에만 두어 드리프트를 막는다.

def _file_cfg_sorted_funcs(analysis: Dict[str, Any], file_name: str) -> List[Dict[str, Any]]:
    """파일에 속한 함수를 그래프에 그리는 순서(라인 오름차순)로 반환."""
    return sorted((f for f in analysis["functions"] if f["file"] == file_name), key=lambda f: f["line"])


def _file_cfg_prefix(index_in_page: int) -> str:
    """페이지 안 index_in_page번째 함수의 mermaid 노드 id 접두사.

    함수 묶음(subgraph) id는 `<접두사>sg`, 그 함수의 CFG 노드 id는 `<접두사><노드순번>`이다.
    """
    return f"ff{index_in_page}_"


def _file_cfg_sub_label(f: Dict[str, Any]) -> str:
    """함수 묶음(subgraph)에 표시할 라벨 텍스트 (`함수명 (:라인)`)."""
    return _mmd_escape(f'{f["name"]} (:{f["line"]})', 60)


def to_mermaid_file_cfg(analysis: Dict[str, Any], file_name: str, page: int = 0) -> Dict[str, Any]:
    """파일 하나에 속한 함수의 CFG를 함수별 subgraph로 묶어 파일 단위 분기 흐름을 graph TD
    mermaid 소스로 생성한다 (IDA 스타일 함수 그래프의 파일 전체 버전). 함수 수가 많은 파일은
    한 페이지(_FILE_CFG_PAGE_SIZE=80개)씩 나눠 반환한다(아래 페이지네이션 참고).

    함수마다 자신의 cfg(nodes/edges)를 재파싱 없이 그대로 subgraph 안에 그리고(to_mermaid_cfg와
    동일한 노드/엣지 렌더링 규칙 — decision은 마름모, has_sink는 주황색 강조), 같은 파일 내
    함수 호출 관계(out_calls.resolved_ids 중 이 페이지에 포함된 대상)는 호출자 함수의 entry
    노드 → 피호출 함수의 entry 노드로 점선 화살표를 그어 함수 흐름을 한눈에 보이게 한다
    (호출부의 정확한 CFG 노드가 아닌 함수 진입점 기준 근사 — 설계 합의). 다른 페이지에 있는
    함수로의 호출은 그리지 않는다(그 페이지에 없는 노드를 참조할 수 없음).

    페이지네이션: 함수를 라인 순으로 정렬한 뒤 _FILE_CFG_PAGE_SIZE개씩 나눠 page번째(0-based)
    페이지에 속한 함수만 그린다(가독성 상한 — 사람이 한 화면에서 식별 가능한 함수 수). 이전
    버전은 "파일 전체 노드 총량 예산 소진 시 이후 함수 생략(break)" 방식이었으나 앞쪽 큰 함수
    하나가 예산을 다 쓰면 뒤쪽 작은 함수들이 전부 생략되는 결함이 있었다 — 함수 개수 기준
    고정 페이지네이션은 모든 함수가 어느 한 페이지에는 반드시 나타나도록 보장해 이 결함을
    해소한다. mermaid 소스 맨 앞에 _MERMAID_ELK_INIT 지시문을 붙여 레이아웃 엔진을 ELK로
    지정한다(dagre의 클러스터 렌더링 버그 회피 — 위 상수 정의 주석 참고).

    노드 id 규칙은 _file_cfg_prefix()에 정의돼 있다(함수 묶음 `ff{페이지내순번}_sg`, CFG 노드
    `ff{페이지내순번}_{노드순번}`). 화면에서 특정 함수가 몇 페이지의 어느 노드로 그려지는지는
    같은 규칙을 공유하는 find_file_cfg_functions()로 역조회한다.

    반환: {mermaid, page, page_size, total_functions, total_pages}. 이 파일에 함수가 없으면
    total_functions=0·total_pages=0이고 mermaid는 플레이스홀더 노드 하나만 있는 그래프.
    """
    all_funcs = _file_cfg_sorted_funcs(analysis, file_name)
    total_functions = len(all_funcs)
    page_size = _FILE_CFG_PAGE_SIZE
    total_pages = (total_functions + page_size - 1) // page_size if total_functions else 0

    if not all_funcs:
        return {"mermaid": 'graph TD\n  empty["이 파일에는 함수가 없습니다"]',
                "page": 0, "page_size": page_size, "total_functions": 0, "total_pages": 0}

    page = min(max(page, 0), total_pages - 1)  # 범위 밖 페이지 요청은 가장 가까운 유효 페이지로 고정
    start = page * page_size
    funcs = all_funcs[start:start + page_size]

    lines = [_MERMAID_ELK_INIT, "graph TD"]
    entry_map: Dict[str, str] = {}   # func_id -> 전역 고유 entry 노드 id (함수 간 호출 연결용)
    included: set = set()            # subgraph에 실제로 포함된 func_id (이 페이지 내부만)

    for fi, f in enumerate(funcs):
        cfg = f.get("cfg")
        node_list = cfg["nodes"] if cfg else []
        if not node_list:
            continue

        prefix = _file_cfg_prefix(fi)
        id_map = {n["id"]: f"{prefix}{i}" for i, n in enumerate(node_list)}

        sub_label = _file_cfg_sub_label(f)
        lines.append(f'  subgraph {prefix}sg["{sub_label}"]')
        for n in node_list:
            nid = id_map[n["id"]]
            label = _mmd_escape(n["label"], 260)
            if n["kind"] == "decision":
                lines.append(f'    {nid}{{"{label}"}}')
            else:
                lines.append(f'    {nid}["{label}"]')
            if n.get("has_sink"):
                lines.append(f"    style {nid} fill:#f96,stroke:#333,stroke-width:2px")
        for e in cfg.get("edges", []):
            if e["from"] not in id_map or e["to"] not in id_map:
                continue
            a, b = id_map[e["from"]], id_map[e["to"]]
            lines.append(_mmd_edge(a, b, e.get("label"), indent="    "))
        lines.append("  end")

        if cfg.get("entry") in id_map:
            entry_map[f["id"]] = id_map[cfg["entry"]]
        included.add(f["id"])

    seen_call_edges = set()
    for f in funcs:
        if f["id"] not in included or f["id"] not in entry_map:
            continue
        for c in f.get("out_calls", []):
            for callee_id in (c.get("resolved_ids") or []):
                if callee_id == f["id"] or callee_id not in included or callee_id not in entry_map:
                    continue
                key = (f["id"], callee_id)
                if key in seen_call_edges:
                    continue
                seen_call_edges.add(key)
                lines.append(f'  {entry_map[f["id"]]} -.-> {entry_map[callee_id]}')

    return {
        "mermaid": "\n".join(lines),
        "page": page,
        "page_size": page_size,
        "total_functions": total_functions,
        "total_pages": total_pages,
    }


def find_file_cfg_functions(analysis: Dict[str, Any], file_name: str, name_query: str = "",
                             limit: int = 100) -> Dict[str, Any]:
    """파일 별 분기 흐름 그래프에서 함수를 찾아 "몇 페이지의 어느 노드인지" 반환한다.

    to_mermaid_file_cfg가 그리는 그래프는 함수가 많은 파일에서 페이지로 나뉘고 화면도 넓어져
    눈으로 특정 함수를 찾기 어렵다 — 이 함수는 그래프 생성과 동일한 정렬·페이지 분할·노드 id
    규칙(_file_cfg_sorted_funcs / _file_cfg_prefix / _file_cfg_sub_label)을 그대로 사용해
    "그 함수가 그려지는 페이지 번호 + 화면에서 찾을 노드 id"를 알려준다. 대시보드는 이 값으로
    해당 페이지를 그린 뒤 그 노드로 스크롤·강조한다.

    name_query는 함수명 부분/대소문자 무관 일치(빈 값이면 이 파일의 전체 함수 목록).

    각 항목:
      id/name/line — 함수 식별 정보(라인 오름차순)
      page         — 그 함수가 그려지는 페이지(0-based)
      sg_id        — 그래프 안 함수 묶음(subgraph) id. 그려지지 않는 함수면 None
      entry_id     — 함수 진입 노드 id. 함수 묶음 테두리 없이 평면으로 렌더된 화면의 폴백용
      label        — 묶음 라벨 텍스트. id로 못 찾을 때 라벨 텍스트로 찾기 위한 폴백용
      drawn        — CFG 노드가 하나도 없어(빈 본문) 그래프에 그려지지 않는 함수면 False

    반환: {results, limit, page_size, total_functions, total_pages}.
    """
    all_funcs = _file_cfg_sorted_funcs(analysis, file_name)
    page_size = _FILE_CFG_PAGE_SIZE
    total_functions = len(all_funcs)
    total_pages = (total_functions + page_size - 1) // page_size if total_functions else 0

    nq = (name_query or "").strip().lower()
    results: List[Dict[str, Any]] = []
    for idx, f in enumerate(all_funcs):
        if nq and nq not in f["name"].lower():
            continue
        prefix = _file_cfg_prefix(idx % page_size)   # 접두사는 전체 순번이 아닌 "페이지 안 순번" 기준
        cfg = f.get("cfg")
        node_list = cfg["nodes"] if cfg else []
        # 진입 노드 id — to_mermaid_file_cfg의 id_map(노드 순번 기반)과 같은 방식으로 계산
        entry_id = None
        if node_list and cfg.get("entry"):
            for i, n in enumerate(node_list):
                if n["id"] == cfg["entry"]:
                    entry_id = f"{prefix}{i}"
                    break
        results.append({
            "id": f["id"],
            "name": f["name"],
            "line": f["line"],
            "page": idx // page_size,
            "sg_id": f"{prefix}sg" if node_list else None,
            "entry_id": entry_id,
            "label": _file_cfg_sub_label(f),
            "drawn": bool(node_list),
        })
        if len(results) >= limit:
            break

    return {
        "results": results,
        "limit": limit,            # 결과가 이 수에 걸려 잘렸는지 화면에서 판단하기 위해 함께 반환
        "page_size": page_size,
        "total_functions": total_functions,
        "total_pages": total_pages,
    }
