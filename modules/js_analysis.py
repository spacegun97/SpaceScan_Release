"""
js_analysis.py — JS/HTML/XFDL/XADL/XJS/XML 정적 데이터플로우 분석 모듈
==============================================================================
탐지 모듈(scan() 인터페이스)·SQLi 추출·엑셀 취합·OSINT 정찰과 완전히 분리된 별도 모드.
업로드된 소스에서 함수를 찾아내고, 함수별 내부 데이터플로우(입력→처리→출력)와
함수 간 호출 관계(호출 그래프)를 정적으로 재구성한다. 네트워크 요청 없음(완전 오프라인).

지원 입력 형식:
  .js    — 파일 전체를 단일 스크립트로 파싱
  .html/.htm — <script> 블록 + 인라인 이벤트 핸들러 속성(onclick 등) 추출
               (외부 <script src="..."> 는 URL만 기록, 절대 fetch하지 않음)
  .xfdl/.xadl/.xml — 투비소프트 Nexacro/XPlatform 폼·앱정의 XML. <Script> 엘리먼트 CDATA 추출
  .xjs   — Nexacro 스크립트 파일. 우선 XML(<Script> 루트)로 파싱을 시도하고,
           실패하면(순수 JS로 저장된 경우) 파일 전체를 단일 JS 유닛으로 폴백

**하드 룰: 이 모듈은 어떤 외부 호스트로도 요청을 보내지 않는다.** 업로드된 바이트만
읽어 esprima(순수 파이썬 JS 파서)로 파싱한다.

알려진 한계 (설계 단계에서 사용자와 합의된 근사치 분석 범위):
  - 파서가 esprima이므로 ES2017까지만 지원 (optional chaining `?.`, nullish
    coalescing `??` 등 ES2020+ 문법은 파싱 실패 → 해당 유닛만 parse_errors에 기록하고 스킵)
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
"""
import html.parser as _htmlparser
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple

# esprima는 최상단이 아닌 _try_parse() 내부에서 지연 import한다 — app.py가 이 모듈을
# import하는 시점(앱 기동)에는 esprima 미설치 여도 죽지 않아야 하고, 실제 분석
# 진입 시점에 app.py의 _ensure_jsanalysis_deps()가 먼저 설치를 보장한다.

# ── 상수 ────────────────────────────────────────────────────────────────────

SUPPORTED_EXTS = frozenset({".js", ".html", ".htm", ".xfdl", ".xadl", ".xjs", ".xml"})

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


def _analyze_dataflow(body, params: List[str], src: str, line_offset: int,
                       is_concise_arrow: bool = False) -> Dict[str, Any]:
    """함수 본문 하나를 스캔해 지역변수 정의(defs)/반환(returns)/외부호출(out_calls)을 추출.

    흐름 비민감 근사치: if/else·루프 분기를 모두 순회하되 상호배타성은 구분하지 않는다.
    중첩 함수 정의(FunctionDeclaration/Expression/Arrow)는 경계로 삼아 내려가지 않는다
    — 그 함수는 별도 인벤토리 항목으로 자기 자신의 dataflow를 갖는다.
    """
    known = set(params)
    defs: List[Dict[str, Any]] = []
    returns: List[Dict[str, Any]] = []
    out_calls: List[Dict[str, Any]] = []

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
                    args.append({"kind": "expr", "depends_on": sorted(dep)})
            out_calls.append({"callee": callee, "obj": _call_root_name(node.callee), "args": args,
                               "line": _line(node), "expr": _slice(src, node)})
            for a in node.arguments:  # 중첩 호출 f(g(x)) 지원
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
                defs.append({"var": n, "depends_on": sorted(dep),
                             "expr": _slice(src, node.init) if node.init is not None else "",
                             "line": _line(node)})
            if node.init is not None:
                visit(node.init)
            return

        if t == "AssignmentExpression":
            if node.operator == "=" and getattr(node.left, "type", None) == "Identifier":
                name = node.left.name
                dep = set()
                _collect_used(node.right, known, dep)
                known.add(name)
                defs.append({"var": name, "depends_on": sorted(dep),
                             "expr": _slice(src, node.right), "line": _line(node)})
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

    return {"defs": defs, "returns": returns, "out_calls": out_calls}


# ── 함수 인벤토리 (파일 전체 재귀 탐색) ────────────────────────────────────────

def _collect_functions(program, file: str, unit_label: str, line_offset: int, src: str) -> List[Dict[str, Any]]:
    """유닛(파일 전체 또는 script 블록) 하나에서 모든 함수(중첩 포함)를 찾아 인벤토리 생성.

    이름 없는 함수 표현식은 대입 위치(변수/속성/this.x/클래스 메서드)에서 이름 힌트를
    끌어온다 (const login = function(){} → 'login', Foo.bar(){} → 'Foo.bar').
    """
    functions: List[Dict[str, Any]] = []
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
            dataflow = _analyze_dataflow(body_node, params, src, line_offset, is_concise_arrow=is_concise)
            fid = f"{file}::{full_name}@{line}"
            functions.append({
                "id": fid, "file": file, "unit": unit_label, "name": full_name,
                "line": line, "params": params,
                "defs": dataflow["defs"], "returns": dataflow["returns"],
                "out_calls": dataflow["out_calls"],
                "calls": sorted(set(c["callee"] for c in dataflow["out_calls"])),
                "called_by": [],  # analyze()에서 전체 파일 취합 후 역인덱스로 채움
            })
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
    return functions


# ── 파일 어댑터: HTML ─────────────────────────────────────────────────────────

class _ScriptCollector(_htmlparser.HTMLParser):
    """HTMLParser 서브클래스 — <script> 블록 텍스트 + 인라인 이벤트 핸들러 속성 수집.

    stdlib html.parser는 관대한(lenient) 파서라 깨진 HTML도 최대한 진행한다
    (이 프로젝트의 '실용적 근사치 분석' 방침과 일치).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.units: List[Dict[str, Any]] = []
        self.external_refs: List[str] = []
        self._in_script = False
        self._script_start_line = 0
        self._script_buf: List[str] = []
        self._script_is_js = True

    def handle_starttag(self, tag, attrs) -> None:
        attrs_d = dict(attrs)
        if tag.lower() == "script":
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
        else:
            # 인라인 이벤트 핸들러: onclick="..." 등 (data-*/커스텀 속성은 화이트리스트로 오탐 방지)
            for name, value in attrs:
                if name and name.lower() in HTML_EVENT_ATTRS and value:
                    line = self.getpos()[0]
                    self.units.append({"label": f"inline:{name}@L{line}", "code": value, "line_offset": line - 1})

    def handle_data(self, data) -> None:
        if self._in_script:
            self._script_buf.append(data)

    def handle_endtag(self, tag) -> None:
        if tag.lower() == "script" and self._in_script:
            if self._script_is_js and self._script_buf:
                code = "".join(self._script_buf)
                if code.strip():
                    self.units.append({"label": f"<script>@L{self._script_start_line}", "code": code,
                                        "line_offset": self._script_start_line - 1})
            self._in_script = False
            self._script_buf = []


def _extract_from_html(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """HTML 텍스트에서 (분석 유닛 목록, 외부 스크립트 URL 목록) 추출."""
    parser = _ScriptCollector()
    try:
        parser.feed(text)
    except Exception:
        pass  # 깨진 HTML도 그때까지 수집된 것은 반환 (관대한 파싱 정책)
    return parser.units, parser.external_refs


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
    """esprima로 스크립트 파싱. classic script 실패 시 ES module 문법(import/export)으로 재시도."""
    import esprima
    try:
        return esprima.parseScript(code, options={"loc": True, "range": True, "tolerant": True})
    except Exception:
        return esprima.parseModule(code, options={"loc": True, "range": True, "tolerant": True})


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

def analyze(sources: List[Tuple[str, bytes]]) -> Dict[str, Any]:
    """업로드된 (파일명, 바이트) 목록을 받아 파일별 추출 → 유닛별 파싱 → 함수 인벤토리 →
    파일 간 모듈 의존 관계(import/require/include/script src) → 전역 호출 그래프(called_by
    역인덱스)까지 구성한 종합 분석 결과를 반환.

    반환 dict:
      files:     파일별 처리 통계 (kind, units, parse_errors, external_refs)
      functions: 전체 함수 인벤토리. out_calls 각 항목에 resolved_ids(해소된 대상 함수 id 목록)·
                 resolution(해소 등급: import/require/local/include/name/unresolved)이 추가됨.
                 파일 경계를 넘어 import/require/include/script src로 우선 연결하고,
                 해소 실패 시에만 이름 매칭(name)으로 폴백한다.
      modules:   파일 간 의존 관계 {edges: [...], unresolved: [...]}
    """
    files_info: List[Dict[str, Any]] = []
    all_functions: List[Dict[str, Any]] = []
    files_module_raw: Dict[str, Dict[str, List[Any]]] = {}

    for filename, raw_bytes in sources:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in SUPPORTED_EXTS:
            files_info.append({"name": filename, "kind": "unsupported", "units": 0,
                                "parse_errors": [f"지원하지 않는 확장자입니다 ({ext or '없음'})"],
                                "external_refs": []})
            continue

        try:
            if ext == ".js":
                units = [{"label": filename, "code": _decode_bytes(raw_bytes), "line_offset": 0}]
                ext_refs: List[str] = []
            elif ext in (".html", ".htm"):
                units, ext_refs = _extract_from_html(_decode_bytes(raw_bytes))
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

        parse_errors: List[str] = []
        unit_ok = 0
        mod_raw: Dict[str, List[Any]] = {"imports": [], "exports": [], "reexports": [],
                                          "includes": [], "script_refs": ext_refs}
        for unit in units:
            if ext in (".xjs", ".xfdl", ".xadl", ".xml"):
                # include는 표준 JS 구문이 아니라 파싱 실패 시 무력화되므로, 파싱 성공 여부와
                # 무관하게 원본에서 직접 추출해둔다.
                mod_raw["includes"].extend(_extract_includes(unit["code"]))
            try:
                tree, used_code = _parse_unit(unit["code"])
            except Exception as e:
                # 유닛 하나가 파싱 실패해도 나머지 유닛/파일은 계속 진행 (배치 중단 안 함)
                parse_errors.append(f"{unit['label']}: 파싱 실패 - {e}")
                continue
            unit_ok += 1
            all_functions.extend(
                _collect_functions(tree, filename, unit["label"], unit["line_offset"], used_code)
            )
            unit_mod_info = _collect_module_info(tree, used_code)
            mod_raw["imports"].extend(unit_mod_info["imports"])
            mod_raw["exports"].extend(unit_mod_info["exports"])
            mod_raw["reexports"].extend(unit_mod_info["reexports"])

        files_module_raw[filename] = mod_raw
        files_info.append({"name": filename, "kind": ext, "units": unit_ok,
                            "parse_errors": parse_errors, "external_refs": ext_refs})

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

    return {
        "files": files_info,
        "functions": all_functions,
        "modules": {"edges": module_graph["edges"], "unresolved": module_graph["unresolved"]},
    }


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


def get_function(analysis: Dict[str, Any], func_id: str) -> Optional[Dict[str, Any]]:
    """함수 id로 상세 레코드(defs/returns/out_calls/called_by 전체) 조회."""
    for f in analysis["functions"]:
        if f["id"] == func_id:
            return f
    return None


# ── Mermaid 소스 생성 ──────────────────────────────────────────────────────────

def _mmd_escape(s: str, limit: int = 50) -> str:
    """mermaid 노드 라벨에 안전하게 넣기 위한 이스케이프(따옴표 제거 + 개행 제거 + 길이 제한)."""
    s = (s or "").replace('"', "'").replace("\n", " ").strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def to_mermaid_call_graph(analysis: Dict[str, Any], center_id: Optional[str] = None,
                           max_nodes: int = 120, depth: int = 1,
                           cross_file_only: bool = False) -> str:
    """전체 호출 그래프 또는 특정 함수(center_id) 중심의 N-hop 서브그래프를 mermaid 소스로 생성.

    center_id 지정 시: depth 홉 이내에서 도달 가능한 호출/피호출 함수만 남겨 그래프를 좁힌다
    (전체 그래프는 파일이 많으면 가독성이 떨어짐). 간선은 각 호출의 resolved_ids(analyze()가
    import/require/include 등을 우선순위로 미리 해소해둔 결과)를 그대로 따라가므로, depth>=2에서는
    파일 경계를 넘는 호출도 이어서 확장된다. cross_file_only=True면 서로 다른 파일 간 호출
    간선만 표시한다(동일 파일 내부 호출 간선은 숨겨 파일 간 관계에 집중할 수 있다).
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
        node_ids = list(keep)[:max_nodes]
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
