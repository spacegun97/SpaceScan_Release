"""_js_ts_adapter.py — tree-sitter-javascript CST → esprima 호환 ESTree AST 어댑터
==============================================================================
js_analysis.py의 파싱 백엔드 체인 3차 폴백(esprima parseScript/parseModule 모두 실패 시)
전용. esprima(ES2017)가 파싱하지 못하는 ES2020+ 문법(옵셔널 체이닝 `?.`, nullish
coalescing `??`, 클래스 필드/private 필드, static 블록 등)이 있는 유닛을 이 어댑터로
재시도한다.

**정규화 계약**: js_analysis.py의 데이터플로우 로직(~120곳)은 esprima가 반환하는
ESTree 노드 모양(타입 문자열 비교 + 점(.) 속성 접근 + `vars(node)` 기반 제네릭 순회)에
묶여 있다. 이 어댑터는 tree-sitter의 CST를 그 계약과 동일한 모양(동일 타입 문자열,
동일 속성명, `.range`=문자 오프셋 튜플, `.loc.start.line`=1-based 줄번호)으로 변환해
반환하므로 js_analysis.py 쪽 다운스트림 코드는 무변경으로 두 백엔드를 동일하게 처리한다.

**근사치 범위** (esprima 백엔드와 동일한 "실용적 근사치 분석" 기조 유지):
  - 옵셔널 체이닝(`?.`)은 일반 멤버/호출 접근과 동일하게 변환한다(`.optional` 플래그
    미부여, `ChainExpression` 래핑 없음) — esprima 4.0.1 자체가 이 스펙 이전 버전이라
    다운스트림도 애초에 이를 구분하지 않으므로 정보 손실이 없다.
  - 정규식 리터럴은 esprima 백엔드와 동일하게 별도 타입("RegexLiteral")으로 분류해
    `_reconstruct_str()`의 원문 슬라이스 폴백 경로를 그대로 타게 한다.
  - BigInt(`10n`)는 접미사 `n`을 제거하고 일반 정수로 근사한다.
  - 배열 구멍(`[1, , 3]`)은 tree-sitter 문법 자체가 빈 슬롯을 노드로 표현하지 않아
    무시된다(요소 개수가 원본보다 적게 나올 수 있음 — 함수 인자/식별자 추출용 분석
    목적상 무해).
  - TypeScript 타입 주석·데코레이터·JSX는 지원 범위 밖(문법 자체가 다름 — 별도 파서 필요).
"""
import re
import threading
from array import array
from bisect import bisect_right
from typing import Any, List, Optional, Tuple

# _mk()가 매 호출부마다 ctx를 넘겨받지 않고도 range/loc을 계산할 수 있도록 스레드로컬에
# 보관한다(parse() 진입 시 설정). Flask가 동시 요청을 여러 스레드로 처리해도 스레드별로
# 격리되므로 안전하다 — convert()/각 _convert_* 헬퍼가 ctx를 명시적으로 주고받는 것과는
# 별개로, _mk() 내부 전용 편의 경로다.
_tls = threading.local()

# ── ESTree 노드 표현 ──────────────────────────────────────────────────────────
#
# js_analysis.py의 제네릭 순회(`vars(node).items()`)가 "range"/"loc"/"type"만 건너뛰고
# 나머지 속성을 전부 재귀 방문하므로, 여기 인스턴스의 __dict__에는 ESTree 필드만 담아야
# 한다(내부 파서 상태를 실어 보내면 안 됨).


class Node:
    """ESTree 노드의 최소 표현 — 순수 __dict__ 기반(슬롯 없음)이라 vars(node)로 순회 가능."""

    def __init__(self, type_: str, **fields: Any) -> None:
        self.type = type_
        self.__dict__.update(fields)


class _Position:
    __slots__ = ("line", "column")

    def __init__(self, line: int, column: int) -> None:
        self.line = line
        self.column = column


class _SourceLocation:
    __slots__ = ("start", "end")

    def __init__(self, start: _Position, end: _Position) -> None:
        self.start = start
        self.end = end


class _TemplateElementValue:
    """TemplateElement.value — esprima와 동일하게 .cooked 속성만 노출."""
    __slots__ = ("cooked",)

    def __init__(self, cooked: Optional[str]) -> None:
        self.cooked = cooked


# ── 바이트 오프셋 → 문자 오프셋 변환 ────────────────────────────────────────────
#
# tree-sitter는 UTF-8 바이트 오프셋을, js_analysis.py의 `_slice()`는 파이썬 str(문자
# 단위) 오프셋을 쓴다. 두 백엔드가 같은 `used_code` 문자열을 공유해야 하므로(_parse_unit
# 계약) 노드 range를 문자 오프셋으로 환산해야 한다. 줄 번호(.loc.start.line)는 개행문자가
# UTF-8에서 항상 1바이트이므로 변환 없이 tree-sitter의 row를 그대로 쓸 수 있다.

def _build_byte_to_char(code: str):
    """문자 인덱스 i가 시작되는 바이트 오프셋 배열을 만들고, 바이트오프셋→문자오프셋
    변환 함수를 반환한다. 노드 경계는 항상 UTF-8 문자 경계와 일치하므로 이분 탐색으로
    정확히 맞아떨어진다.
    """
    offsets = array("q")
    b = 0
    for ch in code:
        offsets.append(b)
        b += len(ch.encode("utf-8"))
    offsets.append(b)  # 끝 지점 sentinel

    def byte_to_char(byte_off: int) -> int:
        return bisect_right(offsets, byte_off) - 1

    return byte_to_char


# ── 문자열/숫자 리터럴 디코딩 ────────────────────────────────────────────────────

_ESCAPE_MAP = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0",
    "\\": "\\", "'": "'", '"': '"', "`": "`",
}


def _decode_escape(text: str) -> str:
    """이스케이프 시퀀스 하나(백슬래시 포함, 예: '\\n', '\\u0041', '\\x41', '\\u{1F600}')를
    디코딩. 인식 못하는 시퀀스는 JS 규칙대로 백슬래시만 제거."""
    body = text[1:]
    if body.startswith("u{"):
        try:
            return chr(int(body[2:-1], 16))
        except ValueError:
            return text
    if body.startswith("u") and len(body) >= 5:
        try:
            return chr(int(body[1:5], 16))
        except ValueError:
            return text
    if body.startswith("x") and len(body) >= 3:
        try:
            return chr(int(body[1:3], 16))
        except ValueError:
            return text
    if body in ("\n", "\r", "\r\n"):
        return ""  # 라인 연속(line continuation) — 문자 제거
    return _ESCAPE_MAP.get(body, body)


def _decode_js_string(ts_node, code_bytes: bytes) -> str:
    """string/template_string 노드의 자식(string_fragment/escape_sequence)을 이어붙여
    "cooked" 값을 만든다."""
    parts: List[str] = []
    for child in ts_node.children:
        if child.type == "string_fragment":
            parts.append(code_bytes[child.start_byte:child.end_byte].decode("utf-8"))
        elif child.type == "escape_sequence":
            parts.append(_decode_escape(code_bytes[child.start_byte:child.end_byte].decode("utf-8")))
    return "".join(parts)


_HEX_RE = re.compile(r'^0[xX]')
_BIN_RE = re.compile(r'^0[bB]')
_OCT_RE = re.compile(r'^0[oO]')
_LEGACY_OCT_RE = re.compile(r'^0[0-7]+$')


def _parse_js_number(text: str) -> Any:
    """number 리터럴 텍스트를 파이썬 숫자로 파싱(esprima의 .value와 동등한 근사치).

    BigInt 접미사(n)는 제거 후 정수로 근사, 파싱 실패 시(알 수 없는 표기) 원문 문자열을
    그대로 반환해 크래시를 피한다(_reconstruct_str의 str(val) 호출과 호환).
    """
    t = text.replace("_", "")
    if t and t[-1] in ("n", "N"):
        t = t[:-1]
    try:
        if _HEX_RE.match(t):
            return int(t, 16)
        if _BIN_RE.match(t):
            return int(t, 2)
        if _OCT_RE.match(t):
            return int(t, 8)
        if _LEGACY_OCT_RE.match(t):
            return int(t, 8)
        if any(c in t for c in ".eE"):
            return float(t)
        return int(t)
    except ValueError:
        return text


# ── 변환 컨텍스트 ────────────────────────────────────────────────────────────

class _Ctx:
    __slots__ = ("code_bytes", "byte_to_char")

    def __init__(self, code_bytes: bytes, byte_to_char) -> None:
        self.code_bytes = code_bytes
        self.byte_to_char = byte_to_char


def _mk(ttype: str, ts_node, **fields: Any) -> Node:
    """ts_node의 range/loc을 자동 부여하며 ESTree 노드를 생성. ctx는 _tls(스레드로컬)에서 읽는다."""
    ctx: _Ctx = _tls.ctx
    rng = (ctx.byte_to_char(ts_node.start_byte), ctx.byte_to_char(ts_node.end_byte))
    loc = _SourceLocation(
        _Position(ts_node.start_point[0] + 1, ts_node.start_point[1]),
        _Position(ts_node.end_point[0] + 1, ts_node.end_point[1]),
    )
    return Node(ttype, range=rng, loc=loc, **fields)


def _text(ts_node, ctx: _Ctx) -> str:
    return ctx.code_bytes[ts_node.start_byte:ts_node.end_byte].decode("utf-8")


def _named(ts_node, field: str):
    return ts_node.child_by_field_name(field)


def _named_opt_empty(ts_node, field: str):
    """_named()와 동일하되, for문의 생략된 init/condition 슬롯(빈 `;`)이 tree-sitter
    문법상 empty_statement 플레이스홀더로 채워지는 것을 esprima와 동일하게 None으로
    정규화한다(esprima는 생략 시 필드 자체가 None — 증가식은 애초에 생략 시 None이라
    이 정규화가 필요 없음)."""
    n = ts_node.child_by_field_name(field)
    return None if (n is not None and n.type == "empty_statement") else n


# ── 함수류(선언/표현식/화살표/제너레이터) 공통 변환 ─────────────────────────────

_FUNC_DECL_MAP = {
    "function_declaration": ("FunctionDeclaration", False),
    "generator_function_declaration": ("FunctionDeclaration", True),
    "function_expression": ("FunctionExpression", False),
    "generator_function": ("FunctionExpression", True),
}


def _convert_function(ts_node, ctx: _Ctx) -> Node:
    """function_declaration/function_expression/generator_function(_declaration) 공통 처리."""
    ttype, generator = _FUNC_DECL_MAP[ts_node.type]
    name_field = _named(ts_node, "name")
    is_async = any(c.type == "async" for c in ts_node.children if not c.is_named)
    params_field = _named(ts_node, "parameters")
    params = [convert(c, ctx) for c in params_field.named_children] if params_field else []
    body = convert(_named(ts_node, "body"), ctx)
    return _mk(ttype, ts_node,
               id=(_mk("Identifier", name_field, name=_text(name_field, ctx)) if name_field else None),
               params=params, body=body, generator=generator, **{"async": is_async})


def _convert_arrow_function(ts_node, ctx: _Ctx) -> Node:
    """arrow_function — 단일 무괄호 매개변수는 'parameter' 필드, 그 외는 'parameters' 필드."""
    is_async = any(c.type == "async" for c in ts_node.children if not c.is_named)
    params_field = _named(ts_node, "parameters")
    if params_field is not None:
        params = [convert(c, ctx) for c in params_field.named_children]
    else:
        single = _named(ts_node, "parameter")
        params = [convert(single, ctx)] if single is not None else []
    body_ts = _named(ts_node, "body")
    body = convert(body_ts, ctx)
    return _mk("ArrowFunctionExpression", ts_node, id=None, params=params, body=body,
               generator=False, **{"async": is_async})


# ── 클래스 멤버(컨테이너 문맥에 따라 Property/MethodDefinition으로 분기) ─────────

def _convert_key(key_field, ctx: _Ctx) -> Tuple[Any, bool]:
    """pair/pair_pattern/method_definition/field_definition의 key 필드를 (key노드, computed) 로."""
    if key_field.type == "computed_property_name":
        inner = key_field.named_children[0]
        return convert(inner, ctx), True
    return convert(key_field, ctx), False


def _method_kind(ts_node) -> str:
    """get/set/일반 판별 — method_definition의 비명명 자식에 get/set 키워드가 있는지 확인."""
    for c in ts_node.children:
        if not c.is_named and c.type in ("get", "set"):
            return c.type
    return None  # None = 일반 메서드(호출자가 문맥별 kind 기본값을 채움)


def _method_value(ts_node, ctx: _Ctx) -> Node:
    """method_definition의 parameters/body로 이름없는 FunctionExpression을 합성."""
    params_field = _named(ts_node, "parameters")
    params = [convert(c, ctx) for c in params_field.named_children] if params_field else []
    body = convert(_named(ts_node, "body"), ctx)
    is_async = any(c.type == "async" for c in ts_node.children if not c.is_named)
    is_gen = any(not c.is_named and c.type == "*" for c in ts_node.children)
    return _mk("FunctionExpression", ts_node, id=None, params=params, body=body,
               generator=is_gen, **{"async": is_async})


def _convert_object_member(ts_node, ctx: _Ctx) -> Node:
    """object(리터럴)/object_pattern의 properties 항목 하나를 esprima 방식(Property로 통일,
    메서드/getter/setter도 kind로 구분)으로 변환. esprima는 객체 리터럴 메서드를
    MethodDefinition이 아닌 Property(method=True)로 표현하므로 이를 그대로 재현한다.
    """
    t = ts_node.type
    if t == "method_definition":
        key_field = _named(ts_node, "name")
        key, computed = _convert_key(key_field, ctx)
        kind = _method_kind(ts_node) or "init"
        return _mk("Property", ts_node, key=key, value=_method_value(ts_node, ctx),
                   kind=kind, computed=computed, method=(kind == "init"), shorthand=False)
    if t in ("pair", "pair_pattern"):
        key_field = _named(ts_node, "key")
        key, computed = _convert_key(key_field, ctx)
        value = convert(_named(ts_node, "value"), ctx)
        return _mk("Property", ts_node, key=key, value=value, kind="init",
                   computed=computed, method=False, shorthand=False)
    if t in ("shorthand_property_identifier", "shorthand_property_identifier_pattern"):
        name = _text(ts_node, ctx)
        ident = _mk("Identifier", ts_node, name=name)
        return _mk("Property", ts_node, key=ident, value=ident, kind="init",
                   computed=False, method=False, shorthand=True)
    if t == "object_assignment_pattern":  # 구조분해 기본값: {b = 1}
        left_field = _named(ts_node, "left")
        name = _text(left_field, ctx)
        ident = _mk("Identifier", left_field, name=name)
        default_val = convert(_named(ts_node, "right"), ctx)
        assign_pat = _mk("AssignmentPattern", ts_node, left=ident, right=default_val)
        return _mk("Property", ts_node, key=ident, value=assign_pat, kind="init",
                   computed=False, method=False, shorthand=True)
    if t == "spread_element" or t == "rest_pattern":
        arg = convert(ts_node.named_children[0], ctx)
        return _mk("RestElement" if t == "rest_pattern" else "SpreadElement", ts_node, argument=arg)
    # 알 수 없는 멤버 타입 — 최대한 처리 대상에서 제외하되 크래시하지 않도록 통과
    return convert(ts_node, ctx)


def _convert_class_member(ts_node, ctx: _Ctx) -> Node:
    """class_body의 body 항목 하나(MethodDefinition/PropertyDefinition/StaticBlock)로 변환."""
    t = ts_node.type
    if t == "method_definition":
        key_field = _named(ts_node, "name")
        key, computed = _convert_key(key_field, ctx)
        is_static = any(not c.is_named and c.type == "static" for c in ts_node.children)
        kind = _method_kind(ts_node)
        if kind is None:
            kind = "constructor" if (not computed and getattr(key, "name", None) == "constructor"
                                      and not is_static) else "method"
        return _mk("MethodDefinition", ts_node, key=key, value=_method_value(ts_node, ctx),
                   kind=kind, computed=computed, static=is_static)
    if t == "field_definition":
        key_field = _named(ts_node, "property")
        key, computed = _convert_key(key_field, ctx)
        is_static = any(not c.is_named and c.type == "static" for c in ts_node.children)
        value_field = _named(ts_node, "value")
        value = convert(value_field, ctx) if value_field is not None else None
        return _mk("PropertyDefinition", ts_node, key=key, value=value,
                   computed=computed, static=is_static)
    if t == "class_static_block":
        inner_block = _named(ts_node, "body")
        body = [convert(c, ctx) for c in inner_block.named_children] if inner_block else []
        return _mk("StaticBlock", ts_node, body=body)
    return convert(ts_node, ctx)


# ── 임포트/익스포트 스펙파이어 ────────────────────────────────────────────────

def _convert_import_clause(clause_ts, ctx: _Ctx) -> List[Node]:
    """import_clause의 자식들(default identifier / namespace_import / named_imports)을
    esprima의 specifiers 목록(ImportDefaultSpecifier/ImportNamespaceSpecifier/ImportSpecifier)
    으로 평탄화."""
    specs: List[Node] = []
    for c in clause_ts.named_children:
        if c.type == "identifier":
            ident = convert(c, ctx)
            specs.append(_mk("ImportDefaultSpecifier", c, local=ident))
        elif c.type == "namespace_import":
            local_field = c.named_children[-1]  # '*' 'as' identifier 중 named는 identifier뿐
            ident = convert(local_field, ctx)
            specs.append(_mk("ImportNamespaceSpecifier", c, local=ident))
        elif c.type == "named_imports":
            for spec in c.named_children:
                if spec.type != "import_specifier":
                    continue
                name_field = _named(spec, "name")
                alias_field = _named(spec, "alias")
                imported = convert(name_field, ctx)
                local = convert(alias_field, ctx) if alias_field is not None else imported
                specs.append(_mk("ImportSpecifier", spec, imported=imported, local=local))
    return specs


def _convert_export_clause(clause_ts, ctx: _Ctx) -> List[Node]:
    """export_clause의 export_specifier 목록을 esprima의 ExportSpecifier 목록으로."""
    specs: List[Node] = []
    for spec in clause_ts.named_children:
        if spec.type != "export_specifier":
            continue
        name_field = _named(spec, "name")
        alias_field = _named(spec, "alias")
        local = convert(name_field, ctx)
        # alias가 'default' 등 예약어라 식별자 노드가 아닌 경우(named=False) 스킵 없이
        # 텍스트 그대로 Identifier로 근사 — export {a as default} 같은 드문 패턴 지원
        if alias_field is not None:
            if alias_field.is_named:
                exported = convert(alias_field, ctx)
            else:
                exported = _mk("Identifier", alias_field, name=_text(alias_field, ctx))
        else:
            exported = local
        specs.append(_mk("ExportSpecifier", spec, local=local, exported=exported))
    return specs


# ── 핵심 디스패치 ────────────────────────────────────────────────────────────

def convert(ts_node, ctx: _Ctx) -> Optional[Node]:
    """tree-sitter 노드 하나를 esprima 호환 ESTree 노드로 변환(재귀).

    js_analysis.py 다운스트림이 실제로 소비하는 타입/필드는 정확히 맞춘다. 제어흐름
    문(if/for/while/do/switch/try/catch/labeled)은 가드 체인 추적(visit())과 CFG
    빌더(build())가 `.type` 문자열로 분기해 `.test`/`.consequent`/`.alternate`/`.body`/
    `.discriminant`/`.cases`/`.block`/`.handler`/`.finalizer` 등 ESTree 필드를 직접
    읽으므로 이들도 정확한 필드 매핑이 필요하다. 그 외(throw/break/continue 등 다운스트림이
    `vars(node)` 제네릭 순회로만 소비하는 문)만 "표준 필드명 + 하위 노드 재귀 변환"으로
    충분한 범용 폴백으로 처리한다.
    """
    if ts_node is None:
        return None
    t = ts_node.type

    # 괄호는 ESTree에 노드가 없다(esprima도 괄호를 투명하게 무시) — 내부 표현식으로 대체
    if t == "parenthesized_expression":
        return convert(ts_node.named_children[0], ctx)

    # 삼항연산자 — _reconstruct_str()이 .consequent를 명시적으로 읽으므로 범용 폴백이
    # 아니라 정확한 필드 매핑이 필요
    if t == "ternary_expression":
        return _mk("ConditionalExpression", ts_node,
                   test=convert(_named(ts_node, "condition"), ctx),
                   consequent=convert(_named(ts_node, "consequence"), ctx),
                   alternate=convert(_named(ts_node, "alternative"), ctx))

    # ── 리프 ──
    if t in ("identifier", "property_identifier", "shorthand_property_identifier",
              "statement_identifier", "private_property_identifier"):
        return _mk("Identifier", ts_node, name=_text(ts_node, ctx))
    if t == "this":
        return _mk("ThisExpression", ts_node)
    if t == "super":
        return _mk("Super", ts_node)
    if t == "null":
        return _mk("Literal", ts_node, value=None)
    if t == "true":
        return _mk("Literal", ts_node, value=True)
    if t == "false":
        return _mk("Literal", ts_node, value=False)
    if t == "number":
        return _mk("Literal", ts_node, value=_parse_js_number(_text(ts_node, ctx)))
    if t == "string":
        return _mk("Literal", ts_node, value=_decode_js_string(ts_node, ctx.code_bytes))
    if t == "regex":
        # esprima 백엔드와 동일하게 "Literal"이 아닌 별도 타입 → _reconstruct_str()의
        # 원문 슬라이스 폴백 경로로 자연히 위임(정규식 리터럴 값은 추적하지 않음).
        pattern_n = ts_node.child_by_field_name("pattern")
        flags_n = ts_node.child_by_field_name("flags")
        return _mk("RegexLiteral", ts_node, value=None,
                   regex={"pattern": _text(pattern_n, ctx) if pattern_n else "",
                          "flags": _text(flags_n, ctx) if flags_n else ""})
    if t == "template_string":
        expressions: List[Node] = []
        quasis: List[Node] = []
        cur_parts: List[str] = []
        for c in ts_node.children:
            if c.type in ("`",):
                continue
            if c.type == "string_fragment":
                cur_parts.append(_text(c, ctx))
            elif c.type == "escape_sequence":
                cur_parts.append(_decode_escape(_text(c, ctx)))
            elif c.type == "template_substitution":
                quasis.append(_mk("TemplateElement", c,
                                  value=_TemplateElementValue("".join(cur_parts)), tail=False))
                cur_parts = []
                inner = [gc for gc in c.named_children]
                expressions.append(convert(inner[0], ctx) if inner else None)
        quasis.append(_mk("TemplateElement", ts_node,
                          value=_TemplateElementValue("".join(cur_parts)), tail=True))
        return _mk("TemplateLiteral", ts_node, expressions=expressions, quasis=quasis)

    # ── 표현식 ──
    if t == "sequence_expression":
        return _mk("SequenceExpression", ts_node,
                   expressions=[convert(c, ctx) for c in ts_node.named_children])
    if t == "assignment_expression":
        return _mk("AssignmentExpression", ts_node, operator="=",
                   left=convert(_named(ts_node, "left"), ctx),
                   right=convert(_named(ts_node, "right"), ctx))
    if t == "augmented_assignment_expression":
        op_field = _named(ts_node, "operator")
        return _mk("AssignmentExpression", ts_node, operator=_text(op_field, ctx),
                   left=convert(_named(ts_node, "left"), ctx),
                   right=convert(_named(ts_node, "right"), ctx))
    if t == "binary_expression":
        # &&/||/?? 는 esprima와 동일하게 LogicalExpression으로 분리한다 — 가드 체인
        # 추적(js_analysis.py의 visit())이 `.type == "LogicalExpression"`으로 분기해
        # &&/|| 가드를 기록하므로, 여기서 BinaryExpression으로 뭉뚱그리면 그 가드가
        # tree-sitter 경로에서만 조용히 누락된다. 그 외 연산자(+,-,*,<,instanceof,in 등)는
        # 기존대로 BinaryExpression 하나로 통일(다운스트림이 세분화하지 않음).
        op_field = _named(ts_node, "operator")
        op_text = _text(op_field, ctx)
        ttype = "LogicalExpression" if op_text in ("&&", "||", "??") else "BinaryExpression"
        return _mk(ttype, ts_node, operator=op_text,
                   left=convert(_named(ts_node, "left"), ctx),
                   right=convert(_named(ts_node, "right"), ctx))
    if t == "unary_expression":
        op_field = _named(ts_node, "operator")
        return _mk("UnaryExpression", ts_node, operator=_text(op_field, ctx),
                   argument=convert(_named(ts_node, "argument"), ctx), prefix=True)
    if t == "update_expression":
        op_field = _named(ts_node, "operator")
        prefix = op_field.start_byte < _named(ts_node, "argument").start_byte
        return _mk("UpdateExpression", ts_node, operator=_text(op_field, ctx),
                   argument=convert(_named(ts_node, "argument"), ctx), prefix=prefix)
    if t == "await_expression":
        return _mk("AwaitExpression", ts_node, argument=convert(ts_node.named_children[0], ctx))
    if t == "yield_expression":
        delegate = any(not c.is_named and c.type == "*" for c in ts_node.children)
        named = ts_node.named_children
        return _mk("YieldExpression", ts_node,
                   argument=convert(named[0], ctx) if named else None, delegate=delegate)
    if t == "member_expression":
        prop_field = _named(ts_node, "property")
        return _mk("MemberExpression", ts_node, object=convert(_named(ts_node, "object"), ctx),
                   property=convert(prop_field, ctx), computed=False)
    if t == "subscript_expression":
        return _mk("MemberExpression", ts_node, object=convert(_named(ts_node, "object"), ctx),
                   property=convert(_named(ts_node, "index"), ctx), computed=True)
    if t == "call_expression":
        args_field = _named(ts_node, "arguments")
        args = [convert(c, ctx) for c in args_field.named_children] if args_field else []
        return _mk("CallExpression", ts_node, callee=convert(_named(ts_node, "function"), ctx),
                   arguments=args)
    if t == "new_expression":
        args_field = _named(ts_node, "arguments")
        args = [convert(c, ctx) for c in args_field.named_children] if args_field else []
        return _mk("NewExpression", ts_node, callee=convert(_named(ts_node, "constructor"), ctx),
                   arguments=args)
    if t in _FUNC_DECL_MAP:
        return _convert_function(ts_node, ctx)
    if t == "arrow_function":
        return _convert_arrow_function(ts_node, ctx)
    if t in ("class", "class_declaration"):
        name_field = _named(ts_node, "name")
        heritage = next((c for c in ts_node.named_children if c.type == "class_heritage"), None)
        super_class = convert(heritage.named_children[0], ctx) if heritage and heritage.named_children else None
        body_field = _named(ts_node, "body")
        members = [_convert_class_member(c, ctx) for c in body_field.named_children
                   if c.type != ";"] if body_field else []
        class_body = _mk("ClassBody", body_field if body_field else ts_node, body=members)
        ttype = "ClassDeclaration" if t == "class_declaration" else "ClassExpression"
        return _mk(ttype, ts_node,
                   id=(convert(name_field, ctx) if name_field is not None else None),
                   superClass=super_class, body=class_body)

    # ── 리터럴 컨테이너 ──
    if t == "object":
        props = [_convert_object_member(c, ctx) for c in ts_node.named_children]
        return _mk("ObjectExpression", ts_node, properties=props)
    if t == "object_pattern":
        props = [_convert_object_member(c, ctx) for c in ts_node.named_children]
        return _mk("ObjectPattern", ts_node, properties=props)
    if t == "array":
        elements = [convert(c, ctx) for c in ts_node.named_children]
        return _mk("ArrayExpression", ts_node, elements=elements)
    if t == "array_pattern":
        elements = [convert(c, ctx) for c in ts_node.named_children]
        return _mk("ArrayPattern", ts_node, elements=elements)
    if t == "spread_element":
        return _mk("SpreadElement", ts_node, argument=convert(ts_node.named_children[0], ctx))

    # ── 패턴(매개변수/구조분해) ──
    if t == "assignment_pattern":  # function f(a = 1)
        return _mk("AssignmentPattern", ts_node, left=convert(_named(ts_node, "left"), ctx),
                   right=convert(_named(ts_node, "right"), ctx))
    if t == "rest_pattern":
        return _mk("RestElement", ts_node, argument=convert(ts_node.named_children[0], ctx))

    # ── 모듈 (import/export) ──
    if t == "import_statement":
        source_field = _named(ts_node, "source")
        clause = next((c for c in ts_node.named_children if c.type == "import_clause"), None)
        specifiers = _convert_import_clause(clause, ctx) if clause else []
        return _mk("ImportDeclaration", ts_node, specifiers=specifiers,
                   source=convert(source_field, ctx))
    if t == "export_statement":
        source_field = _named(ts_node, "source")
        source_node = convert(source_field, ctx) if source_field is not None else None
        decl_field = _named(ts_node, "declaration")
        value_field = _named(ts_node, "value")  # export default <expr>
        has_default = any(not c.is_named and c.type == "default" for c in ts_node.children)
        # "export * from" 은 '*'가 export_statement의 직속 비명명 자식이지만,
        # "export * as ns from" 은 '*'가 named 래퍼 namespace_export 안에 한 단계 더
        # 들어가 있으므로 두 형태 모두 확인해야 한다.
        has_star = (any(not c.is_named and c.type == "*" for c in ts_node.children)
                    or any(c.type == "namespace_export" for c in ts_node.named_children))
        clause = next((c for c in ts_node.named_children if c.type == "export_clause"), None)
        if has_default:
            return _mk("ExportDefaultDeclaration", ts_node,
                       declaration=convert(decl_field if decl_field is not None else value_field, ctx))
        if has_star:  # export * from '...' / export * as ns from '...' (ns 이름은 근사상 버림)
            return _mk("ExportAllDeclaration", ts_node, source=source_node, exported=None)
        if decl_field is not None:  # export const x = 1 / export function f(){} / export class C{}
            return _mk("ExportNamedDeclaration", ts_node, declaration=convert(decl_field, ctx),
                       specifiers=[], source=None)
        specifiers = _convert_export_clause(clause, ctx) if clause else []
        return _mk("ExportNamedDeclaration", ts_node, declaration=None,
                   specifiers=specifiers, source=source_node)

    # ── 선언/문 (제네릭 순회로 충분 — 특정 필드명을 패턴매치하는 다운스트림 코드 없음) ──
    if t in ("variable_declaration", "lexical_declaration"):
        kind_field = _named(ts_node, "kind")
        decls = [convert(c, ctx) for c in ts_node.named_children if c.type == "variable_declarator"]
        return _mk("VariableDeclaration", ts_node,
                   kind=(_text(kind_field, ctx) if kind_field else "var"), declarations=decls)
    if t == "variable_declarator":
        value_field = _named(ts_node, "value")
        return _mk("VariableDeclarator", ts_node, id=convert(_named(ts_node, "name"), ctx),
                   init=(convert(value_field, ctx) if value_field is not None else None))
    if t == "program":
        body = [convert(c, ctx) for c in ts_node.named_children]
        return _mk("Program", ts_node, body=body, sourceType="module")
    if t == "statement_block":
        body = [convert(c, ctx) for c in ts_node.named_children]
        return _mk("BlockStatement", ts_node, body=body)
    if t == "expression_statement":
        return _mk("ExpressionStatement", ts_node, expression=convert(ts_node.named_children[0], ctx))
    if t == "return_statement":
        named = ts_node.named_children
        return _mk("ReturnStatement", ts_node, argument=convert(named[0], ctx) if named else None)
    if t == "empty_statement":
        return _mk("EmptyStatement", ts_node)

    # ── 제어흐름 문 — js_analysis.py의 가드 체인 추적(visit())과 CFG 빌더(build())가
    # `.type` 문자열로 분기해 ESTree 필드를 직접 읽으므로 범용 폴백이 아니라 정확한
    # 필드 매핑이 필요하다(esprima와 동일한 필드명 계약).
    if t == "if_statement":
        alt_field = _named(ts_node, "alternative")  # else_clause 래퍼 → 내부 문(단일 자식)으로 치환
        alternate = convert(alt_field.named_children[0], ctx) if alt_field is not None else None
        return _mk("IfStatement", ts_node,
                   test=convert(_named(ts_node, "condition"), ctx),
                   consequent=convert(_named(ts_node, "consequence"), ctx),
                   alternate=alternate)
    if t == "while_statement":
        return _mk("WhileStatement", ts_node,
                   test=convert(_named(ts_node, "condition"), ctx),
                   body=convert(_named(ts_node, "body"), ctx))
    if t == "do_statement":
        return _mk("DoWhileStatement", ts_node,
                   body=convert(_named(ts_node, "body"), ctx),
                   test=convert(_named(ts_node, "condition"), ctx))
    if t == "for_statement":
        # 생략된 init/condition 슬롯은 tree-sitter 문법상 empty_statement 플레이스홀더로
        # 채워지므로(증가식은 생략 시 진짜 None) esprima와 동일하게 None으로 정규화한다.
        return _mk("ForStatement", ts_node,
                   init=convert(_named_opt_empty(ts_node, "initializer"), ctx),
                   test=convert(_named_opt_empty(ts_node, "condition"), ctx),
                   update=convert(_named(ts_node, "increment"), ctx),
                   body=convert(_named(ts_node, "body"), ctx))
    if t == "for_in_statement":
        # tree-sitter는 for-in/for-of를 동일 노드 타입으로 표현하고 "in"/"of" 연산자
        # 토큰(operator 필드)으로만 구분한다 — js_analysis.py가 .type 문자열
        # (ForInStatement vs ForOfStatement)로 분기하므로 여기서 갈라 매핑한다.
        op_field = _named(ts_node, "operator")
        ttype = "ForOfStatement" if (op_field is not None and _text(op_field, ctx) == "of") else "ForInStatement"
        return _mk(ttype, ts_node,
                   left=convert(_named(ts_node, "left"), ctx),
                   right=convert(_named(ts_node, "right"), ctx),
                   body=convert(_named(ts_node, "body"), ctx))
    if t == "switch_statement":
        body_field = _named(ts_node, "body")  # switch_body 래퍼 → case 목록만 취함
        cases = [convert(c, ctx) for c in body_field.named_children] if body_field else []
        return _mk("SwitchStatement", ts_node,
                   discriminant=convert(_named(ts_node, "value"), ctx), cases=cases)
    if t in ("switch_case", "switch_default"):
        value_field = _named(ts_node, "value")  # switch_default는 이 필드가 없음(=default)
        consequent = [convert(c, ctx) for c in ts_node.children_by_field_name("body")]
        return _mk("SwitchCase", ts_node,
                   test=(convert(value_field, ctx) if value_field is not None else None),
                   consequent=consequent)
    if t == "try_statement":
        handler_field = _named(ts_node, "handler")
        fin_field = _named(ts_node, "finalizer")  # finally_clause 래퍼 → 내부 블록으로 치환
        return _mk("TryStatement", ts_node,
                   block=convert(_named(ts_node, "body"), ctx),
                   handler=(convert(handler_field, ctx) if handler_field is not None else None),
                   finalizer=(convert(fin_field.child_by_field_name("body"), ctx)
                              if fin_field is not None else None))
    if t == "catch_clause":
        param_field = _named(ts_node, "parameter")  # catch(e) 없이 catch{}만 쓰면 없음
        return _mk("CatchClause", ts_node,
                   param=(convert(param_field, ctx) if param_field is not None else None),
                   body=convert(_named(ts_node, "body"), ctx))
    if t == "labeled_statement":
        return _mk("LabeledStatement", ts_node,
                   label=convert(_named(ts_node, "label"), ctx),
                   body=convert(_named(ts_node, "body"), ctx))

    # ── 그 외 전부(throw/break/continue 등) — 범용 폴백 ──
    #
    # 이 아래 타입들은 js_analysis.py 어디에서도 .type 문자열로 특정 분기를 타지 않고
    # `vars(node)` 제네릭 순회로만 소비되므로, 실제 ESTree 필드명을 정확히 맞출 필요
    # 없이 "자식 노드를 전부 변환해 어떤 속성으로든 노출"하기만 하면 하위 호출/대입/
    # 함수 정의가 누락되지 않는다.
    children = [convert(c, ctx) for c in ts_node.named_children]
    return _mk(_GENERIC_TYPE_MAP.get(t, t), ts_node, _children=children)


_GENERIC_TYPE_MAP = {
    "break_statement": "BreakStatement",
    "continue_statement": "ContinueStatement",
    "throw_statement": "ThrowStatement",
    "class_heritage": "ClassHeritage",
}


# ── 진입점 ───────────────────────────────────────────────────────────────────

def _find_error_snippet(node, code_bytes: bytes, depth: int = 0) -> Optional[str]:
    """has_error 트리에서 첫 ERROR/MISSING 노드를 찾아 진단 메시지용 스니펫을 뽑는다."""
    if depth > 200:  # 병적으로 깊은 트리 방어
        return None
    if node.is_error or node.is_missing:
        start, end = node.start_byte, min(node.end_byte, node.start_byte + 40)
        snippet = code_bytes[start:end].decode("utf-8", errors="replace")
        return f"Line {node.start_point[0] + 1}: near {snippet!r}"
    for child in node.children:
        found = _find_error_snippet(child, code_bytes, depth + 1)
        if found:
            return found
    return None


def parse(code: str) -> Node:
    """tree-sitter-javascript로 code를 파싱해 esprima 호환 Program 노드를 반환.

    esprima의 tolerant=True와 달리 이 백엔드는 엄격하다 — has_error가 있으면 즉시
    예외를 던져 해당 유닛을 스킵시킨다(js_analysis.py의 "유닛 단위 실패, 배치는 계속
    진행" 정책과의 일관성 유지 — 부분적으로 깨진 트리를 변환해 조용히 잘못된 분석
    결과를 만드는 것보다 안전).
    """
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser

    code_bytes = code.encode("utf-8")
    lang = Language(_tsjs.language())
    parser = Parser(lang)
    tree = parser.parse(code_bytes)
    root = tree.root_node
    if root.has_error:
        snippet = _find_error_snippet(root, code_bytes) or "구문 오류"
        raise SyntaxError(snippet)

    byte_to_char = _build_byte_to_char(code)
    ctx = _Ctx(code_bytes, byte_to_char)
    _tls.ctx = ctx
    try:
        return convert(root, ctx)
    finally:
        del _tls.ctx
