"""
SQLi 공통 유틸리티 — detection(sql_injection.py)과 extraction(sqli_extract.py)이
공유하는 상수·함수 모음. 두 모듈은 이 파일의 심볼을 동등하게 참조한다.
"""
import re
import secrets
import difflib
from urllib.parse import urlparse, parse_qs, urljoin, urldefrag
from typing import Any, Dict, List, Optional, Set, Tuple

from html import unescape as _html_unescape

from . import _crawl


# ── WAF·에러 탐지 상수 ────────────────────────────────────────────────────────

# WAF 차단 응답 감지 키워드
WAF_KEYWORDS = ("access denied", "blocked", "forbidden")

# CSRF/보안 토큰 성격의 hidden 필드 이름 — 페이로드 주입 시 CSRF 검증 실패 유발하므로 제외
CSRF_TOKEN_NAMES: frozenset = frozenset({
    "csrf", "token", "nonce", "_token", "authenticity_token",
    "__requestverificationtoken", "csrfmiddlewaretoken",
    "__viewstate", "__viewstategenerator", "javax.faces.viewstate",
    "hp_field", "honeypot",
})

# DBMS별 Error-based 페이로드 벡터 — __MARKER__ 토큰은 런타임에 랜덤 마커로 치환
# Generic 페이로드에서 DBMS가 식별된 후 해당 DBMS 벡터만 추가 시도된다
DBMS_ERROR_VECTORS: Dict[str, List[str]] = {
    "MySQL": [
        "AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e))",
        "AND UPDATEXML(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e),1)",
    ],
    "MariaDB": [
        "AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e))",
        "AND UPDATEXML(1,CONCAT(0x7e,(SELECT '__MARKER__'),0x7e),1)",
    ],
    "MSSQL": [
        "AND 1=CONVERT(int,(SELECT '__MARKER__'))",
        "AND 1=CAST('__MARKER__' AS int)",
    ],
    "PostgreSQL": [
        "AND 1=CAST((SELECT '__MARKER__') AS int)",
    ],
    "Oracle": [
        "AND 1=CTXSYS.DRITHSX.SN(1,(SELECT '__MARKER__' FROM dual))",
    ],
    "SQLite": [
        "AND 1=LIKELIHOOD((SELECT 1),1) AND '__MARKER__'='__MARKER__'",
    ],
}

# DB 에러 시그니처 — DBMS 식별에 사용. detection·extraction 공통 참조.
# IBM DB2·Informix·General은 탐지(error_based)는 지원하나 추출(sqli_extract)은 미지원.
DB_ERROR_SIGNATURES: Dict[str, List[str]] = {
    "MySQL": [
        r"You have an error in your SQL syntax",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"Unknown column '[^']+' in 'field list'",
        r"check the manual that corresponds to your MySQL",
        r"MySQL server version for the right syntax",
    ],
    "MariaDB": [
        r"MariaDB",
        r"check the manual that corresponds to your (MySQL|MariaDB)",
        r"MariaDB server version",
    ],
    "MSSQL": [
        r"Unclosed quotation mark",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"Driver.* SQL[\-_ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server.*Driver",
        r"Warning.*(mssql|sqlsrv)_",
        r"System\.Data\.SqlClient\.SqlException",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
        r"Syntax error (converting|in regular expression)",
        r"Conversion failed when converting",
    ],
    "PostgreSQL": [
        r"ERROR:\s+syntax error at or near",
        r"pg_query\(\).*ERROR",
        r"PSQLException",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+invalid input syntax for",
    ],
    "Oracle": [
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"quoted string not properly terminated",
        r"Oracle error",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
    ],
    "SQLite": [
        r"SQLite3::query\(\)",
        r'near ".*": syntax error',
        r"SQLITE_ERROR",
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
    ],
    "IBM DB2": [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"db2_\w+\(",
        r"SQLSTATE=\w+.*DB2",
    ],
    "Informix": [
        r"Warning.*ibase_",
        r"Dynamic SQL Error",
        r"Informix.*Error",
    ],
    "General": [
        r"SQL syntax.*error",
        r"unexpected end of SQL command",
        r"invalid query",
        r"unterminated.*string",
    ],
}


# ── Dynamic Content Marking 상수 ──────────────────────────────────────────────

# 마스킹 regex 1회 적용 시 최대 재작성 횟수 (동적 반복 구간 많을 때 과도한 비용 차단)
_MAX_DYNAMIC_CONTEXTS = 20
# 동적 구간 앞뒤로 확보할 context 문자 수 (regex 경계 안정성 확보)
_DYNAMIC_CONTEXT_LEN = 10


# ── JS URL 파싱 상수 ──────────────────────────────────────────────────────────

_SCRIPT_BLOCK_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)

# JS 내 URL 호출 패턴 — 각 패턴은 URL 부분을 그룹 1로 캡처한다.
# 백틱(`) 템플릿 리터럴은 의도적으로 제외 — 동적 치환값의 모호성으로 인한
# 오탐 및 외부 도메인 유출 리스크 차단.
_JS_URL_PATTERNS = _crawl._JS_LINK_PATTERNS  # _crawl과 동일 패턴 — 단일 소스 유지

# POST 바디 탐지 패턴 — group(1)=URL, 패턴 끝이 '{' 직후 위치.
# _parse_js_urls에서 _extract_brace_content로 완전한 객체를 추출한다 (P5: 중괄호 균형).
# (패턴, body_type) 형식의 리스트.
_POST_BODY_FINDERS: List[Tuple[re.Pattern, str]] = [
    # fetch(url, {...body: JSON.stringify({...})...}) — JSON.stringify({ 직후
    (re.compile(r"""\bfetch\s*\(\s*["']([^"']+)["'][^)]*?JSON\.stringify\s*\(\s*\{""",
                re.IGNORECASE | re.DOTALL), "json"),
    # axios.post/put/patch/delete(url, {...}) — , { 직후
    (re.compile(r"""axios\.(?:post|put|patch|delete)\s*\(\s*["']([^"']+)["']\s*,\s*\{""",
                re.IGNORECASE), "json"),
    # $.post(url, {...}) — , { 직후
    (re.compile(r"""\$\.post\s*\(\s*["']([^"']+)["']\s*,\s*\{""",
                re.IGNORECASE), "form"),
    # $.ajax({url:'...', data:{...}}) — data: { 직후
    (re.compile(r"""\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']+)["'][^}]*?data\s*:\s*\{""",
                re.IGNORECASE | re.DOTALL), "form"),
    # navigator.sendBeacon(url, JSON.stringify({...})) — JSON.stringify({ 직후 (P6)
    (re.compile(r"""navigator\.sendBeacon\s*\(\s*["']([^"']+)["']\s*,\s*JSON\.stringify\s*\(\s*\{""",
                re.IGNORECASE), "json"),
]
# XHR POST 전용 (P6): .open('POST', url) + 근방 .send(JSON.stringify({...}))
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"]POST['"]\s*,\s*["']([^"']+)["']""", re.IGNORECASE
)
_XHR_SEND_JSON_RE = re.compile(
    r"""\.send\s*\(\s*JSON\.stringify\s*\(\s*\{""", re.IGNORECASE
)
# JS 객체 리터럴 키 이름 추출 — 문자열 키 또는 식별자 키
_JS_OBJ_KEY_RE = re.compile(r"""["\']?(\w+)["\']?\s*:""")



# ── HTML 속성 파싱 헬퍼 ───────────────────────────────────────────────────────

def _get_attr(attrs_str: str, attr: str) -> Optional[str]:
    """HTML 속성 문자열에서 특정 속성 값을 추출한다."""
    # 따옴표로 감싼 속성값
    m = re.search(rf'\b{attr}\s*=\s*["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
    if m:
        return m.group(1)
    # 따옴표 없는 속성값
    m = re.search(rf'\b{attr}\s*=\s*(\S+)', attrs_str, re.IGNORECASE)
    if m:
        return m.group(1).rstrip('>')
    return None


def _extract_brace_content(text: str, open_pos: int) -> Optional[str]:
    """text[open_pos]이 '{' 인 지점부터 중괄호 균형을 맞춰 내용을 반환한다 (P5).

    문자열 리터럴(', ", `) 내부의 중괄호는 무시한다.
    반환값: '{' ~ 대응 '}' 사이 내용. 균형 맞는 '}' 없으면 None.
    """
    if open_pos >= len(text) or text[open_pos] != '{':
        return None
    depth = 0
    in_str = False
    str_char = ''
    i = open_pos
    content_start = open_pos + 1
    while i < len(text):
        c = text[i]
        if in_str:
            if c == '\\':
                i += 2
                continue
            if c == str_char:
                in_str = False
        else:
            if c in ('"', "'", '`'):
                in_str = True
                str_char = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return text[content_start:i]
        i += 1
    return None


def _parse_js_urls(body: str, page_url: str,
                   base_netloc: str,
                   whole_script: bool = False) -> List[Dict[str, Any]]:
    """JS 호출 URL과 JSON POST 바디 파라미터를 추출한다.

    whole_script=False (기본): HTML 내 <script> 블록 + 인라인 이벤트 핸들러만 파싱.
    whole_script=True: body 전체를 스크립트로 취급 (.js 파일 등).

    GET 주입 포인트: 쿼리스트링이 있는 URL.
    POST 주입 포인트: JSON.stringify / axios.post / $.post / $.ajax data 객체의 키.
    외부 도메인·로그아웃 경로는 수집 단계에서 즉시 드롭.
    """
    points: List[Dict[str, Any]] = []
    # (url, method, frozenset(param_keys)) 기준 중복 방지
    seen: Set[tuple] = set()

    # ── 파싱 대상 스크립트 블록 수집 ──
    script_blocks: List[str] = []
    if whole_script:
        script_blocks.append(body)
    else:
        for block_match in _SCRIPT_BLOCK_RE.finditer(body):
            script_blocks.append(block_match.group(1))
        for attr_match in re.finditer(
            r'\bon\w+\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE
        ):
            script_blocks.append(attr_match.group(1))

    # ── GET: 쿼리스트링 있는 URL ──
    url_candidates: Set[str] = set()
    for block in script_blocks:
        for pat in _JS_URL_PATTERNS:
            for m in pat.finditer(block):
                url_candidates.add(m.group(1))

    for raw in url_candidates:
        abs_url, _ = urldefrag(urljoin(page_url, raw))
        parsed = urlparse(abs_url)
        if parsed.netloc != base_netloc or _crawl._is_logout_path(parsed.path):
            continue
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue
        params = {k: v[0] for k, v in qs.items()}
        key = (abs_url, "GET", frozenset(params))
        if key in seen:
            continue
        seen.add(key)
        param_types = {k: "js_url" for k in params}
        points.append({
            "url": abs_url, "method": "GET",
            "params": params, "param_types": param_types, "body_type": "form",
        })

    # ── POST: JSON 바디 객체 키 (P5: 중괄호 균형 파서, P6: XHR·sendBeacon 추가) ──
    for block in script_blocks:
        # 일반 패턴: URL 탐지 → 패턴 끝('{'  직후)에서 brace-balance로 완전한 바디 추출
        for pat, btype in _POST_BODY_FINDERS:
            for m in pat.finditer(block):
                brace_pos = m.end() - 1  # 패턴이 '{' 포함 후 끝나므로 -1이 '{' 위치
                if brace_pos < 0 or brace_pos >= len(block) or block[brace_pos] != '{':
                    continue
                obj_body = _extract_brace_content(block, brace_pos)
                if not obj_body:
                    continue
                raw_url = m.group(1)
                abs_url, _ = urldefrag(urljoin(page_url, raw_url))
                parsed = urlparse(abs_url)
                if parsed.netloc != base_netloc or _crawl._is_logout_path(parsed.path):
                    continue
                keys = [k for k in _JS_OBJ_KEY_RE.findall(obj_body)
                        if k.lower() not in ("true", "false", "null")]
                if not keys:
                    continue
                params = {k: "" for k in keys}
                key = (abs_url, "POST", frozenset(params))
                if key in seen:
                    continue
                seen.add(key)
                param_types = {k: "js_body" for k in params}
                points.append({
                    "url": abs_url, "method": "POST",
                    "params": params, "param_types": param_types, "body_type": btype,
                })

        # XHR POST (P6): .open('POST', url) 탐지 → 근방 600자 내 .send(JSON.stringify({...})) 연관
        for xhr_m in _XHR_OPEN_RE.finditer(block):
            search_end = min(len(block), xhr_m.end() + 600)
            send_m = _XHR_SEND_JSON_RE.search(block, xhr_m.end(), search_end)
            if not send_m:
                continue
            brace_pos = send_m.end() - 1
            if brace_pos >= len(block) or block[brace_pos] != '{':
                continue
            obj_body = _extract_brace_content(block, brace_pos)
            if not obj_body:
                continue
            raw_url = xhr_m.group(1)
            abs_url, _ = urldefrag(urljoin(page_url, raw_url))
            parsed = urlparse(abs_url)
            if parsed.netloc != base_netloc or _crawl._is_logout_path(parsed.path):
                continue
            keys = [k for k in _JS_OBJ_KEY_RE.findall(obj_body)
                    if k.lower() not in ("true", "false", "null")]
            if not keys:
                continue
            params = {k: "" for k in keys}
            key = (abs_url, "POST", frozenset(params))
            if key in seen:
                continue
            seen.add(key)
            param_types = {k: "js_body" for k in params}
            points.append({
                "url": abs_url, "method": "POST",
                "params": params, "param_types": param_types, "body_type": "json",
            })

    return points


# ── 입력 포인트 수집 ──────────────────────────────────────────────────────────

def parse_input_points(page_url: str, body: str,
                       base_netloc: str,
                       kind: str = "html") -> List[Dict]:
    """페이지 본문에서 입력 포인트를 수집한다.

    kind="html" (기본): HTML 전 항목 수집.
      1. URL 쿼리 파라미터
      2. <a href> 쿼리 파라미터 (크롤러 미방문 링크 커버)
      3. <form> 필드(hidden 포함) — enctype에 따라 body_type = form/json/xml 분기
      4. data-url/href/action/src 속성의 쿼리 파라미터
      5. JS 내부 URL / POST 바디 키 (fetch/XMLHttpRequest/$.ajax/axios 등)

    kind="script": .js 파일 등 — HTML 구조 파싱 없이 본문 전체를 스크립트로 취급.
      URL 쿼리 파라미터(1)와 JS 호출 URL/POST 바디 키(5)만 수집.

    kind="json": JSON API 응답 — 본문을 재귀 탐색하여 같은 도메인 URL 문자열의
      쿼리 파라미터를 GET 입력 포인트로 수집(HATEOAS / 중첩 리소스 링크 커버).
      URL 쿼리 파라미터(1)도 수집.
    """
    points: List[Dict[str, Any]] = []

    # ── 1. URL 쿼리 파라미터 추출 ──
    parsed = urlparse(page_url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if qs:
        params = {k: v[0] for k, v in qs.items()}
        param_types = {k: "url" for k in params}
        points.append({"url": page_url, "method": "GET",
                       "params": params, "param_types": param_types,
                       "body_type": "form"})

    # kind="script"이면 HTML 구조 파싱(2~4) 건너뛰고 JS 추출만 수행
    if kind == "script":
        points.extend(_parse_js_urls(body, page_url, base_netloc, whole_script=True))
        return points

    # kind="json"이면 JSON 본문을 재귀 탐색하여 URL 쿼리 파라미터를 수집한다
    if kind == "json":
        try:
            import json as _json_mod

            def _walk_json(obj: Any) -> None:
                if isinstance(obj, str):
                    if not obj.startswith(("http://", "https://", "/")):
                        return
                    try:
                        abs_url, _ = urldefrag(urljoin(page_url, obj))
                        parsed_u = urlparse(abs_url)
                        if parsed_u.netloc != base_netloc:
                            return
                        if _crawl._is_logout_path(parsed_u.path):
                            return
                        qs_j = parse_qs(parsed_u.query, keep_blank_values=True)
                        if qs_j:
                            params_j = {k: v[0] for k, v in qs_j.items()}
                            param_types_j = {k: "json_url" for k in params_j}
                            points.append({"url": abs_url, "method": "GET",
                                           "params": params_j,
                                           "param_types": param_types_j,
                                           "body_type": "form"})
                    except Exception:
                        pass
                elif isinstance(obj, dict):
                    for v in obj.values():
                        _walk_json(v)
                elif isinstance(obj, list):
                    for v in obj:
                        _walk_json(v)

            _walk_json(_json_mod.loads(body))
        except Exception:
            pass
        return points

    # ── 2. <a href> 쿼리 파라미터 추출 (크롤러 미방문 링크 커버) ──
    for href_match in re.finditer(
        r'<a\b[^>]*\bhref=["\']([^"\']+)["\']', body, re.IGNORECASE
    ):
        href = _html_unescape(href_match.group(1))
        abs_url, _ = urldefrag(urljoin(page_url, href))
        # 외부 도메인 링크는 제외
        if urlparse(abs_url).netloc != base_netloc:
            continue
        # 로그아웃 경로는 세션 파기 방지를 위해 제외
        if _crawl._is_logout_path(urlparse(abs_url).path):
            continue
        href_qs = parse_qs(urlparse(abs_url).query, keep_blank_values=True)
        if href_qs:
            params = {k: v[0] for k, v in href_qs.items()}
            param_types = {k: "href" for k in params}
            points.append({"url": abs_url, "method": "GET",
                           "params": params, "param_types": param_types,
                           "body_type": "form"})

    # ── 3. <form> 태그 파싱 (P8: 미닫힌 폼 경계 확장 + HTML5 form= 속성 지원) ──

    # HTML5 form= 속성: 폼 밖에 있지만 특정 폼 id에 귀속되는 input 사전 수집
    orphan_inputs: Dict[str, List[Dict]] = {}
    for field_match in re.finditer(
        r'<(?:input|select|textarea)\b([^>]*)', body, re.IGNORECASE
    ):
        field_attrs = field_match.group(1)
        form_ref = _get_attr(field_attrs, "form")
        if not form_ref:
            continue
        name = _get_attr(field_attrs, "name")
        if not name:
            continue
        input_type = (_get_attr(field_attrs, "type") or "text").lower()
        if input_type in ("submit", "button", "image", "reset", "file"):
            continue
        orphan_inputs.setdefault(form_ref, []).append({
            "name": name, "type": input_type,
            "value": _get_attr(field_attrs, "value") or "",
        })

    # 폼 경계: </form> 또는 다음 <form> 중 먼저 오는 위치로 결정 (미닫힘 폼 대응)
    form_opens = list(re.finditer(r'<form\b([^>]*)>', body, re.IGNORECASE))
    for i, form_open in enumerate(form_opens):
        attrs_str = form_open.group(1)
        content_start = form_open.end()

        next_open_pos = form_opens[i + 1].start() if i + 1 < len(form_opens) else len(body)
        close_m = re.search(r'</form\b', body[content_start:next_open_pos], re.IGNORECASE)
        content_end = (content_start + close_m.start()) if close_m else next_open_pos
        form_body = body[content_start:content_end]

        enctype = (_get_attr(attrs_str, "enctype") or "").lower()
        # multipart/form-data 폼은 스킵
        if "multipart" in enctype:
            continue
        # enctype에 따른 body_type 결정 (POST 전송 시 분기용)
        if "json" in enctype:
            body_type = "json"
        elif "xml" in enctype:
            body_type = "xml"
        else:
            body_type = "form"

        method = (_get_attr(attrs_str, "method") or "GET").upper()
        # P4: action 속성값 HTML 엔티티 디코드 후 urljoin
        raw_action = _html_unescape(_get_attr(attrs_str, "action") or "") or page_url
        action_url = urljoin(page_url, raw_action)

        # action URL이 다른 도메인이면 스킵
        if urlparse(action_url).netloc != base_netloc:
            continue
        # 로그아웃 경로의 폼은 세션 파기 방지를 위해 제외
        if _crawl._is_logout_path(urlparse(action_url).path):
            continue

        # 폼 내부 필드 수집
        params: Dict[str, str] = {}
        param_types: Dict[str, str] = {}
        for field_match in re.finditer(
            r'<(?:input|select|textarea)\b([^>]*)', form_body, re.IGNORECASE
        ):
            field_attrs = field_match.group(1)
            name = _get_attr(field_attrs, "name")
            if not name:
                continue
            input_type = (_get_attr(field_attrs, "type") or "text").lower()
            # 제출·파일 필드는 스캔 대상 제외
            if input_type in ("submit", "button", "image", "reset", "file"):
                continue
            if input_type == "hidden":
                # CSRF/보안 토큰 성격 필드는 제외 (주입 시 CSRF 검증 실패 유발)
                if name.lower() in CSRF_TOKEN_NAMES:
                    continue
                params[name] = _get_attr(field_attrs, "value") or ""
                param_types[name] = "hidden"
            else:
                params[name] = _get_attr(field_attrs, "value") or ""
                param_types[name] = "visible"

        # HTML5 form= 귀속 필드 병합 (이 폼의 id와 일치하는 orphan input 추가)
        form_id = _get_attr(attrs_str, "id") or ""
        for orphan in orphan_inputs.get(form_id, []):
            oname = orphan["name"]
            if oname in params:
                continue
            if orphan["type"] == "hidden":
                if oname.lower() in CSRF_TOKEN_NAMES:
                    continue
                params[oname] = orphan["value"]
                param_types[oname] = "hidden"
            else:
                params[oname] = orphan["value"]
                param_types[oname] = "visible"

        if not params:
            continue

        if method == "GET":
            # GET 폼은 action URL에 쿼리 파라미터로 변환 (body_type은 무관)
            points.append({"url": action_url, "method": "GET",
                           "params": params, "param_types": param_types,
                           "body_type": "form"})
        else:
            points.append({"url": action_url, "method": "POST",
                           "params": params, "param_types": param_types,
                           "body_type": body_type})

    # ── 4. data-url/href/action/src 속성의 쿼리 파라미터 추출 ──
    for data_match in re.finditer(
        r'\b(data-(?:url|href|action|src))=["\']([^"\']+)["\']', body, re.IGNORECASE
    ):
        attr_val = _html_unescape(data_match.group(2))
        abs_url, _ = urldefrag(urljoin(page_url, attr_val))
        # 외부 도메인 URL은 제외
        if urlparse(abs_url).netloc != base_netloc:
            continue
        # 로그아웃 경로는 세션 파기 방지를 위해 제외
        if _crawl._is_logout_path(urlparse(abs_url).path):
            continue
        data_qs = parse_qs(urlparse(abs_url).query, keep_blank_values=True)
        if data_qs:
            params = {k: v[0] for k, v in data_qs.items()}
            param_types = {k: "data" for k in params}
            points.append({"url": abs_url, "method": "GET",
                           "params": params, "param_types": param_types,
                           "body_type": "form"})

    # ── 5. JS 내부 URL / POST 바디 키 추출 ──
    points.extend(_parse_js_urls(body, page_url, base_netloc, whole_script=False))

    return points


# ── 유사도·마커·Dynamic Content Masking ───────────────────────────────────────

def similarity(a: str, b: str) -> float:
    """두 문자열의 유사도를 0~1 범위로 반환한다."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def gen_marker() -> str:
    """랜덤 9자 마커 생성 — 'SecTest' + 2 hex (예: SecTesta3).

    sqlmap의 [DELIMITER_START]/[DELIMITER_STOP] 개념과 유사.
    응답 디버깅 시 도구 흔적임을 즉시 식별 가능하도록 'SecTest' prefix 사용,
    동일 세션 내 마커 충돌 회피 위해 짧은 hex suffix(1/65K) 부여.
    """
    return "SecTest" + secrets.token_hex(1)


def build_dynamic_contexts(b1: str, b2: str,
                           context_len: int = _DYNAMIC_CONTEXT_LEN
                           ) -> List[Tuple[str, str]]:
    """두 baseline 응답 diff에서 동적 콘텐츠 주변의 (prefix, suffix) 쌍을 추출한다.

    difflib.get_opcodes()로 불일치 블록을 찾고, 각 불일치 블록 앞뒤의 equal 블록에서
    context_len자 공통 문자열을 prefix/suffix로 캡처. 이후 `apply_dynamic_mask()`가
    이 쌍을 regex 경계로 사용해 동적 구간을 __DYN__으로 치환한다.

    성능 상한: 최대 _MAX_DYNAMIC_CONTEXTS(20)개까지만 반환.
    """
    contexts: List[Tuple[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    opcodes = list(difflib.SequenceMatcher(None, b1, b2).get_opcodes())

    for idx, (tag, i1, i2, _j1, _j2) in enumerate(opcodes):
        if tag == "equal":
            continue
        # 직전/직후 opcode가 equal일 때만 안정적인 context 추출 가능
        prev_op = opcodes[idx - 1] if idx > 0 else None
        next_op = opcodes[idx + 1] if idx < len(opcodes) - 1 else None
        if not prev_op or prev_op[0] != "equal":
            continue
        if not next_op or next_op[0] != "equal":
            continue

        _, p_i1, p_i2, _, _ = prev_op
        _, n_i1, n_i2, _, _ = next_op

        # prefix: 직전 equal 블록의 마지막 context_len자 / suffix: 직후 equal 블록의 처음 context_len자
        prefix = b1[max(p_i1, p_i2 - context_len):p_i2]
        suffix = b1[n_i1:min(n_i2, n_i1 + context_len)]

        if len(prefix) < context_len or len(suffix) < context_len:
            continue

        key = (prefix, suffix)
        if key in seen:
            continue
        seen.add(key)
        contexts.append(key)
        if len(contexts) >= _MAX_DYNAMIC_CONTEXTS:
            break

    return contexts


def apply_dynamic_mask(text: str, contexts: List[Tuple[str, str]]) -> str:
    """text에서 (prefix ... suffix) 사이 영역을 (prefix + __DYN__ + suffix)로 치환한다.

    동적 콘텐츠(세션 ID·타임스탬프·nonce 등)를 균질화해 diff 기반 Boolean 판정의
    자연 변동 오차를 제거한다.
    """
    if not contexts:
        return text
    for prefix, suffix in contexts:
        pattern = re.escape(prefix) + r".*?" + re.escape(suffix)
        replacement = prefix + "__DYN__" + suffix
        text = re.sub(pattern, replacement, text, flags=re.DOTALL)
    return text
