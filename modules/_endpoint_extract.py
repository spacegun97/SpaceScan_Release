"""
_endpoint_extract.py — js_analysis의 AST 엔드포인트 탐지를 크롤러(_crawl.py)·
SQLi/경로순회 입력 포인트 수집(_sqli_util.py)에 연결하는 공유 게이트.

설계 원칙(모듈화 — 고도화가 한쪽에만 적용되지 않도록):
  - "탐지"(무엇이 엔드포인트인가 / URL·파라미터 재구성)는 js_analysis.extract_endpoints()
    하나가 유일한 출처다. JS 분석 대시보드 화면과 이 모듈을 경유하는 모든 스캐너가
    문자 그대로 동일한 코드를 호출하므로, 새 sink 형태 인식 등 탐지 고도화를 그쪽에
    한 번 넣으면 분석 화면·크롤러·SQLi·경로순회가 동시에 좋아진다.
  - "게이트"(실제 요청 가능 여부 판정 — 동일 도메인/로그아웃 경로/미해소 플레이스홀더)는
    이 파일의 gate()가 유일한 출처다. 게이트 규칙 고도화(오탐 조정 등)를 여기 한 번
    넣으면 크롤러·SQLi·경로순회가 동시에 좋아진다.
  - _crawl.py/_sqli_util.py 쪽 코드는 이 모듈이 돌려준 결과를 각자 필요한 얕은 형태
    (링크 문자열 / 입력 포인트 dict)로 바꾸는 어댑터 역할만 한다(discover_* 함수).

JS 분석 모드(js_analysis.analyze()) 자체는 이 게이트를 거치지 않는다 — 그쪽은 오히려
미해소 엔드포인트·저신뢰 candidate_endpoints까지 다 보여주는 것이 목적(공격표면 파악)
이라 "요청 가능한 것만" 걸러내는 이 게이트를 적용하면 정보가 깎인다. 같은 탐지 결과를
분석 화면은 날것 그대로, 스캐너는 게이트를 통과시켜 각자 목적에 맞게 쓴다.

정규식 기반 기존 추출(_crawl._JS_LINK_PATTERNS, _sqli_util._JS_URL_PATTERNS)은 대체하지
않고 그대로 둔다 — AST가 파싱 실패(TS/JSX 등 미지원 문법)하거나 백엔드 미설치일 때의
안전 바닥(floor)이며, 두 결과는 병합(union)해서 쓴다. 이후의 미탐 대응도 정규식이 아니라
이 파일과 js_analysis 쪽(AST 계층)에 넣는 것을 원칙으로 한다.
"""
import re
from datetime import datetime
from urllib.parse import urljoin, urldefrag, urlparse
from typing import Any, Dict, List, Optional, Tuple

from . import _crawl
from . import js_analysis

# js_analysis가 재구성한 URL/파라미터 값에 남는 미해소 값 플레이스홀더 — "{contextRoot}"
# 처럼 정적으로 못 푼 값을 감싸는 표기(js_analysis._PLACEHOLDER_RE와 동일 패턴을 그대로
# 참조 — 두 곳이 따로 정의되어 드리프트하는 것을 방지).
_PLACEHOLDER_RE = js_analysis._PLACEHOLDER_RE

# N-hop 파라미터 전파(variants)가 호출자 인자를 그대로 substitution한 값 중, 실제
# HTTP 요청에 안전하게 쓸 수 있는 "리터럴처럼 생긴" 값만 인정하는 패턴 — 숫자거나
# 점(.)·괄호·공백이 없는 단순 토큰(예: "5", "USER_LIST", "active")만 허용한다.
# js_analysis의 variant substitution 값은 문자열 리터럴 인자는 따옴표가 벗겨진 실제
# 값("5")이지만, `row.uid`처럼 리터럴이 아닌 인자도 재구성된 표현식 텍스트 그대로
# 담겨 있어(분석·표시 목적이므로 의도적으로 리터럴화하지 않음 — js_analysis 자체
# 문서 참고) 구분 없이 그대로 쓰면 크롤 요청에 "uid=row.uid" 같은 문자 그대로의
# 표현식 텍스트가 나갈 수 있다. 크롤 링크(discover_crawl_links)에서만 이 검사를
# 적용하고, 입력 포인트(discover_input_points)는 어차피 SQLi가 값을 페이로드로
# 덮어쓰므로 이름만 있으면 되어 이 검사를 적용하지 않는다.
_SAFE_LITERAL_VALUE_RE = re.compile(r'^(?:-?\d+(?:\.\d+)?|[A-Za-z_][\w\-]*)?$')


def _is_safe_literal_value(value: str) -> bool:
    """크롤 요청에 그대로 써도 되는 "리터럴처럼 생긴" 값인지 확인한다 (위 설명 참고)."""
    return bool(_SAFE_LITERAL_VALUE_RE.match(value))


def _endpoint_variants(ep: Dict[str, Any]) -> List[Tuple[str, Dict[str, str]]]:
    """엔드포인트 하나의 기본 재구성 결과 + N-hop 파라미터 전파(variants)로 얻은 모든
    구체화 결과를 (url, {name: value}) 튜플 목록으로 평탄화한다.

    base 하나만 보고 버리지 않는 이유: 게이트웨이형 엔드포인트(예: `/gateway.do?cmd=
    {action}`)는 variant마다 값이 다른 별개의 실제 엔드포인트를 의미하므로, base가
    미해소라서 드롭되더라도 그 variants 중 실제로 풀린 것들은 살려야 한다.
    """
    out: List[Tuple[str, Dict[str, str]]] = [
        (ep.get("url", ""), {p["name"]: p.get("value", "") for p in ep.get("params", [])})
    ]
    for v in ep.get("variants", []):
        out.append((v.get("url", ""), dict(v.get("params", {}))))
    return out


def _is_requestable_path(url_no_query: str) -> bool:
    """경로(쿼리 제외) 부분에 미해소 "{name}" 플레이스홀더가 남아있지 않은지 확인한다.

    쿼리 파라미터 *값*에 남은 플레이스홀더는 여기서 걸러내지 않는다 — SQLi/경로순회는
    그 값을 자신의 페이로드로 덮어쓰므로 실제 요청 가능 여부에 영향을 주지 않는다
    (파라미터 *이름*만 알면 충분). 반면 경로/호스트에 남은 플레이스홀더는 그대로
    요청하면 리터럴 "{contextRoot}" 문자열이 그대로 전송되는 요청 불가능한 URL이므로
    반드시 걸러야 한다.
    """
    return not _PLACEHOLDER_RE.search(url_no_query)


def gate(endpoints: List[Dict[str, Any]], page_url: str, base_netloc: str,
         scope: str, debug_sink: Optional[List[Tuple[str, str, str]]] = None
         ) -> List[Dict[str, Any]]:
    """AST가 재구성한 엔드포인트 목록(js_analysis.extract_endpoints()의 결과)을 실제로
    요청 가능한 것만 걸러 절대 URL로 정규화한다.

    필터 3종(크롤러의 기존 정책과 동일한 판정 함수를 그대로 재사용):
      1. 경로/호스트에 미해소 "{name}" 플레이스홀더가 남은 경우 드롭
      2. 동일 사이트가 아니면(`_crawl._same_site`) 드롭
      3. 로그아웃 경로면(`_crawl._is_logout_path`) 드롭

    드롭 사유는 debug_sink가 주어지면 그 리스트에 append한다(기존 debug_events/
    crawl_path.log 관례와 동일한 (timestamp, scope, message) 튜플) — 경로 미탐
    트러블슈팅 시 "AST는 찾았는데 게이트에서 왜 버려졌는지"를 바로 확인하기 위함.

    반환 레코드: {"method": str, "url": str(절대 URL, 쿼리 포함), "params": {name: value}}
    (method, url, 파라미터명 집합) 기준으로 중복 제거한다.
    """
    kept: List[Dict[str, Any]] = []
    seen: set = set()

    def _drop(method: str, raw_url: str, reason: str) -> None:
        if debug_sink is not None:
            debug_sink.append((datetime.now().isoformat(timespec='milliseconds'),
                               scope, f"AST 엔드포인트 드롭({reason}): {method} {raw_url}"))

    for ep in endpoints:
        method = ep.get("method") or "GET"
        for raw_url, params in _endpoint_variants(ep):
            if not raw_url:
                continue
            path_part = raw_url.split("?", 1)[0]
            if not _is_requestable_path(path_part):
                _drop(method, raw_url, "경로에 미해소 플레이스홀더")
                continue
            abs_url, _ = urldefrag(urljoin(page_url, raw_url))
            parsed = urlparse(abs_url)
            if not _crawl._same_site(parsed.netloc, base_netloc):
                _drop(method, raw_url, "타 도메인")
                continue
            if _crawl._is_logout_path(parsed.path):
                _drop(method, raw_url, "로그아웃 경로")
                continue
            key = (method, abs_url, frozenset(params.keys()))
            if key in seen:
                continue
            seen.add(key)
            kept.append({"method": method, "url": abs_url, "params": params})
    return kept


def _extract(body: str, kind: str) -> List[Dict[str, Any]]:
    """js_analysis.extract_endpoints()를 호출하기 위한 공통 진입로. kind에 맞춰
    합성 파일명(확장자만 의미 있음)을 부여하고, 실패 시 조용히 빈 리스트를 반환한다."""
    fname = "page.html" if kind == "html" else "page.js"
    try:
        return js_analysis.extract_endpoints(fname, body.encode("utf-8", errors="replace"))
    except Exception:
        return []


def discover_crawl_links(body: str, page_url: str, base_netloc: str, kind: str,
                          debug_sink: Optional[List[Tuple[str, str, str]]] = None
                          ) -> List[str]:
    """크롤 큐 확장용 어댑터: AST로 발견해 게이트를 통과한 엔드포인트를 절대 URL
    문자열 목록으로 변환한다. kind: "html" | "script".

    쿼리 파라미터 값이 "리터럴처럼 생긴" 안전한 값(_is_safe_literal_value)이 아니면
    빈 문자열로 비운다 — 미해소 플레이스홀더("{name}")뿐 아니라, N-hop 파라미터
    전파(variants)가 호출자의 비-리터럴 인자를 그대로 남긴 경우(예: "row.uid")까지
    포함한다. 실제로 그런 문자열 그대로 요청을 보내는 것은 무의미하기 때문이다
    (기존 <form> 필드 큐잉 관례인 blank-value 방식과 동일한 스타일).

    크롤러는 BFS 방문을 항상 GET으로만 수행하므로(정규식 경로도 동일), POST로
    탐지된 엔드포인트는 params가 쿼리가 아닌 바디 키이므로 쿼리스트링으로 붙이지
    않고 URL만(쿼리 없이) 큐에 추가한다.
    """
    if kind not in ("html", "script"):
        return []
    endpoints = _extract(body, kind)
    if not endpoints:
        return []
    gated = gate(endpoints, page_url, base_netloc, scope="crawl", debug_sink=debug_sink)

    links: List[str] = []
    for ep in gated:
        # POST 등은 params가 바디 키이므로 쿼리스트링을 붙이지 않고 URL만 큐에 추가
        if ep["method"] != "GET":
            links.append(ep["url"].split("?", 1)[0])
            continue
        if not ep["params"]:
            links.append(ep["url"])
            continue
        base, _, _query = ep["url"].partition("?")
        pairs = []
        for name, value in ep["params"].items():
            v = value if _is_safe_literal_value(value) else ""
            pairs.append(f"{name}={v}")
        links.append(f"{base}?{'&'.join(pairs)}")
    return links


def discover_input_points(body: str, page_url: str, base_netloc: str, whole_script: bool,
                           scope: str, debug_sink: Optional[List[Tuple[str, str, str]]] = None
                           ) -> List[Dict[str, Any]]:
    """SQLi/경로순회 입력 포인트 수집용 어댑터: AST로 발견해 게이트를 통과한 엔드포인트를
    parse_input_points()류가 쓰는 입력 포인트 dict 목록으로 변환한다.

    파라미터가 없는 엔드포인트(주입할 자리 없음)는 제외한다. 파라미터 값에 남은
    플레이스홀더는 그대로 둔다 — SQLi가 어차피 자신의 페이로드로 덮어쓴다.
    param_types는 "ast_url"(GET)/"ast_body"(POST) — 기존 "hidden"/"path" 두 값만
    분기 로직에 영향을 주므로 새 태그는 표시용으로만 쓰이고 기존 흐름에 영향 없다.
    """
    kind = "script" if whole_script else "html"
    endpoints = _extract(body, kind)
    if not endpoints:
        return []
    gated = gate(endpoints, page_url, base_netloc, scope=scope, debug_sink=debug_sink)

    points: List[Dict[str, Any]] = []
    for ep in gated:
        if not ep["params"]:
            continue
        tag = "ast_url" if ep["method"] == "GET" else "ast_body"
        points.append({
            "url": ep["url"], "method": ep["method"],
            "params": dict(ep["params"]),
            "param_types": {k: tag for k in ep["params"]},
            "body_type": "form" if ep["method"] == "GET" else "json",
        })
    return points
