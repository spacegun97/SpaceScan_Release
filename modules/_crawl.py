"""
BFS 웹 크롤러 공통 유틸
directory_listing, sql_injection, path_traversal 모듈이 공유한다.
"""
import json as _json
import threading
import time
import re
import requests
from collections import deque
from datetime import datetime
from html import unescape as _html_unescape
from urllib.parse import urlparse, urljoin, urldefrag, parse_qs
from typing import List, Dict, Any, Callable, Optional, Tuple
from ._cancel import wait_or_cancel, run_cancellable, ScanCancelled

# 로그아웃 경로 패턴 — 세션 파기 방지를 위해 큐 추가 단계에서 제외
# path의 마지막 segment가 logout/log-out/signout/sign-out과 정확히 일치하는 경우만 매칭
# (예: /logout, /auth/logout, /sqli/logout.jsp → 차단 / /logout-help → 차단 안 함)
LOGOUT_PATTERN = re.compile(
    r'/(logout|log-out|signout|sign-out)(/|\.|$)', re.IGNORECASE
)

# 페이지네이션 성격 파라미터 — C9 서명 방문 상한(3회) 예외 대상
# (예: ?page=1..N 형태로 이어지는 링크가 max_pages까지 계속 발견되도록 허용)
_PAGINATION_PARAMS = frozenset({
    "page", "p", "pg", "pageno", "page_no", "pagenum",
    "offset", "start", "skip", "from", "idx",
})

# 스크립트 본문에서 링크 발견용 JS URL 패턴 (큐 확장 목적)
# C-6: 백틱(`) 템플릿 리터럴 포함 — 링크 발견(큐 확장)만이 목적이라 ${...} 보간이 섞여도
# _add()의 '${' 가드가 걸러낸다. _sqli_util._JS_URL_PATTERNS는 실제 입력 포인트를 구성하므로
# 백틱을 별도로 제외한 자체 패턴을 갖는다 (아래 참조 없이 독립 정의).
_JS_LINK_PATTERNS = [
    re.compile(r"""\bfetch\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
    re.compile(r"""\.open\s*\(\s*["']\w+["']\s*,\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
    re.compile(r"""\$\.(?:get|post|ajax)\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
    re.compile(r"""\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*["'`]([^"'`]+)["'`]""",
               re.IGNORECASE | re.DOTALL),
    re.compile(r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*["'`]([^"'`]+)["'`]""",
               re.IGNORECASE),
    re.compile(r"""window\.open\s*\(\s*["'`]([^"'`]+)["'`]""", re.IGNORECASE),
    re.compile(r"""location\.(?:href|replace|assign)\s*(?:=|\()\s*["'`]([^"'`]+)["'`]""",
               re.IGNORECASE),
]

# 스크립트 Content-Type 키워드
_SCRIPT_CT_KEYWORDS = ("javascript", "ecmascript")

# CT로 분류되지 않은 응답의 본문 스니핑용 — 선행 HTML 주석 이후 흔한 HTML 태그로 시작하는지 확인
_HTML_SNIFF_RE = re.compile(
    r'^(?:\s*<!--.*?-->)*\s*<(?:!doctype\s+html|\?xml|html|head|body|div|table'
    r'|ul|ol|section|main|article|nav|header|footer|span|p|a)\b',
    re.IGNORECASE | re.DOTALL
)


class _RenderedResponse:
    """Playwright 렌더 결과를 requests.Response 부분집합으로 포장한다.

    _classify_response / _extract_links_from_body 등 기존 로직이 수정 없이 재사용되도록
    .url / .headers / .text 인터페이스만 흉내낸다.
    """
    def __init__(self, url: str, content_type: str, text: str) -> None:
        self.url = url
        self.headers: Dict[str, str] = {"content-type": content_type}
        self.text = text


def _is_logout_path(path: str) -> bool:
    """URL path가 로그아웃 경로 패턴과 매칭되는지 확인한다."""
    return bool(LOGOUT_PATTERN.search(path))


def _same_site(netloc: str, base_netloc: str) -> bool:
    """netloc이 base_netloc과 동일 사이트인지 확인한다.

    호스트 대소문자를 무시하고, 선행 "www." 유무 한 단계만 동일 취급한다.
    (예: example.com ↔ www.example.com은 동일 취급, api.example.com은 별개 취급)
    포트·그 외 서브도메인은 그대로 구분한다.
    """
    def _canon(n: str) -> str:
        n = n.lower()
        return n[4:] if n.startswith("www.") else n
    return _canon(netloc) == _canon(base_netloc)


def _classify_response(resp: requests.Response, final_url: str) -> str:
    """응답을 'html' / 'script' / 'json' / 'other' 네 종류로 분류한다.

    C3: application/xhtml+xml 추가, CT 누락·text/plain 시 본문 앞 500자 스니핑으로 html 추정.
    C4: 상태코드와 무관하게 CT·확장자·본문으로만 판정 — 비200 응답도 본문 파싱 대상이 됨.
    C-1: CT 누락·text/plain 시 { / [ 시작이면 json.loads 검증 후 json 분류 (오분류 방지).
    C-2: html/script/json으로 특정되지 않은 모든 CT(application/xml·octet-stream 등 포함)에서
         본문 앞부분 스니핑을 시도해, 서버가 CT를 잘못 내려주는 경우의 본문 폐기를 줄인다.
    """
    ct = resp.headers.get("content-type", "").lower()
    if "text/html" in ct or "application/xhtml+xml" in ct:
        return "html"
    if any(kw in ct for kw in _SCRIPT_CT_KEYWORDS) or final_url.split("?")[0].endswith(".js"):
        return "script"
    if "application/json" in ct:
        return "json"
    # 위 CT로 특정되지 않은 모든 경우 본문 앞부분 스니핑으로 html/json 추정 (C-2)
    head = resp.text[:500].lstrip()
    if _HTML_SNIFF_RE.match(head):
        return "html"
    if head.startswith(("{", "[")):
        try:
            _json.loads(resp.text)  # 진짜 JSON일 때만 분류 — 오분류·불필요 본문 보관 방지
            return "json"
        except Exception:
            pass
    return "other"


def _fetch_sitemap_urls(
    url: str, base_netloc: str, timeout: int,
    cookies: Optional[Dict[str, str]],
    proxies: Optional[Dict[str, str]],
    headers: Dict[str, str],
    delay: float = 0.7,
    stop_event: Optional["threading.Event"] = None,
    _depth: int = 0,
) -> List[str]:
    """sitemap URL에서 같은 도메인 페이지 URL을 재귀 수집한다 (C8).

    <sitemapindex> 구조를 만나면 자식 sitemap을 재귀 조회한다.
    재귀 깊이 상한 3, 자식 sitemap 최대 20개.
    C-R: 재귀 호출을 포함해 요청 직전마다 delay를 적용해 서버 부하를 제한하고,
    stop_event가 set되면 ScanCancelled로 즉시 중단한다(BFS 본 루프와 동일 정책).
    """
    if _depth > 2:
        return []
    result: List[str] = []
    try:
        wait_or_cancel(stop_event, delay)  # 속도 조절 딜레이 (+ [중단] 검사)
        # 요청 자체는 데몬 워커에서 실행 — 전송 후 응답 대기 중에도 [중단]이 즉시 반응한다.
        # stop 시 워커는 버려두고(요청 1건은 스스로 자연 종료) 호출 스레드만 즉시 탈출한다.
        resp = run_cancellable(
            lambda: requests.get(url, timeout=timeout, verify=False, allow_redirects=True,
                                 cookies=cookies, proxies=proxies, headers=headers),
            stop_event,
        )
        if resp.status_code != 200:
            return result
        text = resp.text

        # sitemap index: <sitemap><loc>...</loc></sitemap> 자식 재귀 조회
        child_locs = re.findall(
            r'<sitemap\b[^>]*>\s*<loc>\s*(https?://[^<\s]+)\s*</loc>',
            text, re.IGNORECASE
        )
        if child_locs:
            for child_url in child_locs[:20]:
                result.extend(
                    _fetch_sitemap_urls(child_url.strip(), base_netloc, timeout,
                                        cookies, proxies, headers, delay, stop_event,
                                        _depth + 1)
                )
            return result

        # 일반 sitemap: <loc> 필터링
        for m in re.finditer(r'<loc>\s*(https?://[^<\s]+)\s*</loc>', text, re.IGNORECASE):
            abs_url, _ = urldefrag(m.group(1).strip())
            parsed = urlparse(abs_url)
            if _same_site(parsed.netloc, base_netloc) and not _is_logout_path(parsed.path):
                result.append(abs_url)
    except Exception:
        pass
    return result


def _seed_from_robots_sitemap(
    base_netloc: str, scheme: str, timeout: int,
    cookies: Optional[Dict[str, str]],
    proxies: Optional[Dict[str, str]],
    auth_headers: Optional[Dict[str, str]],
    delay: float = 0.7,
    stop_event: Optional["threading.Event"] = None,
) -> List[str]:
    """robots.txt와 sitemap.xml에서 같은 도메인 URL을 수집해 시드 목록으로 반환한다.

    robots.txt의 Disallow/Allow 라인은 발견 힌트로 사용하며 차단 규칙을 따르지 않는다.
    sitemap.xml은 _fetch_sitemap_urls로 중첩 sitemap index까지 재귀 전개한다 (C8).
    수집된 URL은 base_netloc 기준 동일 도메인 여부와 로그아웃 경로 필터를 통과해야 한다.
    C-R: robots.txt 요청도 BFS 본 루프와 동일하게 delay를 적용하고 stop_event로 중단 가능하게 한다.
    """
    seeds: List[str] = []
    origin = f"{scheme}://{base_netloc}"
    headers = auth_headers or {}

    # robots.txt 처리
    try:
        wait_or_cancel(stop_event, delay)  # 속도 조절 딜레이 (+ [중단] 검사)
        # 요청 자체는 데몬 워커에서 실행 — 전송 후 응답 대기 중에도 [중단]이 즉시 반응한다.
        resp = run_cancellable(
            lambda: requests.get(origin + "/robots.txt", timeout=timeout,
                                 verify=False, allow_redirects=True,
                                 cookies=cookies, proxies=proxies, headers=headers),
            stop_event,
        )
        if resp.status_code == 200:
            for m in re.finditer(
                r'^(?:Disallow|Allow|Sitemap)\s*:\s*(\S+)',
                resp.text, re.MULTILINE | re.IGNORECASE
            ):
                val = m.group(1)
                abs_url, _ = urldefrag(
                    val if val.startswith("http") else urljoin(origin, val)
                )
                parsed = urlparse(abs_url)
                # Sitemap 지시자는 _fetch_sitemap_urls로 재귀 전개
                if m.group(0).lstrip().lower().startswith("sitemap"):
                    seeds.extend(
                        _fetch_sitemap_urls(abs_url, base_netloc, timeout,
                                            cookies, proxies, headers, delay, stop_event)
                    )
                elif (_same_site(parsed.netloc, base_netloc)
                      and not _is_logout_path(parsed.path)):
                    seeds.append(abs_url)
    except Exception:
        pass

    # sitemap.xml 처리 — 재귀 전개
    seeds.extend(
        _fetch_sitemap_urls(origin + "/sitemap.xml", base_netloc, timeout,
                            cookies, proxies, headers, delay, stop_event)
    )

    return seeds


def _extract_urls_from_json(body: str, base_url: str, base_netloc: str) -> List[str]:
    """JSON 본문에서 같은 도메인 URL 문자열을 재귀 탐색하여 반환한다 (HATEOAS 커버).

    절대 URL(http/https) 또는 루트 상대 경로(/)를 인식한다.
    """
    result: List[str] = []
    try:
        data = _json.loads(body)
    except Exception:
        return result

    def _walk(obj: Any) -> None:
        if isinstance(obj, str):
            if not obj.startswith(("http://", "https://", "/")):
                return
            try:
                abs_url, _ = urldefrag(urljoin(base_url, obj))
                parsed = urlparse(abs_url)
                if _same_site(parsed.netloc, base_netloc) and not _is_logout_path(parsed.path):
                    result.append(abs_url)
            except Exception:
                pass
        elif isinstance(obj, dict):
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(data)
    return result


def _extract_links_from_body(body: str, final_url: str,
                              base_netloc: str, kind: str,
                              debug_sink: Optional[List[Tuple[str, str, str]]] = None) -> List[str]:
    """HTML 또는 스크립트 본문에서 같은 도메인 링크를 추출한다.

    P4: HTML 엔티티 디코드(_html_unescape) 후 urljoin.
    C5: data-url/href/action/src, srcset, <base href>, <meta refresh>, 따옴표 없는 href 추가.
    C6: html 종류에서도 <script> 블록·on* 핸들러의 JS 링크 패턴으로 큐 확장.
    C13: 위 정규식(_JS_LINK_PATTERNS)이 놓치는 동적 조립 URL(변수 결합·axios baseURL
         인스턴스·N-hop 파라미터 전파 등)을 esprima/tree-sitter AST 기반(js_analysis
         재사용, _endpoint_extract 경유)으로 보강한다. 정규식 결과와 병합(union)만
         하며 대체하지 않는다 — AST 파싱 실패(TS/JSX 등)·백엔드 미설치 시 조용히
         빈 리스트로 폴백한다. debug_sink가 주어지면 게이트 드롭 사유를 append한다
         (기존 debug_events/crawl_path.log 관례 — 경로 미탐 트러블슈팅용).
    """
    links: List[str] = []

    # <base href> 추출 — 상대 경로 해석 기준을 재설정한다 (html 종류에서만)
    base_url = final_url
    if kind == "html":
        base_m = re.search(r'<base\b[^>]*\bhref=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if base_m:
            candidate = _html_unescape(base_m.group(1))
            abs_base, _ = urldefrag(urljoin(final_url, candidate))
            if _same_site(urlparse(abs_base).netloc, base_netloc):
                base_url = abs_base

    def _add(raw: str) -> None:
        """원시 URL 문자열을 정규화·필터링 후 links에 추가한다.
        P4: HTML 엔티티를 디코드하여 파라미터 손상을 방지한다.
        """
        raw = _html_unescape(raw).strip()
        if not raw or raw.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
            return
        # 백틱 템플릿 리터럴의 ${...} 보간 값은 실제 URL이 아니므로 큐잉하지 않는다 (C6 백틱 확장 부작용 차단)
        if '${' in raw:
            return
        abs_url, _ = urldefrag(urljoin(base_url, raw))
        parsed = urlparse(abs_url)
        if _same_site(parsed.netloc, base_netloc) and not _is_logout_path(parsed.path):
            links.append(abs_url)

    if kind == "html":
        # href/src/action — 따옴표 있는 경우
        # C-4: 등호 앞뒤 공백·줄바꿈 허용 + 여는 따옴표와 짝이 맞는 반대 따옴표까지 캡처
        #      (예: href="/x?n=O'Brien" 에서 값 내부 작은따옴표로 잘리지 않도록 역참조 사용)
        for _quote, attr_val in re.findall(
            r'(?:href|src|action)\s*=\s*(["\'])(.*?)\1', body, re.IGNORECASE
        ):
            _add(attr_val)

        # href/src/action — 따옴표 없는 경우 (href=/path 형태, C5/C-4)
        for attr_val in re.findall(
            r'(?:href|src|action)\s*=\s*([^"\'>\s]+)', body, re.IGNORECASE
        ):
            _add(attr_val)

        # data-url / data-href / data-action / data-src 속성 (C5)
        for attr_val in re.findall(
            r'data-(?:url|href|action|src)=["\']([^"\']+)["\']', body, re.IGNORECASE
        ):
            _add(attr_val)

        # srcset — 쉼표 구분 후보에서 URL(공백 전 첫 토큰) 추출 (C5)
        for srcset_val in re.findall(r'srcset=["\']([^"\']+)["\']', body, re.IGNORECASE):
            for candidate in srcset_val.split(','):
                parts = candidate.strip().split()
                if parts:
                    _add(parts[0])

        # <meta http-equiv=refresh content="N; url=..."> (C5)
        for content_val in re.findall(
            r'<meta\b[^>]*\bhttp-equiv=["\']refresh["\'][^>]*\bcontent=["\']([^"\']+)["\']',
            body, re.IGNORECASE
        ):
            m = re.search(r'url\s*=\s*([^\s"\'>;]+)', content_val, re.IGNORECASE)
            if m:
                _add(m.group(1))

        # C-5: GET <form>의 action + 필드명을 조합해 결과 페이지 URL을 큐에 추가한다.
        # (입력 포인트 자체는 parse_input_points가 별도로 수집 — 여기는 링크 발견 목적)
        for form_m in re.finditer(
            r'<form\b([^>]*)>(.*?)</form>', body, re.IGNORECASE | re.DOTALL
        ):
            attrs_str, form_body = form_m.group(1), form_m.group(2)
            method_m = re.search(r'\bmethod\s*=\s*["\']?(\w+)', attrs_str, re.IGNORECASE)
            if method_m and method_m.group(1).upper() != "GET":
                continue
            action_m = re.search(r'\baction\s*=\s*["\']([^"\']+)["\']', attrs_str, re.IGNORECASE)
            action = _html_unescape(action_m.group(1)).strip() if action_m else ""

            field_names: List[str] = []
            for field_m in re.finditer(
                r'<(?:input|select|textarea)\b([^>]*)', form_body, re.IGNORECASE
            ):
                field_attrs = field_m.group(1)
                type_m = re.search(r'\btype\s*=\s*["\']?(\w+)', field_attrs, re.IGNORECASE)
                ftype = type_m.group(1).lower() if type_m else "text"
                if ftype in ("submit", "button", "image", "reset", "file"):
                    continue
                name_m = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', field_attrs, re.IGNORECASE)
                if name_m:
                    field_names.append(name_m.group(1))

            if field_names:
                qs = "&".join(f"{n}=" for n in field_names)
                sep = "&" if "?" in action else "?"
                _add(f"{action}{sep}{qs}")

        # C6: <script> 블록 · on* 인라인 핸들러에서 JS URL 패턴으로 큐 확장
        for block_m in re.finditer(
            r'<script\b[^>]*>(.*?)</script>', body, re.IGNORECASE | re.DOTALL
        ):
            for pat in _JS_LINK_PATTERNS:
                for lm in pat.finditer(block_m.group(1)):
                    _add(lm.group(1))
        for attr_m in re.finditer(r'\bon\w+\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE):
            for pat in _JS_LINK_PATTERNS:
                for lm in pat.finditer(attr_m.group(1)):
                    _add(lm.group(1))

    elif kind == "script":
        # 스크립트 파일: JS 호출 패턴에서 URL 추출
        for pat in _JS_LINK_PATTERNS:
            for m in pat.finditer(body):
                _add(m.group(1))

    elif kind == "json":
        # JSON 응답: 본문에서 URL 문자열 재귀 추출 (HATEOAS / 중첩 리소스 링크)
        for url in _extract_urls_from_json(body, base_url, base_netloc):
            links.append(url)

    # C13: AST 기반 엔드포인트 탐지로 보강 (html/script만 대상 — json은 URL 재귀
    # 추출로 이미 커버됨). _endpoint_extract가 게이트(동일 도메인/로그아웃/플레이스홀더)
    # 까지 마친 절대 URL만 돌려주므로 여기서는 그대로 이어붙이기만 한다.
    if kind in ("html", "script"):
        from . import _endpoint_extract  # 순환 import 회피 — 함수 내부 지연 import
        links.extend(_endpoint_extract.discover_crawl_links(
            body, base_url, base_netloc, kind, debug_sink=debug_sink))

    return links


def _make_route_handler(base_netloc: str,
                        xhr_points: List[Dict],
                        xhr_visited: set,
                        delay: float = 0.7,
                        stop_event: Optional["threading.Event"] = None,
                        activity: Optional[Dict[str, float]] = None):
    """Playwright 라우트 훅을 반환한다.

    C2 강제: 비-GET 요청은 전송 차단(abort). GET 로그아웃 경로도 abort(세션 보호).
    네트워크 인터셉션: 같은 netloc의 GET(쿼리 파라미터)·POST(바디) 요청을
    입력 포인트 dict로 기록한다. PUT/PATCH/DELETE 등은 abort만 하고 기록 제외.

    C-R: 같은 도메인(base_netloc)으로 실제 전송(continue_)되는 요청(문서·서브리소스 모두)에는
    정적 크롤과 동일하게 delay를 적용해 타깃 서버 부하를 제한한다. 다른 도메인(CDN·폰트 등)은
    타깃 서버 부하가 아니므로 대상에서 제외한다. stop_event가 set되면 대기를 즉시 끊고
    해당 요청을 abort한다([중단] 즉시 반응 — Playwright 콜백 스레드에서 예외를 밖으로
    전파하지 않고 이 안에서 직접 처리한다).
    activity: {"ts": float} — 같은 도메인 요청이 관측될 때마다 시각을 갱신한다.
    _render_fetch가 load 이후 연쇄 XHR 드레인 완료 시점을 판단하는 데 사용한다.
    """
    def handler(route) -> None:
        req = route.request
        method = req.method.upper()
        url = req.url
        try:
            parsed = urlparse(url)
        except Exception:
            route.continue_()
            return

        same_site = _same_site(parsed.netloc, base_netloc)
        if same_site and activity is not None:
            activity["ts"] = time.time()

        # 비-GET 차단 (C2) — GET 로그아웃도 abort (세션 보호)
        if method != "GET" or _is_logout_path(parsed.path):
            # POST: 같은 도메인이면 입력 포인트로 기록(전송은 차단)
            if method == "POST" and same_site:
                key = ("POST", url)
                if key not in xhr_visited:
                    xhr_visited.add(key)
                    post_data = req.post_data or ""
                    params: Dict[str, str] = {}
                    body_type = "form"
                    try:
                        parsed_body = _json.loads(post_data)
                        if isinstance(parsed_body, dict):
                            params = {k: str(v) for k, v in parsed_body.items()
                                      if isinstance(k, str)}
                            body_type = "json"
                    except Exception:
                        try:
                            qs = parse_qs(post_data, keep_blank_values=True)
                            params = {k: v[0] for k, v in qs.items()}
                        except Exception:
                            pass
                    if params:
                        param_types = {k: "xhr_body" for k in params}
                        xhr_points.append({
                            "url": url, "method": "POST",
                            "params": params, "param_types": param_types,
                            "body_type": body_type,
                        })
            # 전송 차단(abort)이므로 서버로 나가지 않음 — throttle 불필요
            route.abort()
            return

        # GET: 같은 도메인 + 쿼리 파라미터 있으면 입력 포인트로 기록
        if same_site:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            if qs:
                key = ("GET", url)
                if key not in xhr_visited:
                    xhr_visited.add(key)
                    params = {k: v[0] for k, v in qs.items()}
                    param_types = {k: "xhr_get" for k in params}
                    xhr_points.append({
                        "url": url, "method": "GET",
                        "params": params, "param_types": param_types,
                        "body_type": "form",
                    })

        # 같은 도메인으로 실제 전송되는 요청 — throttle 적용 (C-R)
        if same_site:
            try:
                wait_or_cancel(stop_event, delay)
            except ScanCancelled:
                # 콜백 스레드 밖(BFS 본 루프)에서 다음 wait_or_cancel(stop_event, 0)이
                # 곧 ScanCancelled를 던져 크롤을 중단하므로, 여기서는 이 요청만 정리한다.
                try:
                    route.abort()
                except Exception:
                    pass
                return
        route.continue_()

    return handler


def _render_fetch(render_ctx,
                  url: str, delay: float,
                  xhr_points: List[Dict], xhr_visited: set,
                  base_netloc: str, stop_event=None) -> Optional["_RenderedResponse"]:
    """Playwright 컨텍스트로 URL을 렌더링하고 _RenderedResponse를 반환한다.

    - 라우트 훅을 통해 C2 강제 + 네트워크 인터셉션 + 같은 도메인 delay throttle 동시 적용(C-R).
    - 문서·서브리소스 모두 라우트 훅에서 delay가 적용되므로(서버 부하는 정적 크롤과 동일하게
      제한됨), 탐색(goto) 자체에는 고정 시간 상한을 두지 않는다(timeout=0) — 같은 도메인
      서브리소스 수 × delay가 고정 timeout을 쉽게 넘을 수 있기 때문이다. 대신 [중단] 버튼으로
      언제든 즉시 빠져나올 수 있다(라우트 훅의 stop_event 검사가 즉시 반응).
    - load 완료 후 같은 도메인 후속 요청(연쇄 XHR)이 (delay + 여유시간) 동안 없을 때까지
      최대 settle_cap초 대기해 비동기 API 호출을 포착한다. 폴링형 SPA의 무한 대기 방지를
      위해 settle_cap으로 절대 상한을 둔다.
    - 예외(크래시 등) 시 None 반환 → 호출부에서 정적 크롤 폴백.
    """
    page = None
    try:
        activity: Dict[str, float] = {"ts": time.time()}
        page = render_ctx.new_page()
        page.route("**/*", _make_route_handler(base_netloc, xhr_points, xhr_visited,
                                                delay, stop_event, activity))
        resp = page.goto(url, timeout=0, wait_until="load")
        if resp is None:
            return None
        # 연쇄 XHR 드레인 대기 — activity 시각이 quiet_window 이상 안 갱신되면 완료로 간주
        quiet_window = (delay + 1.0) if delay and delay > 0 else 1.0
        settle_cap = max(10.0, (delay or 0) * 6)
        deadline = time.time() + settle_cap
        while time.time() < deadline:
            remaining = quiet_window - (time.time() - activity["ts"])
            if remaining <= 0:
                break
            wait_or_cancel(stop_event, min(remaining, 0.5))
        ct = resp.headers.get("content-type", "") or ""
        rendered_html = page.content()
        final_url = page.url
        return _RenderedResponse(final_url, ct, rendered_html)
    except Exception:
        return None
    finally:
        if page:
            try:
                page.close()
            except Exception:
                pass


def crawl(base_url: str, base_netloc: str, timeout: int,
          delay: float, max_pages: int,
          cookies: Optional[Dict[str, str]] = None,
          progress_cb: Optional[Callable[[int, int], None]] = None,
          proxies: Optional[Dict[str, str]] = None,
          auth_headers: Optional[Dict[str, str]] = None,
          render: bool = False,
          stop_event: Optional["threading.Event"] = None,
          debug_sink: Optional[List[Tuple[str, str, str]]] = None) -> List[Dict[str, Any]]:
    """BFS 크롤링으로 같은 도메인 내 페이지를 수집한다.

    반환값 페이지 dict 필드:
    - url       : 최종 리다이렉트 후 URL
    - path      : URL 경로 부분
    - body      : 응답 바디 (html/script/json 종류만, other는 None)
    - kind      : "html" | "script" | "json" | "other" | "xhr"
    - visited_at: 방문 타임스탬프
    - points    : (kind="xhr" 전용) 네트워크 인터셉션으로 수집된 입력 포인트 list

    render=True이면 Playwright Chromium으로 렌더링 후 DOM·XHR 트래픽을 수집한다.
    의존성 설치 실패 시 정적 requests 크롤로 자동 폴백.
    BFS 시작 전 robots.txt와 sitemap.xml에서 추가 시드를 수집한다.
    debug_sink가 주어지면 AST 기반 엔드포인트 탐지(C13, _extract_links_from_body 참고)의
    게이트 드롭 사유를 (timestamp, scope, message) 튜플로 append한다 — 호출자(각 모듈의
    scan())가 자신의 debug_events 리스트를 그대로 넘기면 crawl_path.log에 함께 남는다.
    progress_cb: (current_visited, max_pages) 형식으로 매 페이지 방문 시 호출된다.
    """
    visited: set = set()
    # C9: (path, frozenset(쿼리 파라미터명)) 서명별 방문 횟수 — 값만 다른 반복 URL 예산 보호
    sig_count: Dict[Tuple[str, frozenset], int] = {}
    scheme = urlparse(base_url).scheme or "https"

    # ── Playwright 브라우저 초기화 (render=True일 때만) ──────────────────────────
    _pw_mgr = None
    _browser = None
    render_ctx = None
    xhr_points: List[Dict[str, Any]] = []   # 네트워크 인터셉션 수집 입력 포인트
    xhr_visited: set = set()                # (method, url) 중복 방지

    if render:
        try:
            from _core import _ensure_render_deps
        except ImportError:
            try:
                import sys, os
                sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
                from _core import _ensure_render_deps
            except Exception:
                _ensure_render_deps = lambda: False  # type: ignore
        if _ensure_render_deps():
            try:
                from playwright.sync_api import sync_playwright
                _pw_mgr = sync_playwright().__enter__()
                launch_opts: Dict[str, Any] = {"headless": True}
                if proxies:
                    proxy_url = proxies.get("https") or proxies.get("http")
                    if proxy_url:
                        launch_opts["proxy"] = {"server": proxy_url}
                _browser = _pw_mgr.chromium.launch(**launch_opts)
                ctx_opts: Dict[str, Any] = {"ignore_https_errors": True}
                if auth_headers:
                    ctx_opts["extra_http_headers"] = auth_headers
                render_ctx = _browser.new_context(**ctx_opts)
                # 쿠키 주입 — 도메인은 호스트명만 사용(포트 제외)
                if cookies:
                    domain = base_netloc.split(":")[0]
                    render_ctx.add_cookies([
                        {"name": k, "value": v, "domain": domain, "path": "/"}
                        for k, v in cookies.items()
                    ])
            except Exception:
                # 브라우저 기동 실패 → 정적 크롤로 폴백
                render_ctx = None
                if _browser:
                    try:
                        _browser.close()
                    except Exception:
                        pass
                if _pw_mgr:
                    try:
                        _pw_mgr.stop()
                    except Exception:
                        pass
                _browser = _pw_mgr = None

    queue: deque = deque([base_url])
    pages: List[Dict[str, Any]] = []

    try:
        # robots.txt / sitemap.xml 시드 수집 → 큐 선투입
        # try 블록 안에서 실행해야, 시드 수집 중 [중단](ScanCancelled)이 발생해도
        # 아래 finally의 Playwright 리소스 정리가 보장된다.
        extra_seeds = _seed_from_robots_sitemap(
            base_netloc, scheme, timeout, cookies, proxies, auth_headers,
            delay, stop_event
        )
        queue.extend(extra_seeds)

        while queue and len(visited) < max_pages:
            # [중단] 검사 — 매 페이지 진입 시 즉시 탈출 (render/static 양 경로 공통)
            wait_or_cancel(stop_event, 0)
            url, _ = urldefrag(queue.popleft())   # 프래그먼트(#...) 제거
            if url in visited:
                continue

            # C9: 서명(path + 파라미터명 집합) 기준 방문 상한 3회
            # 단, 파라미터명이 페이지네이션 성격(_PAGINATION_PARAMS)이면 상한을 적용하지 않는다.
            # (예: ?page=1..N 뒤에만 등장하는 링크도 max_pages 한도 내에서 발견 가능해야 함.
            #  전체 방문 수는 while 조건의 max_pages로 계속 상한된다.)
            _p = urlparse(url)
            _param_names = frozenset(parse_qs(_p.query).keys())
            sig: Tuple[str, frozenset] = (_p.path, _param_names)
            is_pagination_sig = bool({n.lower() for n in _param_names} & _PAGINATION_PARAMS)
            if not is_pagination_sig and sig_count.get(sig, 0) >= 3:
                visited.add(url)  # 재평가·재적재 방지
                continue

            visited.add(url)
            sig_count[sig] = sig_count.get(sig, 0) + 1

            # 진행률 콜백 — 방문 시점마다 호출 (요청 성공·실패 무관)
            if progress_cb:
                progress_cb(len(visited), max_pages)

            # ── 렌더 경로 (render=True + 브라우저 기동 성공) ────────────────────
            resp = None
            if render_ctx:
                resp = _render_fetch(render_ctx, url, delay,
                                     xhr_points, xhr_visited, base_netloc,
                                     stop_event=stop_event)

            # ── 정적 경로 (render=False 또는 렌더 실패 폴백) ─────────────────────
            # C12: 타임아웃·일시적 네트워크 오류에 한해 최대 2회 재시도 (0.5s→1.0s 백오프)
            # ConnectionError(연결거부·DNS 실패)·SSLError 등 영구성 오류는 즉시 중단
            if resp is None:
                for attempt in range(3):
                    try:
                        if attempt > 0:
                            wait_or_cancel(stop_event, 0.5 * attempt)
                        # C-R: 렌더 경로는 이제 요청 단위(라우트 훅)로 delay를 소비하며,
                        # goto 자체가 요청 하나 못 띄우고 실패하는 경우(브라우저 크래시 등)
                        # delay 소비가 0일 수 있으므로, 정적 폴백은 항상 delay를 적용한다
                        # (렌더 소요 delay와 다소 겹치더라도 버스트보다 안전한 쪽을 택함).
                        wait_or_cancel(stop_event, delay)
                        # 요청 자체는 데몬 워커에서 실행 — 응답 대기 중에도 [중단]이 즉시 반응한다.
                        resp = run_cancellable(
                            lambda: requests.get(url, timeout=timeout, verify=False,
                                                 allow_redirects=True, cookies=cookies,
                                                 proxies=proxies, headers=auth_headers or {}),
                            stop_event,
                        )
                        break  # 성공
                    except (requests.exceptions.Timeout,
                            requests.exceptions.ChunkedEncodingError):
                        continue  # 재시도 대상 — 타임아웃·청크 전송 오류
                    except Exception:
                        break     # 영구성 오류 — 즉시 중단

            if resp is None:
                continue

            # 리다이렉트 후 도메인 확인 — 다르면 이 페이지는 수집하지 않음
            final_url = resp.url
            if not _same_site(urlparse(final_url).netloc, base_netloc):
                continue

            path = urlparse(final_url).path or "/"
            kind = _classify_response(resp, final_url)
            # html / script / json 종류는 본문 보관 (other는 경로만 기록)
            body = resp.text if kind in ("html", "script", "json") else None

            pages.append({"url": final_url, "path": path,
                          "body": body, "kind": kind,
                          "visited_at": datetime.now().isoformat(timespec='milliseconds')})

            # HTML·스크립트·JSON 본문에서 링크 추출해 큐에 추가
            if body:
                for link in _extract_links_from_body(body, final_url, base_netloc, kind,
                                                     debug_sink=debug_sink):
                    if link not in visited:
                        queue.append(link)

    finally:
        # Playwright 리소스 정리 (render=False이면 모두 None → 무해)
        if render_ctx:
            try:
                render_ctx.close()
            except Exception:
                pass
        if _browser:
            try:
                _browser.close()
            except Exception:
                pass
        if _pw_mgr:
            try:
                _pw_mgr.stop()
            except Exception:
                pass

    # 네트워크 인터셉션으로 수집된 입력 포인트를 합성 엔트리로 추가
    # sql_injection / path_traversal 이 page["points"]를 직접 사용한다.
    if xhr_points:
        pages.append({
            "url": base_url,
            "path": urlparse(base_url).path or "/",
            "body": None,
            "kind": "xhr",
            "visited_at": datetime.now().isoformat(timespec='milliseconds'),
            "points": xhr_points,
        })

    return pages
