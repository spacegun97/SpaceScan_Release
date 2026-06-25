"""
SQL Injection 취약점 스캐너
Error-based + Boolean-based 두 가지 기법으로 GET/POST 입력 포인트를 스캔한다.
OWASP Top 10 A03:2021 — Injection
"""
import re
import time
import requests
from datetime import datetime
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, List, Set, Tuple, Optional, Callable

from . import _crawl
from ._sqli_util import (
    WAF_KEYWORDS, DBMS_ERROR_VECTORS, DB_ERROR_SIGNATURES,
    parse_input_points, similarity, gen_marker, build_dynamic_contexts,
    apply_dynamic_mask,
)


# ── 페이로드 정의 ────────────────────────────────────────────────────────────

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "1' ORDER BY 1--",
    "1' ORDER BY 1#",
    "1' ORDER BY 1/**/",
    "1 AND 1=CONVERT(int,@@version)--",
    # 괄호·큰따옴표 컨텍스트 커버 (WHERE (id=$p), LIKE '%$p%', etc.)
    "')-- ",         # 괄호 + 작은따옴표 종결
    '")-- ',         # 괄호 + 큰따옴표 종결
    ")-- ",          # 괄호 종결 (숫자 컨텍스트)
    "'))-- ",        # 2중 괄호
]

BOOLEAN_PAIRS = [
    ("' AND '1'='1' -- ", "' AND '1'='2' -- "),   # 문자열 컨텍스트 (-- 주석)
    ("' AND '1'='1'#",    "' AND '1'='2'#"),        # 문자열 컨텍스트 (# 주석)
    ("  AND 1=1 -- ",     "  AND 1=2 -- "),          # 숫자 컨텍스트
    # 괄호 컨텍스트 (WHERE (id=$p) 등)
    (") AND (1=1) -- ",       ") AND (1=2) -- "),
    ("') AND ('1'='1') -- ",  "') AND ('1'='2') -- "),
]

# Inline Query 페이로드 — value 전체를 치환하며 __MARKER__ 가 응답 본문에 반사되면 확정
INLINE_VECTORS: List[str] = [
    "(SELECT '__MARKER__')",
    "(SELECT '__MARKER__' FROM dual)",
]


# ── 메인 스캔 함수 ────────────────────────────────────────────────────────────

def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         max_pages: int = 1000, cookies: Optional[Dict[str, str]] = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: Optional[Dict[str, str]] = None,
         auth_headers: Optional[Dict[str, str]] = None,
         render: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "module":       "SQL Injection",
        "target":       target_url,
        "findings":     [],
        "debug_events": [],
    }
    debug_events: List[Tuple[str, str, str]] = result["debug_events"]
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "sql_injection", "스캔 시작"))

    base = target_url.rstrip("/")
    base_netloc = urlparse(target_url).netloc

    # Phase 1: BFS 크롤링 (진행률 0~40% 구간에 매핑)
    crawl_cb = None
    if progress_cb:
        def crawl_cb(cur, total):
            progress_cb(int(cur / total * 40) if total else 0, 100)
    pages = _crawl.crawl(base, base_netloc, timeout, delay, max_pages, cookies,
                         progress_cb=crawl_cb, proxies=proxies,
                         auth_headers=auth_headers, render=render)
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "sql_injection", f"BFS 크롤링 완료: {len(pages)}개 페이지"))

    # Phase 2: 크롤링 결과에서 입력 포인트 수집 (빠른 작업, 40% 지점 고정)
    seen_points: Set[Tuple] = set()
    input_points: List[Dict[str, Any]] = []

    for page in pages:
        # kind="xhr": 네트워크 인터셉션 포인트를 직접 사용 (body 파싱 불필요)
        if page.get("kind") == "xhr":
            for pt in page.get("points", []):
                key = (pt["url"], pt["method"], frozenset(pt["params"].keys()))
                if key not in seen_points:
                    seen_points.add(key)
                    input_points.append(pt)
            continue

        # body가 있으면 kind에 따라 입력 포인트 파싱, 없으면 path 주입 포인트만 수집
        if page.get("body"):
            points = parse_input_points(
                page["url"], page["body"], base_netloc, kind=page.get("kind", "html")
            )
        else:
            points = []
        # URI path 숫자 세그먼트 주입 포인트 수집 (body 유무 무관)
        points.extend(_parse_path_points(page["url"]))

        for pt in points:
            # (url, method, 파라미터명 집합) 기준으로 중복 제거
            key = (pt["url"], pt["method"], frozenset(pt["params"].keys()))
            if key not in seen_points:
                seen_points.add(key)
                input_points.append(pt)

    # Phase 2.5: 공격 시작 전 외부 도메인 최종 필터링
    # 수집 단계의 netloc 검증이 누락·실수로 뚫리더라도 이 단계에서 외부 URL을 모두 제거한다.
    # 각 수집 단계(form/href/data-*) 검증 + 이 최종 필터 + _request() 사전 검증 = 3중 방어.
    input_points = [pt for pt in input_points
                    if urlparse(pt["url"]).netloc == base_netloc]
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "sql_injection", f"입력 포인트 수집: {len(input_points)}개"))

    if progress_cb:
        progress_cb(40, 100)

    # Phase 3: 입력 포인트별 스캔 (진행률 40~100% 구간)
    all_findings: List[Dict[str, Any]] = []
    session = requests.Session()
    session.verify = False
    # 프록시 설정 (BurpSuite 등 — None이면 무효)
    if proxies:
        session.proxies.update(proxies)
    # 쿠키가 전달된 경우 세션에 적용
    if cookies:
        session.cookies.update(cookies)
    # 인증 헤더 적용 (Authorization, X-API-Key 등)
    if auth_headers:
        session.headers.update(auth_headers)

    try:
        total_points = len(input_points)
        for idx, point in enumerate(input_points):
            # Error-based 스캔 (Generic → DBMS-specific 2단계)
            error_findings, vulnerable_params = _scan_error_based(
                point, timeout, delay, session, base_netloc
            )
            all_findings.extend(error_findings)

            # Boolean-based 스캔 (Error-based에서 취약 확인된 파라미터는 제외, Dynamic Masking 적용)
            bool_findings = _scan_boolean_based(
                point, timeout, delay, session, vulnerable_params, base_netloc
            )
            all_findings.extend(bool_findings)

            # Inline Query 스캔 (반사 기반 탐지 — 이전 기법에서 확인된 파라미터는 제외)
            inline_findings = _scan_inline_query(
                point, timeout, delay, session, vulnerable_params, base_netloc
            )
            all_findings.extend(inline_findings)

            if progress_cb and total_points > 0:
                progress_cb(40 + int((idx + 1) / total_points * 60), 100)
    finally:
        session.close()

    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "sql_injection", f"스캔 완료: {len(all_findings)}개 취약점"))
    result["findings"]     = all_findings
    result["crawl_events"] = [(p["visited_at"], p["url"]) for p in pages]
    return result


# ── Error-based 스캔 ──────────────────────────────────────────────────────────

def _scan_error_based(point: Dict, timeout: int, delay: float,
                      session: requests.Session,
                      base_netloc: str) -> Tuple[List[Dict], Set[str]]:
    """입력 포인트에 대해 Error-based SQLi 탐지를 수행한다.

    2단계 구성:
      Phase 1 (Generic): ERROR_PAYLOADS로 에러 시그니처 매칭 → DBMS 1차 식별
      Phase 2 (DBMS-specific): 식별된 DBMS의 DBMS_ERROR_VECTORS를 추가 주입하여
                               마커 반사 또는 강한 시그니처 재확인

    주입은 _inject_and_request()를 통해 param_types(path/일반) 및 body_type(form/json/xml)에
    맞게 분기 처리된다.
    반환: (findings 리스트, 취약 확인된 파라미터명 집합)
    """
    findings: List[Dict] = []
    vulnerable_params: Set[str] = set()
    params = point["params"]
    url = point["url"]
    method = point["method"]

    # WAF 사전 체크: hidden이 아닌 가시 필드를 우선 사용 — CSRF 검증 실패로 인한 오판 방지
    param_types = point.get("param_types", {})
    visible = [p for p in params if param_types.get(p) != "hidden"]
    first_param = visible[0] if visible else next(iter(params))

    try:
        time.sleep(delay)
        resp = _inject_and_request(session, point, first_param, "'",
                                   timeout, base_netloc)
    except Exception:
        return findings, vulnerable_params

    # WAF 차단 감지 시 입력 포인트 전체 스킵
    if _is_waf_blocked(resp):
        return findings, vulnerable_params

    # 첫 번째 페이로드(')의 응답도 시그니처 매칭에 사용 (추가 요청 없음)
    dbms, evidence = _match_error_signature(resp.text)
    if dbms:
        # resp.url: 리다이렉트 후 최종 URL (GET이면 payload 포함된 full URL)
        findings.append(_make_error_finding(url, method, first_param, "'", dbms, evidence, resp.url))
        vulnerable_params.add(first_param)

    # ── Phase 1: Generic 페이로드 순회 ──
    for param in params:
        if param in vulnerable_params:
            continue

        # 첫 번째 파라미터는 ' 페이로드를 이미 테스트했으므로 인덱스 1부터 시작
        start_idx = 1 if param == first_param else 0

        for payload in ERROR_PAYLOADS[start_idx:]:
            try:
                time.sleep(delay)
                resp = _inject_and_request(session, point, param, payload,
                                           timeout, base_netloc)
            except Exception:
                continue

            dbms, evidence = _match_error_signature(resp.text)
            if dbms:
                findings.append(_make_error_finding(url, method, param, payload, dbms, evidence, resp.url))
                vulnerable_params.add(param)
                break  # 해당 파라미터 추가 페이로드 테스트 스킵

    # ── Phase 2: DBMS-specific 페이로드 ──
    # Phase 1에서 식별된 첫 DBMS를 기준으로 해당 DBMS 전용 Error 벡터만 추가 시도
    identified_dbms = next((f["dbms"] for f in findings if f.get("dbms")), None)
    if identified_dbms and identified_dbms in DBMS_ERROR_VECTORS:
        dbms_vectors = DBMS_ERROR_VECTORS[identified_dbms]
        for param in params:
            if param in vulnerable_params:
                continue
            for vector_template in dbms_vectors:
                # 랜덤 마커로 __MARKER__ 치환 → 응답 반사 시 데이터 유출 확증
                marker = gen_marker()
                payload = vector_template.replace("__MARKER__", marker)
                try:
                    time.sleep(delay)
                    resp = _inject_and_request(session, point, param, payload,
                                               timeout, base_netloc)
                except Exception:
                    continue

                # 마커가 응답 본문에 반사되었다면 데이터 유출 가능성 확정 (가장 강한 증거)
                if marker in resp.text:
                    evidence = f"DBMS={identified_dbms}, marker '{marker}' 응답 반사 (데이터 유출 가능)"
                    findings.append(_make_error_finding(url, method, param, payload,
                                                       identified_dbms, evidence, resp.url))
                    vulnerable_params.add(param)
                    break

                # 마커 반사가 없어도 에러 시그니처로 확인
                dbms_sig, sig_evidence = _match_error_signature(resp.text)
                if dbms_sig:
                    findings.append(_make_error_finding(url, method, param, payload,
                                                       dbms_sig, sig_evidence, resp.url))
                    vulnerable_params.add(param)
                    break

    return findings, vulnerable_params


# ── Boolean-based 스캔 ────────────────────────────────────────────────────────

def _scan_boolean_based(point: Dict, timeout: int, delay: float,
                        session: requests.Session,
                        vulnerable_params: Set[str],
                        base_netloc: str) -> List[Dict]:
    """입력 포인트에 대해 Boolean-based SQLi 탐지를 수행한다.

    Dynamic Content Marking 적용:
      2개 baseline 응답의 diff에서 동적 콘텐츠(세션 ID/타임스탬프/nonce 등)의
      양옆 context를 추출하여, 이후 모든 응답 비교 전에 해당 구간을 마스킹한다.
      → 동적 페이지에서도 Boolean 판정이 가능해져 오탐 감소.

    Error-based에서 이미 취약 확인된 파라미터는 건너뛴다.
    주입은 _inject_and_request()를 통해 param_types/body_type에 맞게 분기 처리된다.
    """
    findings: List[Dict] = []
    params = point["params"]
    url = point["url"]
    method = point["method"]

    # Boolean-based 대상 파라미터가 없으면 조기 종료
    target_param_names = [k for k in params if k not in vulnerable_params]
    if not target_param_names:
        return findings

    # Step 1: 원본 요청 2회 → 동적 콘텐츠 context 추출 + 자연 변동폭 측정
    try:
        time.sleep(delay)
        resp1 = _baseline_request(session, point, timeout, base_netloc)
        time.sleep(delay)
        resp2 = _baseline_request(session, point, timeout, base_netloc)
    except Exception:
        return findings

    # 두 baseline의 diff에서 동적 구간 주변 (prefix, suffix) 컨텍스트 수집
    dynamic_contexts = build_dynamic_contexts(resp1.text, resp2.text)

    # 마스킹 후 두 baseline 유사도 측정 (동적 콘텐츠 제거된 상태)
    baseline_masked = apply_dynamic_mask(resp1.text, dynamic_contexts)
    resp2_masked    = apply_dynamic_mask(resp2.text, dynamic_contexts)
    natural_ratio   = similarity(baseline_masked, resp2_masked)

    # 마스킹 후에도 변동폭이 과도하면 스킵 (기존 0.85 → 0.7 완화: 마스킹이 흡수한 만큼 관용)
    if natural_ratio < 0.7:
        return findings

    # Step 2: 각 파라미터에 Boolean pair 주입 → 마스킹된 응답 간 유사도 비교
    for param in target_param_names:
        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                time.sleep(delay)
                true_resp = _inject_and_request(session, point, param, true_payload,
                                                timeout, base_netloc)
                time.sleep(delay)
                false_resp = _inject_and_request(session, point, param, false_payload,
                                                 timeout, base_netloc)
            except Exception:
                continue

            # Boolean 응답에서 WAF 차단 감지 시 해당 파라미터 스킵
            if _is_waf_blocked(true_resp) or _is_waf_blocked(false_resp):
                break

            # 동일 dynamic_contexts로 공격 응답도 마스킹하여 비교 (baseline과 동일 기준)
            true_masked  = apply_dynamic_mask(true_resp.text,  dynamic_contexts)
            false_masked = apply_dynamic_mask(false_resp.text, dynamic_contexts)

            sim_true  = similarity(baseline_masked, true_masked)
            sim_false = similarity(baseline_masked, false_masked)
            sim_tf    = similarity(true_masked,     false_masked)

            # 판정: true가 baseline과 유사 AND false가 baseline과 다름 AND 두 응답이 서로 다름
            if (sim_true  > natural_ratio - 0.05
                    and sim_false < natural_ratio - 0.15
                    and sim_tf    < natural_ratio - 0.1):

                evidence = (
                    f"true_sim={sim_true:.2f}, false_sim={sim_false:.2f}, "
                    f"natural={natural_ratio:.2f}, masked_contexts={len(dynamic_contexts)}"
                )
                # Boolean-based는 true 응답의 최종 URL을 기록
                findings.append(
                    _make_boolean_finding(url, method, param, true_payload, evidence, true_resp.url)
                )
                vulnerable_params.add(param)
                break  # 이 파라미터 추가 페이로드 스킵

    return findings


# ── 공통 헬퍼 ─────────────────────────────────────────────────────────────────

def _request(session: requests.Session, method: str, url: str,
             params: Dict[str, str], timeout: int,
             base_netloc: str,
             body_type: str = "form") -> requests.Response:
    """method에 따라 GET 또는 POST 요청을 전송한다.

    base_netloc이 지정된 경우 요청 전·후 2중 검증으로 외부 도메인 유출을 차단한다.
    - 사전 검증: 요청 URL의 netloc이 base_netloc과 다르면 요청 자체를 차단
    - 사후 검증: 리다이렉트 후 외부 도메인으로 이탈한 경우 차단
    호출부는 Exception을 catch하므로 해당 요청 결과는 조용히 스킵된다.

    body_type (POST 시에만 의미):
    - "form" (기본): application/x-www-form-urlencoded
    - "json": application/json — requests의 json kwarg가 자동 직렬화 + 헤더 설정
    - "xml":  application/xml — params를 평면 XML 트리로 조립 후 전송
    """
    # 사전 검증 — 외부 도메인으로 payload 전송 차단 (최종 방어선)
    if base_netloc and urlparse(url).netloc != base_netloc:
        raise ValueError(f"request to external domain blocked: {urlparse(url).netloc}")

    if method == "POST":
        if body_type == "json":
            resp = session.post(url, json=params, timeout=timeout, allow_redirects=True)
        elif body_type == "xml":
            body = _dict_to_xml(params)
            headers = {"Content-Type": "application/xml"}
            resp = session.post(url, data=body, headers=headers,
                                timeout=timeout, allow_redirects=True)
        else:
            resp = session.post(url, data=params, timeout=timeout, allow_redirects=True)
    else:
        resp = session.get(url, params=params, timeout=timeout, allow_redirects=True)
    # 사후 검증 — 리다이렉트로 외부 도메인으로 이탈 시 세션 쿠키 유출 방지
    if base_netloc and urlparse(resp.url).netloc != base_netloc:
        raise ValueError(f"redirect to external domain: {urlparse(resp.url).netloc}")
    return resp


def _is_waf_blocked(resp: requests.Response) -> bool:
    """응답이 WAF 차단 패턴과 일치하는지 확인한다.

    403 단독으로는 WAF로 판정하지 않음 — CSRF 검증 실패(403)와 구별하기 위해
    응답 바디에 WAF 차단 키워드가 있는 경우만 WAF로 판정한다.
    """
    body_lower = resp.text.lower()
    return any(kw in body_lower for kw in WAF_KEYWORDS)


def _match_error_signature(body: str) -> Tuple[Optional[str], Optional[str]]:
    """응답 바디에서 DB 에러 시그니처를 탐색한다.

    반환: (DBMS명, 매칭된 에러 문자열) 또는 (None, None)
    """
    for dbms, patterns in DB_ERROR_SIGNATURES.items():
        for pattern in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                return dbms, m.group(0)[:200]
    return None, None


def _make_error_finding(url: str, method: str, param: str, payload: str,
                        dbms: str, evidence: str,
                        response_url: str) -> Dict[str, Any]:
    """Error-based finding dict를 생성한다."""
    return {
        "severity":     "HIGH",
        "url":          url,
        "method":       method,
        "param":        param,
        "type":         "error_based",
        "dbms":         dbms,
        "payload":      payload,
        "description":  f"[Error-based / {dbms}] '{param}' 파라미터에서 SQL 인젝션 가능성 탐지",
        "evidence":     evidence,
        "response_url": response_url,
    }


def _make_boolean_finding(url: str, method: str, param: str, payload: str,
                          evidence: str,
                          response_url: str) -> Dict[str, Any]:
    """Boolean-based finding dict를 생성한다."""
    return {
        "severity":     "HIGH",
        "url":          url,
        "method":       method,
        "param":        param,
        "type":         "boolean_based",
        "dbms":         None,
        "payload":      payload,
        "description":  f"[Boolean-based] '{param}' 파라미터에서 SQL 인젝션 가능성 탐지",
        "evidence":     evidence,
        "response_url": response_url,
    }


# ── URI path 파라미터 ─────────────────────────────────────────────────────────

def _parse_path_points(url: str) -> List[Dict[str, Any]]:
    """URL path에서 순수 숫자 세그먼트를 주입 포인트로 추출한다.

    예: /view/1/detail → 인덱스 2 세그먼트('1')가 주입 대상.
    UUID/slug는 오탐 방지를 위해 제외하고 `^\\d+$` 매칭 세그먼트만 등록한다.
    파라미터명은 내부 식별자 '__path_<idx>' 형식.
    """
    points: List[Dict[str, Any]] = []
    parsed = urlparse(url)
    segments = parsed.path.split("/")

    for idx, seg in enumerate(segments):
        if seg and seg.isdigit():
            param_name = f"__path_{idx}"
            points.append({
                "url":         url,
                "method":      "GET",
                "params":      {param_name: seg},
                "param_types": {param_name: "path"},
                "body_type":   "form",
            })
    return points


def _build_path_url(url: str, param_name: str, value: str) -> str:
    """URL path에서 '__path_<idx>' 위치의 세그먼트를 value로 치환해 재조립한다.

    payload의 '/'와 공백은 세그먼트 경계 훼손을 막기 위해 %2F·%20으로 인코딩한다.
    SQL 특수문자(', ", ;)는 원본 유지 — SQL 구문 보존 목적.
    """
    if not param_name.startswith("__path_"):
        return url
    try:
        idx = int(param_name[len("__path_"):])
    except ValueError:
        return url

    parsed = urlparse(url)
    segments = parsed.path.split("/")
    if idx >= len(segments):
        return url

    encoded_value = value.replace("/", "%2F").replace(" ", "%20")
    segments[idx] = encoded_value

    new_path = "/".join(segments)
    return urlunparse((
        parsed.scheme, parsed.netloc, new_path,
        parsed.params, parsed.query, parsed.fragment,
    ))


# ── XML body 조립 ────────────────────────────────────────────────────────────

def _dict_to_xml(params: Dict[str, str]) -> str:
    """params dict를 평면 XML 트리로 조립한다.

    결과 형식: <root><key1>value1</key1><key2>value2</key2>...</root>
    payload 내 '<', '>', '&'는 SQL 구문 유지를 위해 이스케이프하지 않는다
    (XML 파서가 이를 만나 에러를 뱉을 수 있으며 이는 Error-based 탐지에 유리).
    """
    parts = ["<root>"]
    for k, v in params.items():
        parts.append(f"<{k}>{v}</{k}>")
    parts.append("</root>")
    return "".join(parts)


# ── 주입 실행 진입점 ─────────────────────────────────────────────────────────

def _baseline_request(session: requests.Session, point: Dict[str, Any],
                      timeout: int,
                      base_netloc: str) -> requests.Response:
    """point의 원본(페이로드 없음) 요청을 전송한다.

    path injection point는 URL 그대로 사용하고 params는 생략한다.
    그 외는 body_type(form/json/xml)에 따라 원본 값으로 요청.
    """
    url = point["url"]
    method = point["method"]
    body_type = point.get("body_type", "form")
    param_types = point.get("param_types", {})

    if any(t == "path" for t in param_types.values()):
        return _request(session, method, url, {}, timeout, base_netloc, body_type)
    return _request(session, method, url, point["params"],
                    timeout, base_netloc, body_type)


def _inject_and_request(session: requests.Session, point: Dict[str, Any],
                        param: str, payload: str,
                        timeout: int,
                        base_netloc: str,
                        where: str = "append") -> requests.Response:
    """point의 특정 param에 payload를 주입하여 요청을 전송한다.

    where 모드:
    - "append" (기본): test_value = original_value + payload  (Error/Boolean-based)
    - "replace":        test_value = payload                    (Inline Query 등, value 전체 치환)

    param_types에 따라 주입 경로를 분기한다:
    - "path": URL의 해당 path 세그먼트를 payload로 치환하여 GET 전송 (쿼리 생략)
    - 그 외:  params 복사본에 payload 주입 후 body_type(form/json/xml)으로 전송
    """
    url = point["url"]
    method = point["method"]
    body_type = point.get("body_type", "form")
    param_types = point.get("param_types", {})

    original_value = point["params"][param]
    if where == "replace":
        test_value = payload
    else:
        test_value = original_value + payload

    if param_types.get(param) == "path":
        # URL path 세그먼트 치환 — 쿼리 파라미터는 보내지 않음
        test_url = _build_path_url(url, param, test_value)
        return _request(session, method, test_url, {}, timeout, base_netloc, body_type)

    # 일반 form / json / xml — 해당 param 값만 치환
    test_params = dict(point["params"])
    test_params[param] = test_value
    return _request(session, method, url, test_params, timeout, base_netloc, body_type)


# ── Inline Query 스캔 ────────────────────────────────────────────────────────

def _scan_inline_query(point: Dict, timeout: int, delay: float,
                       session: requests.Session,
                       vulnerable_params: Set[str],
                       base_netloc: str) -> List[Dict]:
    """Inline Query 탐지 — 서브쿼리 결과가 응답 본문에 반사되는지 확인한다.

    __MARKER__를 포함한 페이로드를 value 전체에 치환 주입하고(where="replace"),
    응답 본문에 마커가 그대로 나타나면 HIGH finding 생성.

    Error/Boolean에서 이미 취약 확인된 파라미터는 건너뛴다 (중복 finding 방지).
    """
    findings: List[Dict] = []
    params = point["params"]
    url = point["url"]
    method = point["method"]

    for param in params:
        if param in vulnerable_params:
            continue

        for vector in INLINE_VECTORS:
            marker = gen_marker()
            payload = vector.replace("__MARKER__", marker)
            try:
                time.sleep(delay)
                resp = _inject_and_request(
                    session, point, param, payload,
                    timeout, base_netloc, where="replace",
                )
            except Exception:
                continue

            # WAF 차단 감지 시 해당 파라미터 추가 벡터 스킵
            if _is_waf_blocked(resp):
                break

            # 응답 본문에 마커가 그대로 반사되었는지 확인
            if marker in resp.text:
                findings.append(
                    _make_inline_finding(url, method, param, payload, marker, resp.url)
                )
                vulnerable_params.add(param)
                break  # 이 파라미터 추가 벡터 스킵

    return findings


def _make_inline_finding(url: str, method: str, param: str, payload: str,
                         marker: str,
                         response_url: str) -> Dict[str, Any]:
    """Inline Query finding dict를 생성한다."""
    return {
        "severity":     "HIGH",
        "url":          url,
        "method":       method,
        "param":        param,
        "type":         "inline_query",
        "dbms":         None,
        "payload":      payload,
        "description":  f"[Inline Query] '{param}' 파라미터에서 SQL 인젝션 가능성 탐지 (서브쿼리 결과 반사 확인)",
        "evidence":     f"마커 '{marker}' 응답 본문 반사 확인",
        "response_url": response_url,
    }
