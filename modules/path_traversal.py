"""
Path Traversal 탐지 스캐너 (패시브)
크롤링된 파라미터 값과 URL path에서 경로 패턴을 탐지한다.
OWASP Top 10 A01:2021 — Broken Access Control
"""
import re
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Set, Tuple, Optional, Callable

from . import _crawl
from ._sqli_util import parse_input_points


# ── 탐지 패턴 정의 ───────────────────────────────────────────────────────────

# (카테고리, 정규식, 수동 테스트 힌트) — 우선순위 높은 순서로 정의
TRAVERSAL_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    # ── 기존 패턴 (구체·위험도 높은 것 우선) ──────────────────────────────────
    (
        "traversal",
        re.compile(r'\.\.[\\/]|%2e%2e[/\\%]|%252e%252e|\.\.;/|\.\.%00', re.IGNORECASE),
        "LFI / Path Traversal",
    ),
    (
        "wrapper_scheme",
        re.compile(r'(?:file|php|data|expect|phar|zip|gopher|dict|ldap)://', re.IGNORECASE),
        "SSRF / LFI / Protocol Wrapper",
    ),
    (
        "windows_abs",
        re.compile(r'\b[A-Za-z]:[\\/]'),
        "LFI / 파일 다운로드",
    ),
    (
        "unc_path",
        re.compile(r'\\{2}[^\\]+\\'),
        "SSRF / UNC Path 접근",
    ),
    (
        "unix_system",
        re.compile(r'/(etc|var|usr|home|root|proc|sys|boot|tmp|dev)/', re.IGNORECASE),
        "LFI / 시스템 파일 접근",
    ),
    # ── 신규 패턴 — 파라미터 값 전용 (광범위, FP 감수·미탐 최소화) ──────────
    # http(s):// 스킴 포함 URL — SSRF / 오픈리다이렉트 단서
    (
        "ssrf_url",
        re.compile(r'https?://', re.IGNORECASE),
        "SSRF / 오픈리다이렉트",
    ),
    # IPv4 (옥텟 검증 없음) 또는 IPv6 — 스킴 없는 내부망 참조 포함
    (
        "ip_addr",
        re.compile(
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'             # IPv4
            r'|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}',  # IPv6 (콜론 그룹 2개 이상)
            re.IGNORECASE,
        ),
        "SSRF / 내부망 접근",
    ),
    # 슬래시·백슬래시 포함 경로 값 — /normal/page, dir\file 등 경로 구조 탐지
    (
        "path_value",
        re.compile(r'[/\\]'),
        "파일 경로 / LFI",
    ),
    # 확장자가 있는 단독 파일명 — config.xml, test.jsp, 슬래시 없어도 탐지
    (
        "filename",
        re.compile(r'[\w-]+\.[A-Za-z0-9]{1,6}'),
        "파일 접근 / LFI",
    ),
]

# 카테고리 → 한국어 표시명
PATTERN_LABELS: Dict[str, str] = {
    "traversal":      "디렉터리 트래버설",
    "wrapper_scheme": "프로토콜 래퍼",
    "windows_abs":    "Windows 절대 경로",
    "unc_path":       "UNC 경로",
    "unix_system":    "Unix 시스템 경로",
    "ssrf_url":       "SSRF / 오픈리다이렉트",
    "ip_addr":        "IP 주소 직접 참조",
    "path_value":     "경로 값",
    "filename":       "파일명 직접 참조",
}

# URL path 검사 대상 카테고리 (파라미터와 달리 traversal·wrapper만 — 오탐 최소화)
_PATH_CATS: Set[str] = {"traversal", "wrapper_scheme"}


# ── 메인 스캔 함수 ────────────────────────────────────────────────────────────

def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         max_pages: int = 100, cookies: Optional[Dict[str, str]] = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: Optional[Dict[str, str]] = None,
         auth_headers: Optional[Dict[str, str]] = None,
         render: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "module":       "Path Traversal",
        "target":       target_url,
        "findings":     [],
        "debug_events": [],
    }
    debug_events: List[Tuple[str, str, str]] = result["debug_events"]
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "path_traversal", "스캔 시작"))

    base = target_url.rstrip("/")
    base_netloc = urlparse(target_url).netloc

    # Phase 1: BFS 크롤링 (진행률 0~90%)
    crawl_cb = None
    if progress_cb:
        def crawl_cb(cur, total):
            progress_cb(int(cur / total * 90) if total else 0, 100)
    pages = _crawl.crawl(base, base_netloc, timeout, delay, max_pages,
                         cookies, progress_cb=crawl_cb, proxies=proxies,
                         auth_headers=auth_headers, render=render)
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "path_traversal", f"BFS 크롤링 완료: {len(pages)}개 페이지"))

    if progress_cb:
        progress_cb(90, 100)

    # Phase 2: 경로 패턴 매칭 (진행률 90~100%, 로컬 연산)
    # (url, method, param) 기준 중복 방지 — 동일 포인트에 여러 패턴 매칭 시 하나의 finding만 생성
    seen: Set[Tuple[str, str, str]] = set()
    findings: List[Dict[str, Any]] = []

    for page in pages:
        # kind="xhr": 네트워크 인터셉션 포인트를 직접 검사 (body 파싱 불필요)
        if page.get("kind") == "xhr":
            for point in page.get("points", []):
                for param, value in point["params"].items():
                    _check_and_add(point["url"], point["method"], param, value,
                                   seen, findings)
            continue

        # (A) 파라미터 값 검사 — body가 있으면 kind에 따라 파싱 (html/script/json 모두)
        if page.get("body"):
            for point in parse_input_points(
                page["url"], page["body"], base_netloc, kind=page.get("kind", "html")
            ):
                for param, value in point["params"].items():
                    _check_and_add(point["url"], point["method"], param, value,
                                   seen, findings)

        # (B) URL path 직접 검사 — traversal / wrapper_scheme 패턴에 한해 탐지
        path = urlparse(page["url"]).path
        if path:
            _check_path(page["url"], path, seen, findings)

    if progress_cb:
        progress_cb(100, 100)

    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "path_traversal", f"스캔 완료: {len(findings)}개 취약점"))
    result["findings"]     = findings
    result["crawl_events"] = [(p["visited_at"], p["url"]) for p in pages]
    return result


# ── 패턴 매칭 헬퍼 ──────────────────────────────────────────────────────────

def _check_and_add(url: str, method: str, param: str, value: str,
                   seen: Set[Tuple], findings: List[Dict[str, Any]]) -> None:
    """파라미터 값에서 경로 패턴을 탐지하고 finding을 추가한다.

    (url, method, param) 기준으로 중복을 제거한다.
    여러 패턴이 동시에 매칭되면 우선순위 1위를 primary로 쓰고 나머지는 evidence에 표시한다.
    """
    if not value:
        return
    key = (url, method, param)
    if key in seen:
        return

    matched: List[Tuple[str, str]] = [
        (cat, hint)
        for cat, pattern, hint in TRAVERSAL_PATTERNS
        if pattern.search(value)
    ]
    if not matched:
        return

    seen.add(key)
    primary_cat, primary_hint = matched[0]
    all_labels = [PATTERN_LABELS.get(c, c) for c, _ in matched]
    findings.append(
        _make_finding(url, method, param, primary_cat, primary_hint, value, all_labels)
    )


def _check_path(url: str, path: str,
                seen: Set[Tuple], findings: List[Dict[str, Any]]) -> None:
    """URL path에서 traversal / wrapper_scheme 패턴을 탐지한다."""
    key = (url, "GET", "__path__")
    if key in seen:
        return

    matched: List[Tuple[str, str]] = [
        (cat, hint)
        for cat, pattern, hint in TRAVERSAL_PATTERNS
        if cat in _PATH_CATS and pattern.search(path)
    ]
    if not matched:
        return

    seen.add(key)
    primary_cat, primary_hint = matched[0]
    all_labels = [PATTERN_LABELS.get(c, c) for c, _ in matched]
    findings.append(
        _make_finding(url, "GET", "__path__", primary_cat, primary_hint, path, all_labels)
    )


def _make_finding(url: str, method: str, param: str, category: str, hint: str,
                  matched_value: str,
                  all_labels: List[str]) -> Dict[str, Any]:
    """Path Traversal finding dict를 생성한다."""
    label = PATTERN_LABELS.get(category, category)
    pattern_str = ", ".join(all_labels) if len(all_labels) > 1 else label

    if param == "__path__":
        description = (
            f"{method} {url} — URL path에서 {label} 패턴 탐지 "
            f"({hint} 수동 검증 권장)"
        )
    else:
        description = (
            f"{method} {url}의 파라미터 '{param}'에서 {label} 패턴 탐지 "
            f"({hint} 수동 검증 권장)"
        )

    return {
        "severity":    "HIGH",
        "url":         url,
        "method":      method,
        "param":       param if param != "__path__" else None,
        "description": description,
        "evidence":    f"패턴={pattern_str}, 값={matched_value[:100]}",
        # 패시브 탐지 — 추가 HTTP 요청 없으므로 response_url 없음
        "response_url": None,
    }
