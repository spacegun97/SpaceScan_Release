"""
디렉토리 리스팅 취약점 스캐너
크롤링으로 실제 존재하는 경로를 수집한 뒤, 해당 경로들의 상위 디렉토리에 대해 리스팅 여부를 확인한다.
"""
import time
import re
import requests
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, Set, Callable, Optional, List, Tuple
from . import _crawl

LISTING_SIGNATURES = [
    r"Index of /",
    r"Directory listing for",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
    r"<title>Index of",
]

# 경로에 포함 시 민감 디렉토리로 분류
SENSITIVE_KEYWORDS = {"admin", "backup", "config", "log", "logs", "temp", "tmp", "data", "old", "dev"}


def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         max_pages: int = 1000, cookies: Optional[Dict[str, str]] = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: Optional[Dict[str, str]] = None,
         auth_headers: Optional[Dict[str, str]] = None,
         render: bool = False) -> Dict[str, Any]:
    result = {
        "module":       "Directory Listing",
        "target":       target_url,
        "findings":     [],
        "debug_events": [],
    }
    debug_events: List[Tuple[str, str, str]] = result["debug_events"]
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "directory_listing", "스캔 시작"))

    base = target_url.rstrip("/")
    base_netloc = urlparse(target_url).netloc

    # Phase 1: BFS 크롤링 (진행률 0~50% 구간에 매핑)
    crawl_cb = None
    if progress_cb:
        def crawl_cb(cur, total):
            progress_cb(int(cur / total * 50) if total else 0, 100)
    pages = _crawl.crawl(base, base_netloc, timeout, delay, max_pages, cookies,
                         progress_cb=crawl_cb, proxies=proxies,
                         auth_headers=auth_headers, render=render)
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "directory_listing", f"BFS 크롤링 완료: {len(pages)}개 페이지"))
    endpoints = {p["path"] for p in pages}

    # Phase 2: 수집된 경로에서 상위 디렉토리 추출
    directories = _extract_directories(endpoints)
    total_dirs = len(directories)
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "directory_listing", f"디렉토리 점검 대상: {total_dirs}개"))

    # Phase 3: 각 디렉토리에 GET 요청 → 리스팅 시그니처 확인 (진행률 50~100% 구간)
    findings = []

    for idx, dir_path in enumerate(sorted(directories)):
        url = base + dir_path
        try:
            time.sleep(delay)
            resp = requests.get(url, timeout=timeout, verify=False,
                                allow_redirects=True, cookies=cookies,
                                proxies=proxies, headers=auth_headers or {})

            # 리다이렉트 후 도메인이 달라지면 제외
            if urlparse(resp.url).netloc != base_netloc:
                continue

            if resp.status_code == 200:
                is_listing, sig = _is_listing(resp.text)
                if is_listing:
                    sensitive = any(kw in dir_path.lower() for kw in SENSITIVE_KEYWORDS)
                    exposed = _extract_files(resp.text)
                    findings.append({
                        "url":           url,
                        "path":          dir_path,
                        "status_code":   resp.status_code,
                        "severity":      "MEDIUM",
                        "description":   f"디렉토리 리스팅 활성화: {dir_path}" + (" [민감 경로]" if sensitive else ""),
                        "evidence":      sig,
                        "exposed_files": exposed[:20],
                        "total_files":   len(exposed),
                    })

        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused"
            return result
        except Exception:
            continue
        finally:
            # 각 디렉토리 처리 완료 후 진행률 보고 (예외 발생·리다이렉트 제외 무관)
            if progress_cb and total_dirs > 0:
                progress_cb(50 + int((idx + 1) / total_dirs * 50), 100)

    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "directory_listing", f"스캔 완료: {len(findings)}개 취약점"))
    result["findings"]     = findings
    result["crawl_events"] = [(p["visited_at"], p["url"]) for p in pages]
    return result



def _extract_directories(paths: Set[str]) -> Set[str]:
    """URL 경로 집합에서 모든 상위 디렉토리 경로를 추출한다.

    예) /blog/posts/article.html  →  {"/", "/blog/", "/blog/posts/"}
        /api/v2/users             →  {"/", "/api/", "/api/v2/", "/api/v2/users/"}
    확장자가 없는 마지막 세그먼트는 디렉토리로 간주하여 추가한다.
    """
    dirs: Set[str] = {"/"}

    for path in paths:
        parts = path.split("/")
        # 중간 세그먼트를 디렉토리로 추출 (i=1이면 루트 '/'이므로 i=2부터)
        for i in range(2, len(parts)):
            d = "/".join(parts[:i]) + "/"
            dirs.add(d)
        # 마지막 세그먼트에 확장자가 없으면 디렉토리일 수 있음
        last = parts[-1] if parts else ""
        if last and "." not in last:
            dirs.add(path.rstrip("/") + "/")

    return dirs


def _is_listing(body: str):
    """응답 바디에서 디렉토리 리스팅 시그니처를 탐색한다."""
    for sig in LISTING_SIGNATURES:
        m = re.search(sig, body, re.IGNORECASE)
        if m:
            return True, m.group(0)
    return False, None


def _extract_files(body: str) -> list:
    """디렉토리 리스팅 페이지에서 href 속성 기반으로 노출 파일 목록을 추출한다."""
    files = []
    for m in re.finditer(r'href=["\']([^"\'?#]+)["\']', body, re.IGNORECASE):
        href = m.group(1)
        if href not in ("../", "/") and not href.startswith(("http", "?")):
            files.append(href)
    return list(set(files))
