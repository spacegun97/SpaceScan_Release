"""
WEB/WAS 서버 기본·샘플 페이지 노출 취약점 스캐너
경로 데이터는 modules/data/*.json 에서 로드한다.
"""
import json
import os
import re
import time
import requests
from datetime import datetime
from typing import Any, Dict, List, Tuple, Callable, Optional

# ── 카테고리 → 한국어 설명 매핑 ──────────────────────────────────────────
CATEGORIES: Dict[str, str] = {
    "admin_console":    "관리 콘솔 노출",
    "status_page":      "서버 상태 모니터링 페이지 노출",
    "config_exposure":  "서버 설정 정보 노출",
    "debug_endpoint":   "디버그·진단 엔드포인트 노출",
    "sample_app":       "샘플 애플리케이션 노출",
    "default_resource": "기본 설치 리소스 노출",
    "sensitive_file":   "민감 파일 접근 가능",
    "api_endpoint":     "내부 API 엔드포인트 노출",
}

# ── 기술 스택별 탐지 패턴 정의 ────────────────────────────────────────────
# 경로 데이터는 modules/data/<stack>.json 에서 별도 로드
TECH_REGISTRY: Dict[str, Dict] = {
    "Apache": {
        "detect": {
            "headers": {"Server": [r"Apache"]},
            "body": [r"Apache/[\d.]+", r"<address>Apache", r"It works!"],
        },
    },
    "Nginx": {
        "detect": {
            "headers": {"Server": [r"nginx"]},
            "body": [r"<center>nginx</center>", r"nginx/[\d.]+", r"Welcome to nginx"],
        },
    },
    "IIS": {
        "detect": {
            "headers": {
                "Server": [r"Microsoft-IIS", r"IIS/[\d.]+"],
                "X-Powered-By": [r"ASP\.NET"],
            },
            "body": [r"IIS Windows Server", r"Microsoft-IIS/[\d.]+", r"iisstart\.png"],
        },
    },
    "Tomcat": {
        "detect": {
            "headers": {"Server": [r"Apache-Coyote", r"Apache Tomcat"]},
            "body": [r"Apache Tomcat/[\d.]+", r"<h1>HTTP Status \d+", r"Tomcat"],
        },
    },
    "JBoss": {
        "detect": {
            "headers": {
                "Server": [r"JBoss", r"WildFly"],
                "X-Powered-By": [r"JBoss", r"Undertow"],
            },
            "body": [r"JBoss", r"WildFly", r"jboss"],
        },
    },
    "WebLogic": {
        "detect": {
            "headers": {
                "Server": [r"WebLogic"],
                "X-Powered-By": [r"Servlet"],
            },
            "body": [r"WebLogic", r"BEA WebLogic", r"Oracle WebLogic"],
        },
    },
    "WebSphere": {
        "detect": {
            "headers": {
                "Server": [r"WebSphere"],
                "X-Powered-By": [r"Servlet", r"JSP"],
            },
            "body": [r"WebSphere", r"IBM WebSphere"],
        },
    },
    # ── CMS ───────────────────────────────────────────────────────────────
    "WordPress": {
        "detect": {
            "headers": {
                "Link": [r"wp-json"],
                "X-Pingback": [r"xmlrpc\.php"],
            },
            "body": [
                r'<meta name="generator" content="WordPress',
                r"wp-content/",
                r"wp-includes/",
                r"/wp-login\.php",
            ],
        },
    },
    "Drupal": {
        "detect": {
            "headers": {
                "X-Generator": [r"Drupal"],
                "X-Drupal-Cache": [r".+"],
                "X-Drupal-Dynamic-Cache": [r".+"],
            },
            "body": [
                r'<meta name="Generator" content="Drupal',
                r"Drupal\.settings",
                r"drupal\.org",
                r"/sites/default/files/",
                r"drupal-settings-json",
            ],
        },
    },
    # ── Editor ────────────────────────────────────────────────────────────
    "CKEditor": {
        "detect": {
            "headers": {},
            "body": [
                r"ckeditor\.js",
                r"/ckeditor/",
                r"CKEDITOR\.",
                r"/ckfinder/",
                r"CKEditor",
            ],
        },
    },
    "FCKEditor": {
        "detect": {
            "headers": {},
            "body": [
                r"fckeditor\.js",
                r"/fckeditor/",
                r"FCKeditor",
                r"FCKConfig",
                r"FCKeditorAPI",
            ],
        },
    },
    "SmartEditor": {
        "detect": {
            "headers": {},
            "body": [
                r"HuskyEZCreator",
                r"SmartEditor",
                r"SE2_",
                r"nhn\.husky",
                r"SmartEditor2",
            ],
        },
    },
    "CrossEditor": {
        "detect": {
            "headers": {},
            "body": [
                r"CrossEditor",
                r"namo_cross_editor",
                r"crosseditor",
                r"NamoEditor",
            ],
        },
    },
}

# 사용자 입력 화면 카테고리 그룹 (출력 순서 결정)
TECH_CATEGORIES = {
    "WEB":         ["Apache", "Nginx", "IIS"],
    "WAS":         ["Tomcat", "JBoss", "WebLogic", "WebSphere"],
    "Application": ["WordPress", "Drupal", "CKEditor", "FCKEditor", "SmartEditor", "CrossEditor"],
}

# JSON 데이터 파일 디렉터리
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _load_paths(stack: str) -> List[Dict]:
    """스택명에 해당하는 JSON 파일에서 경로 목록을 로드한다."""
    fpath = os.path.join(DATA_DIR, f"{stack.lower()}.json")
    try:
        with open(fpath, "r", encoding="utf-8") as fh:
            return json.load(fh).get("paths", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _detect_stacks(target_url: str, timeout: int,
                   cookies: Optional[Dict[str, str]] = None,
                   proxies: Optional[Dict[str, str]] = None,
                   auth_headers: Optional[Dict[str, str]] = None) -> List[str]:
    """응답 헤더·바디 패턴 분석으로 기술 스택 탐지."""
    detected: List[str] = []
    try:
        resp = requests.get(target_url, timeout=timeout, verify=False,
                            allow_redirects=True, cookies=cookies,
                            proxies=proxies, headers=auth_headers or {})
    except Exception:
        return detected

    headers = {k.lower(): v for k, v in resp.headers.items()}
    body    = resp.text

    for stack, info in TECH_REGISTRY.items():
        detect = info["detect"]
        found  = False

        # 헤더 패턴 우선 검사
        for header_name, patterns in detect.get("headers", {}).items():
            header_val = headers.get(header_name.lower(), "")
            if any(re.search(p, header_val, re.IGNORECASE) for p in patterns):
                found = True
                break

        # 헤더 미탐지 시 바디 패턴 검사
        if not found:
            found = any(re.search(p, body, re.IGNORECASE) for p in detect.get("body", []))

        if found:
            detected.append(stack)

    return detected




def scan(target_url: str, timeout: int = 10, delay: float = 0.7,
         stacks: Optional[List[str]] = None,
         cookies: Optional[Dict[str, str]] = None,
         progress_cb: Optional[Callable[[int, int], None]] = None,
         proxies: Optional[Dict[str, str]] = None,
         auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "module":       "Default & Sample Pages",
        "target":       target_url,
        "findings":     [],
        "debug_events": [],
    }
    debug_events: List[Tuple[str, str, str]] = result["debug_events"]
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "default_pages", "스캔 시작"))

    # stacks가 외부에서 전달된 경우 탐지 단계를 건너뜀
    if stacks is not None:
        final_stacks = stacks
    else:
        final_stacks = _detect_stacks(target_url, timeout, cookies, proxies=proxies,
                                      auth_headers=auth_headers)

    if not final_stacks:
        result["error"] = "탐지된 기술 스택 없음 — 스캔 건너뜀"
        return result

    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "default_pages", f"탐지 스택: {', '.join(final_stacks)}"))

    base      = target_url.rstrip("/")
    findings: List[Dict] = []
    seen_urls: set        = set()

    # 전체 경로 수 사전 계산 (진행률 계산용 — 스택별 경로 합산)
    stack_paths = [(s, _load_paths(s)) for s in final_stacks]
    total_paths = sum(len(p) for _, p in stack_paths)
    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "default_pages", f"경로 점검 대상: {total_paths}개"))
    done = 0

    for stack, paths in stack_paths:
        if not paths:
            continue

        for entry in paths:
            done += 1
            url = base + entry["path"]

            if url not in seen_urls:
                try:
                    time.sleep(delay)  # 속도 조절 딜레이
                    resp = requests.get(url, timeout=timeout, verify=False,
                                        allow_redirects=False, cookies=cookies,
                                        proxies=proxies, headers=auth_headers or {})
                except requests.exceptions.ConnectionError:
                    result["error"] = "Connection refused"
                    return result
                except Exception:
                    pass
                else:
                    # MEDIUM: 200/401/403 = 리소스 존재 (접근 제어 유무 무관)
                    # LOW: 200만 노출로 판정
                    exposed = (
                        resp.status_code in (200, 401, 403)
                        if entry["severity"] == "MEDIUM"
                        else resp.status_code == 200
                    )
                    if exposed:
                        seen_urls.add(url)
                        evidence = resp.text[:200].strip() if resp.text else str(resp.status_code)
                        description = CATEGORIES.get(entry.get("category", ""), entry.get("category", ""))
                        findings.append({
                            "severity":    entry["severity"],
                            "tech_stack":  stack,
                            "path":        entry["path"],
                            "url":         url,
                            "status_code": resp.status_code,
                            "description": description,
                            "evidence":    evidence,
                        })

            if progress_cb and total_paths > 0:
                progress_cb(done, total_paths)

    debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                         "default_pages", f"스캔 완료: {len(findings)}개 취약점"))
    result["findings"] = findings
    return result
