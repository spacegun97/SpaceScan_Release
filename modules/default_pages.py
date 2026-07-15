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
from ._cancel import wait_or_cancel

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
    # ── ERP ───────────────────────────────────────────────────────────────
    "SAP": {
        "detect": {
            "headers": {
                "Server": [r"SAP NetWeaver", r"SAP J2EE Engine", r"SAP Web Application Server"],
                "Set-Cookie": [r"SAP_SESSIONID", r"MYSAPSSO2", r"saplb_"],
            },
            "body": [r"SAP NetWeaver", r"/sap/bc/", r"/sap/public/", r"com\.sap\.", r"SAP AG"],
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
    "DEXT5": {
        "detect": {
            "headers": {},
            "body": [
                r"dext5editor",
                r"dext5upload",
                r"DEXT5\.",
                r"DEXT5UPLOAD",
                r"/dext5",
                r"dext5\.js",
            ],
        },
    },
    # ── Framework ─────────────────────────────────────────────────────────
    "Spring": {
        "detect": {
            "headers": {
                "X-Application-Context": [r".+"],
            },
            "body": [
                r"Whitelabel Error Page",
                r"org\.springframework",
                r"Spring Boot",
                r"spring-boot",
            ],
        },
    },
    "PHP": {
        "detect": {
            "headers": {
                "X-Powered-By": [r"PHP/[\d.]+"],
                "Set-Cookie":   [r"PHPSESSID"],
            },
            "body": [
                r"<\?php",
                r"PHPSESSID",
            ],
        },
    },
    "NodeJS": {
        "detect": {
            "headers": {
                "X-Powered-By": [r"Express"],
            },
            "body": [
                r"Cannot GET /",
                r"node\.js",
                r"Express\.js",
            ],
        },
    },
    "Laravel": {
        "detect": {
            "headers": {
                "Set-Cookie": [r"laravel_session", r"XSRF-TOKEN"],
            },
            "body": [
                r"laravel",
                r"Laravel",
                r"XSRF-TOKEN",
                r"_ignition",
            ],
        },
    },
    "Django": {
        "detect": {
            "headers": {
                "Set-Cookie": [r"csrftoken", r"sessionid"],
            },
            "body": [
                r"csrfmiddlewaretoken",
                r"Django",
                r"django",
                r"__debug__",
            ],
        },
    },
    "ASPNET": {
        "detect": {
            "headers": {
                "X-AspNet-Version":  [r"[\d.]+"],
                "X-Powered-By":      [r"ASP\.NET"],
                "Set-Cookie":        [r"ASP\.NET_SessionId"],
            },
            "body": [
                r"__VIEWSTATE",
                r"__EVENTVALIDATION",
                r"ASP\.NET",
                r"WebResource\.axd",
            ],
        },
    },
}

# 사용자 입력 화면 카테고리 그룹 (출력 순서 결정)
TECH_CATEGORIES = {
    "WEB":         ["Apache", "Nginx", "IIS"],
    "WAS":         ["Tomcat", "JBoss", "WebLogic", "WebSphere"],
    "ERP":         ["SAP"],
    "Application": ["WordPress", "Drupal", "CKEditor", "FCKEditor", "SmartEditor", "CrossEditor", "DEXT5"],
    "Framework":   ["Spring", "PHP", "NodeJS", "Laravel", "Django", "ASPNET"],
}

# 백엔드 실행 확장자 → 언어 패밀리. 이 확장자를 가진 경로만 스택 게이팅 대상이 되며,
# 목록에 없는 확장자(.js/.xml/.html/.config/.ini 등 정적·스택 무관 리소스)는 항상 프로빙한다.
BACKEND_EXT: Dict[str, str] = {
    ".jsp": "java", ".jspx": "java", ".do": "java", ".action": "java",
    ".asp": "dotnet", ".aspx": "dotnet", ".ashx": "dotnet", ".asmx": "dotnet", ".axd": "dotnet",
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php",
}

# 감지된 기술 스택 → 언어 패밀리. WEB(Apache/Nginx)·에디터류·NodeJS·Django 등
# 언어 백엔드를 확정하지 않는 스택은 매핑에서 제외되어 게이팅에 기여하지 않는다.
STACK_BACKEND: Dict[str, str] = {
    "Tomcat": "java", "JBoss": "java", "WebLogic": "java", "WebSphere": "java",
    "SAP": "java", "Spring": "java",
    "IIS": "dotnet", "ASPNET": "dotnet",
    "PHP": "php", "Laravel": "php", "WordPress": "php", "Drupal": "php",
}

# 사용자가 직접 선택 가능한 백엔드 언어 패밀리 (BACKEND_EXT/STACK_BACKEND 값과 동일 집합).
# 자동 탐지가 언어를 확정하지 못하는 스택(Apache/Nginx/에디터류 등)만 감지됐을 때,
# 사용자가 직접 언어를 지정해 필터를 활성화할 수 있게 한다.
BACKEND_FAMILIES = {"java", "dotnet", "php"}


def _path_backend(path: str) -> Optional[str]:
    """경로의 확장자로 언어 패밀리를 판별한다. 스택 무관 확장자면 None을 반환한다."""
    _, ext = os.path.splitext(path)
    return BACKEND_EXT.get(ext.lower())


def _allowed_backends(stacks: List[str]) -> set:
    """감지된 스택 목록으로부터 허용 언어 패밀리 집합을 구성한다."""
    return {STACK_BACKEND[s] for s in stacks if s in STACK_BACKEND}

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
         auth_headers: Optional[Dict[str, str]] = None,
         stop_event=None,
         backend_filter: bool = True,
         backends: Optional[List[str]] = None) -> Dict[str, Any]:
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

    # common.json: 스택 탐지 결과와 무관하게 항상 점검하는 제네릭 민감파일 목록
    stack_paths = [(s, _load_paths(s)) for s in final_stacks]
    stack_paths.append(("Common", _load_paths("common")))

    # 백엔드 확장자 필터: 감지된 언어 패밀리 ∪ 사용자가 직접 선택한 언어와 다른
    # 백엔드 실행 확장자(.jsp/.php/.aspx 등)는 제외.
    # 언어 패밀리가 하나도 확정되지 않았으면(allowed 비어있음) 필터를 적용하지 않고 전량 프로빙한다.
    allowed: set = set()
    if backend_filter:
        user_backends = {b for b in (backends or []) if b in BACKEND_FAMILIES}
        allowed = _allowed_backends(final_stacks) | user_backends
    if allowed:
        skipped = 0
        filtered_stack_paths = []
        for stack, paths in stack_paths:
            kept = []
            for entry in paths:
                backend = _path_backend(entry["path"])
                if backend is None or backend in allowed:
                    kept.append(entry)
                else:
                    skipped += 1
            filtered_stack_paths.append((stack, kept))
        stack_paths = filtered_stack_paths
        if skipped:
            debug_events.append((datetime.now().isoformat(timespec='milliseconds'),
                                 "default_pages",
                                 f"백엔드 필터: {', '.join(sorted(allowed))} 외 확장자 {skipped}개 제외"))

    # 전체 경로 수 사전 계산 (진행률 계산용 — 필터링 이후 최종 경로 기준)
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
                    wait_or_cancel(stop_event, delay)  # 속도 조절 딜레이 (+ [중단] 검사)
                    resp = requests.get(url, timeout=timeout, verify=False,
                                        allow_redirects=False, cookies=cookies,
                                        proxies=proxies, headers=auth_headers or {})
                except requests.exceptions.ConnectionError:
                    # 조기 종료 시에도 지금까지 수집한 finding은 보존한다
                    result["error"] = "Connection refused"
                    result["findings"] = findings
                    return result
                except Exception:
                    pass
                else:
                    # 노출 판정: 200/301/302/401/403/405/415/500 = 리소스 존재
                    # (severity 무관 — 리다이렉트·접근 제어·메서드·미디어타입·서버오류와 관계없이 존재 확인)
                    # 301/302: 미인증 접근 시 로그온 페이지로 리다이렉트하는 관리 콘솔(NWA/UserAdmin/Portal 등) 탐지에 필요
                    exposed = resp.status_code in (200, 301, 302, 401, 403, 405, 415, 500)
                    if exposed:
                        seen_urls.add(url)
                        evidence = resp.text[:200].strip() if resp.text else str(resp.status_code)
                        description = CATEGORIES.get(entry.get("category", ""), entry.get("category", ""))
                        note = entry.get("note")
                        if note:
                            description = f"{description} · {note}"
                        # 본문에 "Burp Suite"가 포함되면 대상 서버 응답이 아닌
                        # BurpSuite 프록시 에러 페이지이므로 판정 신뢰 불가 → INFO 강등
                        severity = entry["severity"]
                        if "Burp Suite" in resp.text:
                            severity = "INFO"
                            description = f"{description} · [프록시 오류 — BurpSuite 응답으로 판정 신뢰 불가, 재검증 필요]"
                        findings.append({
                            "severity":    severity,
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
