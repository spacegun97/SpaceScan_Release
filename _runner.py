"""
모듈 실행 공용 헬퍼 — app.py(대시보드)에서 공용으로 사용한다.

각 모듈의 scan() 호출 시 모듈별 추가 파라미터(stacks/max_pages/progress_cb) 구성과
실행 결과 dict 생성을 담당한다. 진행률 매핑·취소 체크 등 인터페이스
고유 책임은 호출부(app.py)에 남긴다.
"""
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from modules._cancel import ScanCancelled


# progress_cb 파라미터를 지원하는 모듈 — 하위 진행률을 전체 진행률로 매핑할 때 사용
MODULES_WITH_PROGRESS_CB = ("directory_listing", "sql_injection", "default_pages", "path_traversal")


def build_module_extra(key: str,
                       *,
                       stacks: Optional[List[str]] = None,
                       max_pages: Optional[int] = None,
                       progress_cb: Optional[Callable[[int, int], None]] = None,
                       render: bool = False,
                       stop_event: Optional["threading.Event"] = None
                       ) -> Dict[str, Any]:
    """모듈 키별로 scan()에 전달할 추가 파라미터 dict를 구성한다.

    - default_pages: stacks (사전 탐지 결과)
    - directory_listing / sql_injection / path_traversal: max_pages, render (크롤링 한계·렌더 옵션)
    - 위 4개 모듈: progress_cb (하위 진행률 콜백)
    - 전체 모듈: stop_event ([중단] 시 요청 루프 즉시 탈출용)
    """
    extra: Dict[str, Any] = {}
    if key == "default_pages" and stacks is not None:
        extra["stacks"] = stacks
    if key in ("directory_listing", "sql_injection", "path_traversal"):
        if max_pages is not None:
            extra["max_pages"] = max_pages
        extra["render"] = render   # render=False도 명시 전달 (기본값 덮어쓰기 방지)
    if key in MODULES_WITH_PROGRESS_CB and progress_cb is not None:
        extra["progress_cb"] = progress_cb
    # stop_event는 4개 스캔 모듈 모두 scan() 시그니처에서 수신한다
    if stop_event is not None:
        extra["stop_event"] = stop_event
    return extra


def run_single_module(mod, label: str, target: str, timeout: int, delay: float,
                      cookies: Optional[Dict[str, str]],
                      proxies: Optional[Dict[str, str]] = None,
                      auth_headers: Optional[Dict[str, str]] = None,
                      **extra) -> Dict[str, Any]:
    """단일 모듈 scan()을 실행하고 elapsed 시간이 포함된 결과 dict를 반환한다.

    예외 발생 시 error 필드가 채워진 fallback dict 반환.
    """
    t0 = time.time()
    try:
        res = mod.scan(target, timeout=timeout, delay=delay,
                       cookies=cookies, proxies=proxies,
                       auth_headers=auth_headers, **extra)
        res["elapsed"] = round(time.time() - t0, 2)
    except ScanCancelled:
        # 사용자 [중단] — 부분 결과 폐기, 취소 표식만 반환 (app.py가 보고서 생략)
        res = {"module": label, "cancelled": True,
               "findings": [], "elapsed": round(time.time() - t0, 2)}
    except Exception as e:
        res = {"module": label, "error": str(e),
               "findings": [], "elapsed": round(time.time() - t0, 2)}
    return res
