"""
스캔 협조적 중단(cooperative cancellation) 공용 헬퍼.

[중단] 버튼은 잡(job)마다 생성된 threading.Event를 set 한다. 각 모듈의 요청 루프는
요청 직전·딜레이 대기 중에 이 이벤트를 검사하여, set 되면 즉시 ScanCancelled를
던져 호출부(_runner)까지 전파한다.

ScanCancelled를 BaseException으로 둔 이유:
요청 루프 다수가 `except Exception: continue` 형태의 광범위 예외 처리를 쓰는데,
중단 신호가 여기에 흡수되면 루프가 계속 돌아 중단이 무력화된다. BaseException을
상속하면 `except Exception`을 통과해 호출부까지 안전하게 전파된다.
"""
import time
import threading
from typing import Optional


class ScanCancelled(BaseException):
    """사용자 [중단] 요청에 의한 협조적 스캔 중단 신호."""
    pass


def wait_or_cancel(stop_event: Optional["threading.Event"], secs: float) -> None:
    """secs 초만큼 대기하되, 대기 도중 stop_event가 set되면 즉시 ScanCancelled를 던진다.

    - stop_event가 이미 set이면 대기 없이 즉시 ScanCancelled (요청 직전 검사 겸용).
    - stop_event=None이면 일반 time.sleep으로 동작 (중단 미지원 호출 호환).
    - Event.wait()는 set되는 즉시 깨어나므로 느린 속도(긴 delay)에서도 대기를 즉시 끊는다.
    """
    if stop_event is None:
        if secs and secs > 0:
            time.sleep(secs)
        return
    # Event.wait(timeout)는 set이면 True를 즉시 반환, 아니면 timeout까지 블록.
    # secs<=0(속도 6단계)이어도 wait(0)으로 set 여부를 즉시 검사한다.
    if stop_event.wait(secs if (secs and secs > 0) else 0):
        raise ScanCancelled()
