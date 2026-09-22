"""
스캔 협조적 중단(cooperative cancellation) 공용 헬퍼.

[중단] 버튼은 잡(job)마다 생성된 threading.Event를 set 한다. 각 모듈의 요청 루프는
요청 직전·딜레이 대기 중에 이 이벤트를 검사하여, set 되면 즉시 ScanCancelled를
던져 호출부(_runner)까지 전파한다.

ScanCancelled를 BaseException으로 둔 이유:
요청 루프 다수가 `except Exception: continue` 형태의 광범위 예외 처리를 쓰는데,
중단 신호가 여기에 흡수되면 루프가 계속 돌아 중단이 무력화된다. BaseException을
상속하면 `except Exception`을 통과해 호출부까지 안전하게 전파된다.

wait_or_cancel은 요청 사이(딜레이 대기 중)의 중단만 즉시 처리한다. 요청이 이미
전송되어 소켓 recv로 블록된 동안에는 이 검사가 닿지 않아 최악의 경우 timeout초까지
반응이 늦어질 수 있다 — run_cancellable이 이 공백을 메운다(아래 참조).
"""
import time
import threading
from typing import Callable, Optional, TypeVar

_T = TypeVar("_T")


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


def run_cancellable(fn: Callable[[], _T],
                    stop_event: Optional["threading.Event"],
                    poll_interval: float = 0.1) -> _T:
    """fn()을 데몬 워커 스레드에서 실행하고, 완료를 기다리는 동안 poll_interval초마다
    stop_event를 검사한다. set되면 워커는 그대로 버려두고(요청은 스스로 응답/timeout으로
    자연 종료 — 추가 요청·재전송 없음) 즉시 ScanCancelled를 던져 호출 스레드가 곧바로
    탈출하게 한다.

    - stop_event=None이면 오버헤드 없이 fn()을 동기 호출한다(중단 미지원 호출 100% 동일 동작).
    - fn 내부에서 발생한 예외는 호출 스레드에서 '원래 객체 그대로' 재발생시킨다
      (Timeout → 재시도 로직, ConnectionError → 조기 종료 등 기존 except 분기가 그대로 동작).
    - fn()은 워커 스레드 1개에서 딱 한 번, 동기적으로 실행된다(동시 요청 없음 — 대상 서버
      부하는 기존과 동일하게 순차 1건씩).
    """
    if stop_event is None:
        return fn()
    if stop_event.is_set():
        raise ScanCancelled()

    box: dict = {}
    done = threading.Event()

    def _worker() -> None:
        try:
            box["v"] = fn()
        except BaseException as e:  # noqa: BLE001 — 원본 예외 그대로 보존해 재발생
            box["e"] = e
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True).start()
    while not done.wait(poll_interval):
        if stop_event.is_set():
            raise ScanCancelled()  # 워커는 버려둠 — 응답 도착/timeout 시 스스로 종료
    if "e" in box:
        raise box["e"]
    return box["v"]
