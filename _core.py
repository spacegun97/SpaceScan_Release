#!/usr/bin/env python3
"""
Space Scan — 공유 유틸리티 (app.py / _runner.py 에서 공용)

GUI(app.py)와 모듈 레이어가 의존하는 함수/상수만 포함한다.
"""
import html as html_module
import math
import os
import sys
import threading
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse


def _ensure_deps():
    import importlib.util
    missing = [p for p in ("requests", "flask", "urllib3")
               if importlib.util.find_spec(p) is None]
    if missing:
        import subprocess
        print(f"[*] 패키지 설치 중: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet"] + missing)
        print("[✓] 설치 완료\n")

_ensure_deps()


# 속도 레벨 → 딜레이(초) 매핑 — 1초 간격 6단계
SPEED_DELAY = {1: 5.0, 2: 4.0, 3: 3.0, 4: 2.0, 5: 1.0, 6: 0.0}

# SQLi 추출 모드 — 1초 간격 6단계 (스캐닝과 별개로 더 세밀하게 제어)
EXTRACT_SPEED_DELAY = {1: 5.0, 2: 4.0, 3: 3.0, 4: 2.0, 5: 1.0, 6: 0.0}


# ── URL / 위험도 / 쿠키 파싱 ───────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def calculate_risk(results: list) -> dict:
    sc = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", "INFO")
            sc[sev] = sc.get(sev, 0) + 1
    return {"severity_counts": sc, "total_findings": sum(sc.values())}


def parse_cookie_string(raw: str) -> dict:
    """`"key=val; key2=val2"` 형식 문자열을 {키: 값} 딕셔너리로 파싱한다."""
    cookies: dict = {}
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


# ── HTML 리포트 빌더 (인라인 CSS/HTML은 상수, 행 빌더는 함수로 분리) ──────────

_REPORT_CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Pretendard:wght@300;400;600;700&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
body{background:#070b14;color:#cdd9f0;font-family:'Pretendard',sans-serif;font-size:14px;line-height:1.6}
.header{background:linear-gradient(135deg,#0f1628,#1a1040,#0f1628);border-bottom:1px solid #1e2d4a;padding:40px 56px}
.logo-tag{font-family:'JetBrains Mono',monospace;font-size:9px;color:#3b82f6;letter-spacing:3px;text-transform:uppercase;margin-bottom:6px;max-width:1400px;margin-left:auto;margin-right:auto}
h1{font-size:26px;font-weight:700;color:#fff;margin-bottom:10px;max-width:1400px;margin-left:auto;margin-right:auto}
.hmeta{display:flex;gap:24px;flex-wrap:wrap;max-width:1400px;margin:0 auto}
.hmeta span{font-family:'JetBrains Mono',monospace;font-size:11px;color:#4a607a}
.hmeta b{color:#cdd9f0}
.main{max-width:1400px;margin:0 auto;padding:36px 56px}
.stat-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:36px}
.stat{background:#0c1120;border:1px solid #1e2d4a;border-radius:10px;padding:18px;text-align:center;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat.h::before{background:#fb923c}.stat.m::before{background:#fbbf24}.stat.l::before{background:#60a5fa}.stat.i::before{background:#22d3ee}.stat.t::before{background:#a78bfa}
.stat-n{font-family:'JetBrains Mono',monospace;font-size:32px;font-weight:700;line-height:1;margin-bottom:6px}
.stat.h .stat-n{color:#fb923c}.stat.m .stat-n{color:#fbbf24}.stat.l .stat-n{color:#60a5fa}.stat.i .stat-n{color:#22d3ee}.stat.t .stat-n{color:#a78bfa}
.stat-lbl{font-size:10px;color:#4a607a;text-transform:uppercase;letter-spacing:1px}
.sec-hd{font-size:11px;font-weight:600;color:#4a607a;text-transform:uppercase;letter-spacing:2px;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #1e2d4a}
.table-wrap{background:#0c1120;border:1px solid #1e2d4a;border-radius:12px;overflow:hidden;margin-bottom:36px}
table{width:100%;border-collapse:collapse}
thead{background:#111827}
th{padding:11px 14px;text-align:left;font-size:10px;font-weight:600;color:#4a607a;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1e2d4a}
td{padding:11px 14px;border-bottom:1px solid #1e2d4a;vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:9px;font-weight:700;letter-spacing:.5px;font-family:monospace;color:#fff}
.footer{border-top:1px solid #1e2d4a;padding:20px 56px;text-align:center;color:#4a607a;font-family:monospace;font-size:11px}
"""

_SEV_BG = {"HIGH": "#991b1b", "MEDIUM": "#78350f", "LOW": "#1e3a5f", "INFO": "transparent"}
_SEV_ORDER = ["HIGH", "MEDIUM", "LOW", "INFO"]


def _render_url_block(url_val: Optional[str], resp_url: Optional[str]) -> Tuple[str, str]:
    """sql_injection 모듈의 URL / 응답 URL 블록을 생성한다.

    카드 name이 method(GET/POST)만 표시하므로 요청 URL을 본문에 항상 노출,
    response_url은 url과 다를 때만 추가 표시.
    """
    if resp_url is not None and url_val:
        url_esc = html_module.escape(str(url_val)[:300])
        url_block = (
            f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">URL</div>'
            f'<code style="font-family:monospace;font-size:11px;color:#60a5fa;'
            f'word-break:break-all;display:block;margin-bottom:6px">{url_esc}</code>'
        )
    else:
        url_block = ""

    if resp_url and resp_url != url_val:
        resp_url_esc = html_module.escape(str(resp_url)[:300])
        resp_url_block = (
            f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">응답 URL</div>'
            f'<code style="font-family:monospace;font-size:11px;color:#60a5fa;'
            f'word-break:break-all;display:block;margin-bottom:6px">{resp_url_esc}</code>'
        )
    else:
        resp_url_block = ""

    return url_block, resp_url_block


def _render_exposed_files(exposed_files: list, total_files: int) -> str:
    """directory_listing 모듈의 노출 파일 목록 블록을 생성한다."""
    if not exposed_files:
        return ""
    file_items = "".join(
        f'<li style="font-family:monospace;font-size:10px;color:#94a3b8">'
        f'{html_module.escape(str(fp))}</li>'
        for fp in exposed_files
    )
    more_label = (
        f'<li style="font-size:10px;color:#4a607a">… 외 {total_files - len(exposed_files)}개</li>'
        if total_files > len(exposed_files) else ""
    )
    return (
        f'<div style="margin-top:6px;font-size:10px;color:#4a607a">노출 파일 ({total_files}건):</div>'
        f'<ul style="margin:4px 0 0 12px;list-style:disc">{file_items}{more_label}</ul>'
    )


def _render_finding_row(f: Dict[str, Any]) -> str:
    """단일 finding을 HTML <tr> 한 줄로 변환한다."""
    sev  = f.get("severity", "INFO")
    name = f.get("header") or f.get("method") or f.get("path") or f.get("param") or f.get("url") or "-"

    # evidence를 HTML 이스케이프 처리하여 <style>, <script> 등 태그가
    # 브라우저에 의해 실제 HTML로 파싱되는 것을 방지
    evid = html_module.escape(str(f.get("evidence", "-"))[:150])

    url_block, resp_url_block = _render_url_block(f.get("url"), f.get("response_url"))
    files_block = _render_exposed_files(f.get("exposed_files", []), f.get("total_files", 0))

    # sql_injection: 기법 + 페이로드
    type_val    = f.get("type")
    payload_val = f.get("payload")
    type_payload_block = ""
    if type_val:
        t_esc = html_module.escape(str(type_val))
        type_payload_block = (
            f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">기법</div>'
            f'<code style="font-family:monospace;font-size:11px;color:#94a3b8;'
            f'display:block;margin-bottom:6px">{t_esc}</code>'
        )
        if payload_val:
            p_esc = html_module.escape(str(payload_val)[:200])
            type_payload_block += (
                f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">페이로드</div>'
                f'<code style="font-family:monospace;font-size:11px;color:#94a3b8;'
                f'word-break:break-all;display:block;margin-bottom:6px">{p_esc}</code>'
            )

    # default_pages / directory_listing: 스택 + 상태 코드
    tech_stack  = f.get("tech_stack")
    status_code = f.get("status_code")
    tech_status_block = ""
    if tech_stack:
        ts_esc = html_module.escape(str(tech_stack))
        tech_status_block = (
            f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">스택</div>'
            f'<code style="font-family:monospace;font-size:11px;color:#94a3b8;'
            f'display:block;margin-bottom:6px">{ts_esc}</code>'
        )
    if status_code is not None:
        tech_status_block += (
            f'<div style="font-size:10px;color:#4a607a;margin-bottom:3px">상태 코드</div>'
            f'<code style="font-family:monospace;font-size:11px;color:#94a3b8;'
            f'display:block;margin-bottom:6px">{status_code}</code>'
        )

    evid_cell = (
        f'{url_block}'
        f'{resp_url_block}'
        f'{type_payload_block}'
        f'{tech_status_block}'
        f'<code style="font-family:monospace;font-size:11px;color:#94a3b8;word-break:break-all">{evid}</code>'
        f'{files_block}'
    )

    return (
        f'<tr>'
        f'<td><span class="badge" style="background:{_SEV_BG.get(sev, "#1e293b")}">{sev}</span></td>'
        f'<td style="color:#4a607a;font-size:12px">{f.get("_module", "-")}</td>'
        f'<td style="font-family:monospace;font-size:12px;color:#60a5fa">{name}</td>'
        f'<td style="font-size:12px">{f.get("description", "-")}</td>'
        f'<td>{evid_cell}</td>'
        f'</tr>'
    )


def _render_finding_rows(results: list) -> str:
    """전체 results에서 finding 행 묶음을 생성한다. 비었으면 단일 안내 행 반환."""
    all_f = []
    for r in results:
        for f in r.get("findings", []):
            all_f.append({**f, "_module": r.get("module", "")})
    all_f.sort(key=lambda x: _SEV_ORDER.index(x.get("severity", "INFO")))

    if not all_f:
        return '<tr><td colspan="5" style="text-align:center;color:#22c55e;padding:40px">✓ 발견된 취약점 없음</td></tr>'
    return "".join(_render_finding_row(f) for f in all_f)


def generate_html_report(results: list, risk: dict, target: str, output_dir: str) -> str:
    """HTML 리포트를 생성하여 파일로 저장하고 절대 경로를 반환한다."""
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = urlparse(target).netloc.replace(".", "_").replace(":", "_")
    fpath  = os.path.join(os.path.abspath(output_dir), f"report_{domain}_{ts}.html")

    sc   = risk["severity_counts"]
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = _render_finding_rows(results)

    html = f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Space Scan Report – {target}</title>
<style>{_REPORT_CSS}</style></head><body>
<div class="header">
  <div class="logo-tag">SPACE SCAN</div>
  <h1>취약점 스캔 리포트</h1>
  <div class="hmeta">
    <span>대상: <b>{target}</b></span><span>일시: <b>{now}</b></span>
    <span>총 발견: <b>{risk['total_findings']}건</b></span>
  </div>
</div>
<div class="main">
<div class="stat-grid">
  <div class="stat t"><div class="stat-n">{risk['total_findings']}</div><div class="stat-lbl">Total</div></div>
  <div class="stat h"><div class="stat-n">{sc['HIGH']}</div><div class="stat-lbl">High</div></div>
  <div class="stat m"><div class="stat-n">{sc['MEDIUM']}</div><div class="stat-lbl">Medium</div></div>
  <div class="stat l"><div class="stat-n">{sc['LOW']}</div><div class="stat-lbl">Low</div></div>
  <div class="stat i"><div class="stat-n">{sc['INFO']}</div><div class="stat-lbl">Info</div></div>
</div>
<div class="sec-hd">취약점 상세</div>
<div class="table-wrap"><table>
<thead><tr><th>심각도</th><th>모듈</th><th>항목</th><th>설명</th><th>증거</th></tr></thead>
<tbody>{rows}</tbody>
</table></div></div>
<div class="footer">Generated by Space Scan v1.0 · {now} · For authorized testing only</div>
</body></html>"""

    os.makedirs(output_dir, exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as fh:
        fh.write(html)
    return fpath


# ── 결과 저장 ─────────────────────────────────────────────────────────────────

def save_crawl_log(results: list, target: str, output_dir: str) -> Optional[str]:
    """크롤링 URL과 모듈 이벤트를 타임스탬프 인터리브 형식으로 crawl_path.log에 저장한다.

    - [crawl] 접두사: BFS 크롤러가 방문한 URL (crawl_events 필드)
    - [<module>] 접두사: 모듈 핵심 흐름 이벤트 — 입력 포인트 수집·WAF 탐지·스캔 완료 등 (debug_events 필드)

    두 필드가 모두 없는 결과만 있으면 파일을 생성하지 않고 None을 반환한다.
    """
    # (iso_ts, label, text) 형식으로 전체 결과에서 이벤트 수집
    entries: list = []
    for r in results:
        # crawl_events: [(ts, url)] — 크롤러 방문 URL
        for ts, url in r.get("crawl_events", []):
            entries.append((ts, "crawl", url))
        # debug_events: [(ts, scope, msg)] — 모듈 핵심 흐름 이벤트
        for ts, scope, msg in r.get("debug_events", []):
            entries.append((ts, scope, msg))

    if not entries:
        return None

    # 타임스탬프 기준 오름차순 정렬
    entries.sort(key=lambda e: e[0])

    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain  = urlparse(target).netloc.replace(".", "_").replace(":", "_")
    fpath   = os.path.join(os.path.abspath(output_dir), f"crawl_path_{domain}_{ts_file}.log")

    os.makedirs(output_dir, exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as fh:
        for ts, label, text in entries:
            # ISO 구분자 'T'를 공백으로 변환 (2026-05-28T10:30:00.123 → 2026-05-28 10:30:00.123)
            fh.write(f"{ts.replace('T', ' ')} [{label}] {text}\n")
    return fpath


# ── SQLi 추출 모드 헬퍼 ────────────────────────────────────────────────────────

def _ensure_extract_deps() -> None:
    """추출 모드 진입 시점에 openpyxl을 lazy 설치한다.

    스캐닝만 사용하는 사용자에게는 불필요하므로 _ensure_deps()와 분리.
    """
    import importlib.util
    if importlib.util.find_spec("openpyxl") is None:
        import subprocess
        print("  [*] openpyxl 설치 중...")
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--quiet", "openpyxl"])
        print("  [✓] openpyxl 설치 완료\n")


_RENDER_READY: object = None   # 프로세스 1회 캐시 — 모듈 3개 중복 subprocess 방지
_RENDER_LOCK = threading.Lock()  # 동시 스캔 잡 중복 설치 방지


def _ensure_render_deps() -> bool:
    """렌더링 모드 진입 시점에 playwright를 lazy 설치한다.

    프로세스 내 1회만 설치 시도(모듈 3개 중복 호출 방지).
    성공 True / 실패(오프라인·바이너리 없음) False 반환 → False면 정적 폴백 신호.
    """
    global _RENDER_READY
    if _RENDER_READY is not None:
        return bool(_RENDER_READY)
    with _RENDER_LOCK:
        if _RENDER_READY is not None:  # 더블체크 — 락 진입 전 선점된 경우 재확인
            return bool(_RENDER_READY)
        import importlib.util
        try:
            if importlib.util.find_spec("playwright") is None:
                import subprocess as _sp
                print("  [*] playwright 설치 중...")
                _sp.check_call([sys.executable, "-m", "pip", "install", "--quiet", "playwright"])
                print("  [✓] playwright 설치 완료")
            # chromium 바이너리 설치 (이미 캐시돼 있으면 수초 내 완료)
            import subprocess as _sp
            _sp.check_call(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
            _RENDER_READY = True
        except Exception as e:
            print(f"  [!] playwright 설치 실패, 정적 크롤로 폴백: {e}")
            _RENDER_READY = False
    return bool(_RENDER_READY)


def _ensure_merge_deps() -> None:
    """엑셀 취합 모드 진입 시점에 openpyxl + xlrd를 lazy 설치한다.

    스캐닝·추출 미사용 사용자에게는 불필요하므로 분리.
    """
    import importlib.util
    missing = [p for p in ("openpyxl", "xlrd")
               if importlib.util.find_spec(p) is None]
    if missing:
        import subprocess
        print(f"  [*] {', '.join(missing)} 설치 중...")
        subprocess.check_call([sys.executable, "-m", "pip", "install",
                               "--quiet"] + missing)
        print(f"  [✓] {', '.join(missing)} 설치 완료\n")


def _estimate_dump(ctx, total_rows: int) -> Dict[str, float]:
    """dump 예상 요청 수 / 소요시간 계산 (순수 함수, 출력 없음).

    - UNION: union_row_batch 행을 1요청에 묶어 회수 → ceil(total / batch) 요청
    - Error: 행당 2요청 (length + content; 긴 결과 시 청크당 +1)
    - Boolean: 행당 21 + (평균 80글자 × 5요청)
    - COUNT는 estimate 단계에서 이미 실행되므로 +1 생략
    """
    if ctx.technique == "union":
        # 묶음 1요청으로 batch 행을 처리 → 정상 경로 기준 best-case 추정
        batch = max(1, getattr(ctx, "union_row_batch", 1))
        total_req = math.ceil(total_rows / batch)
    elif ctx.technique == "error":
        total_req = total_rows * 2
    else:  # boolean
        avg_chars = 80
        total_req = total_rows * (21 + avg_chars * 5)
    est_sec = total_req * max(ctx.delay, 0.05)
    return {"rows": int(total_rows), "requests": int(total_req), "seconds": float(est_sec)}
