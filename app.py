#!/usr/bin/env python3
"""
Space Scan - Flask 대시보드
사용법: python app.py [--port 7777]
"""
import os
import sys
import secrets
import socket
import threading
import time
import argparse
import webbrowser
from datetime import datetime
from typing import Callable, Optional, Dict
from urllib.parse import urlparse, parse_qsl

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR  = os.path.join(BASE_DIR, "reports")
TEMPLATE_DIR = os.path.join(BASE_DIR, "dashboard")

sys.path.insert(0, BASE_DIR)
# _core import 시 _ensure_deps()가 자동 실행되어 의존성 설치 완료
from _core import (normalize_url, calculate_risk, generate_html_report,
                   save_crawl_log, parse_cookie_string, SPEED_DELAY,
                   EXTRACT_SPEED_DELAY, _ensure_extract_deps,
                   _estimate_dump, _ensure_merge_deps, _ensure_recon_deps,
                   _ensure_jsanalysis_deps)
from modules import MODULE_MAP, sqli_extract, excel_merge, recon, js_analysis
from modules._cancel import ScanCancelled
from _runner import build_module_extra, run_single_module, MODULES_WITH_PROGRESS_CB

from flask import Flask, render_template, request, jsonify, send_file

app = Flask(__name__, template_folder=TEMPLATE_DIR)

scan_jobs: dict = {}

# ── SQLi 추출 모드 (Phase 3) ────────────────────────────────────────────────
# 완료/취소 job 1시간 TTL — /api/extract/start 진입부에서 정리 (간이 GC)
JOB_TTL_SEC = 3600
extract_jobs: dict = {}
# current_action_id check-and-set 보호 — 동시 액션 호출 시 409 Conflict 판정용
extract_lock = threading.Lock()

# ── 정보수집(OSINT) 모드 ────────────────────────────────────────────────────
recon_jobs: dict = {}

# ── JS/HTML/XFDL 분석 모드 ───────────────────────────────────────────────────
# 동기 처리(백그라운드 job 아님) — analysis_id로 결과만 캐시, 1시간 TTL GC
jsanalysis_jobs: dict = {}


def _build_proxies(proxy_host, proxy_port) -> Optional[dict]:
    """proxy_host/proxy_port로 requests proxies dict를 생성한다.

    둘 다 None이면 None 반환 (프록시 미사용). 포트 범위 1~65535 벗어나면 None.
    """
    if proxy_host is None and proxy_port is None:
        return None
    host = (proxy_host or "127.0.0.1").strip()
    try:
        port = int(proxy_port) if proxy_port is not None else 8080
    except (ValueError, TypeError):
        port = 8080
    if not (1 <= port <= 65535):
        return None
    proxy_url = f"http://{host}:{port}"
    return {"http": proxy_url, "https": proxy_url}


def _make_progress_cb(job: dict, base_pct: float, span: float) -> Callable[[int, int], None]:
    """모듈 하위 진행률을 전체 진행률로 매핑하는 콜백을 생성한다.

    base_pct: 현재 모듈 시작 지점의 전체 진행률
    span:     모듈 한 칸의 진행률 폭
    99% 상한 — 모듈 완료 시 외부에서 정확한 값으로 덮어쓴다.
    """
    def cb(current: int, total: int) -> None:
        if total > 0:
            sub = (current / total) * span
            job["progress"] = min(99, int(base_pct + sub))
    return cb


def _run_scan(job_id: str, target: str, modules: list, timeout: int,
              delay: float = 0.7, max_pages: int = 1000,
              cookies: Optional[dict] = None,
              proxies: Optional[dict] = None,
              user_stacks: Optional[list] = None,
              user_backends: Optional[list] = None,
              auth_headers: Optional[dict] = None,
              render: bool = False,
              backend_filter: bool = True,
              start_idx: int = 0):
    job = scan_jobs[job_id]
    job["status"] = "running"
    # 재개 시 기존 완료 모듈 결과를 이어받음 (최초 실행은 빈 리스트)
    results = list(job.get("results", []))

    # [중단] 즉시 반응용 이벤트 — cancel_scan에서 set, 각 모듈 요청 루프가 검사
    stop_event = threading.Event()
    job["stop_event"] = stop_event

    # default_pages 스택 사전 탐지 — 미완료 모듈 범위에 있을 때만 실행
    stacks_for_default = None
    backends_for_default = None
    if "default_pages" in modules[start_idx:]:
        dp_mod, _ = MODULE_MAP["default_pages"]
        auto = dp_mod._detect_stacks(target, timeout, cookies, proxies=proxies,
                                     auth_headers=auth_headers)
        # 유효한 스택명만 허용 (TECH_REGISTRY에 없는 값 필터링)
        extra = [s for s in (user_stacks or []) if s in dp_mod.TECH_REGISTRY]
        stacks_for_default = list(set(auto) | set(extra))
        # 유효한 언어 패밀리만 허용 (BACKEND_FAMILIES에 없는 값 필터링)
        backends_for_default = [b for b in (user_backends or []) if b in dp_mod.BACKEND_FAMILIES]

    total_modules = len(modules)
    per_module = 100 / total_modules if total_modules else 0

    for module_idx, key in enumerate(modules):
        if module_idx < start_idx:
            continue  # 재개 시 이미 완료된 모듈 skip
        if job.get("cancelled") or job.get("paused"):
            break
        mod, label = MODULE_MAP.get(key, (None, key))
        if not mod:
            continue
        job["current_module"] = label

        # 모듈별 하위 진행률 → 전체 진행률 매핑 콜백 생성
        progress_cb = (
            _make_progress_cb(job, module_idx * per_module, per_module)
            if key in MODULES_WITH_PROGRESS_CB else None
        )

        extra = build_module_extra(key, stacks=stacks_for_default,
                                   max_pages=max_pages, progress_cb=progress_cb,
                                   render=render, stop_event=stop_event,
                                   backend_filter=backend_filter,
                                   backends=backends_for_default)
        res = run_single_module(mod, label, target, timeout, delay,
                                cookies, proxies=proxies, auth_headers=auth_headers,
                                **extra)
        # 중단 신호로 취소된 모듈은 완료로 카운트하지 않음
        if res.get("cancelled"):
            break
        results.append(res)
        job["results"] = results
        # 모듈 완료 시 정확한 진행률로 갱신 (하위 콜백의 99% 상한 해제)
        job["progress"] = int((module_idx + 1) / total_modules * 100)

    # 초기화(reset) 취소 시 결과 폐기
    if job.get("cancelled"):
        job["status"] = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
        return

    # 중단(paused) 시 완료 모듈 결과 보존, 재개 가능 상태로 전환
    if job.get("paused"):
        job["status"] = "paused"
        job["completed_count"] = len(results)
        job["progress"] = int(len(results) / total_modules * 100) if total_modules else 0
        job["current_module"] = None
        return

    risk = calculate_risk(results)
    job["risk"] = risk

    os.makedirs(REPORTS_DIR, exist_ok=True)
    # 리포트 경로를 절대경로로 저장
    job["html_report"] = generate_html_report(results, risk, target, REPORTS_DIR)
    # 크롤링 모듈이 실행된 경우에만 crawl_path.log 저장
    save_crawl_log(results, target, REPORTS_DIR)

    job["status"] = "completed"
    job["completed_at"] = datetime.now().isoformat()


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data       = request.json or {}
    target     = normalize_url(data.get("target", ""))
    modules    = data.get("modules", list(MODULE_MAP.keys()))
    timeout    = int(data.get("timeout", 10))
    speed      = int(data.get("speed", 5))
    speed      = max(1, min(6, speed))       # 1~6 범위 보정
    delay      = SPEED_DELAY[speed]
    max_pages  = int(data.get("max_pages", 1000))
    max_pages  = max(10, min(30000, max_pages))  # 10~30000 범위 보정
    render     = bool(data.get("render", False))
    backend_filter = bool(data.get("backend_filter", True))
    # 쿠키 문자열 파싱: "key=val; key2=val2" → dict (빈 값이면 None)
    cookies_str = data.get("cookies", "").strip()
    cookies = parse_cookie_string(cookies_str) if cookies_str else {}
    # 인증 헤더 — {"Authorization": "Bearer xxx"} 형태 dict 직접 수신
    auth_headers = data.get("auth_headers") or {}
    if not isinstance(auth_headers, dict):
        return jsonify({"error": "auth_headers는 dict 형식이어야 합니다."}), 400
    # 프록시 설정 — proxy_host/proxy_port 둘 중 하나라도 있으면 활성화
    proxies = _build_proxies(data.get("proxy_host"), data.get("proxy_port"))
    # Default Pages 추가 점검 스택 — 리스트 타입만 허용 (유효성 검사는 _run_scan 내부)
    raw_dp_stacks = data.get("default_pages_stacks") or []
    if not isinstance(raw_dp_stacks, list):
        return jsonify({"error": "default_pages_stacks는 배열이어야 합니다."}), 400
    user_stacks = [str(s) for s in raw_dp_stacks]
    # Default Pages 사용자 선택 백엔드 언어 — 리스트 타입만 허용 (유효성 검사는 _run_scan 내부)
    raw_dp_backends = data.get("default_pages_backends") or []
    if not isinstance(raw_dp_backends, list):
        return jsonify({"error": "default_pages_backends는 배열이어야 합니다."}), 400
    user_backends = [str(b) for b in raw_dp_backends]

    if not target:
        return jsonify({"error": "target URL이 필요합니다."}), 400

    job_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"
    scan_jobs[job_id] = {
        "job_id": job_id, "target": target, "modules": modules,
        "status": "pending", "progress": 0, "current_module": None,
        "cancelled": False, "paused": False, "completed_count": 0,
        "results": [], "risk": None,
        "html_report": None,
        "created_at": datetime.now().isoformat(),
        # 재개용 파라미터 보존 — resume_scan이 동일 인자로 _run_scan 재호출
        "scan_params": {
            "target": target, "modules": modules, "timeout": timeout,
            "delay": delay, "max_pages": max_pages,
            "cookies": cookies or None, "proxies": proxies,
            "user_stacks": user_stacks, "user_backends": user_backends,
            "auth_headers": auth_headers or None,
            "render": render, "backend_filter": backend_filter,
        },
    }
    threading.Thread(
        target=_run_scan,
        args=(job_id, target, modules, timeout, delay, max_pages,
              cookies or None, proxies, user_stacks, user_backends, auth_headers or None,
              render, backend_filter),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>/status")
def scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    # 파일 경로·인증 파라미터·직렬화 불가 객체는 응답에서 제외
    safe = {k: v for k, v in job.items() if k not in ("html_report", "stop_event", "scan_params")}
    safe["has_html_report"] = bool(job.get("html_report") and os.path.exists(job["html_report"]))
    return jsonify(safe)


@app.route("/api/scans")
def list_scans():
    out = [
        {"job_id": jid, "target": j.get("target"), "status": j.get("status"),
         "risk": j.get("risk"), "created_at": j.get("created_at"),
         "completed_at": j.get("completed_at"),
         "has_html_report": bool(j.get("html_report") and os.path.exists(j["html_report"]))}
        for jid, j in list(scan_jobs.items())
    ]
    return jsonify(sorted(out, key=lambda x: x.get("created_at",""), reverse=True))


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
def cancel_scan(job_id):
    """스캔 중단(paused) 또는 초기화(cancelled) 처리.

    reset=False(중단): paused 플래그 + stop_event.set() → _run_scan이 paused 상태로 전환.
    reset=True(초기화): cancelled 플래그 + stop_event.set() → 결과 폐기 후 cancelled로 전환.
    paused 상태에서 reset=True: 스레드가 없으므로 직접 cancelled로 전환.
    """
    data  = request.json or {}
    reset = bool(data.get("reset", False))
    job   = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404

    status = job.get("status")
    # paused 상태에서는 초기화만 허용
    if status == "paused":
        if not reset:
            return jsonify({"error": "이미 일시정지 상태입니다."}), 400
        job["cancelled"] = True
        job["paused"]    = False
        job["status"]    = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
        return jsonify({"ok": True})

    if status not in ("pending", "running"):
        return jsonify({"error": "취소할 수 없는 상태입니다."}), 400

    if reset:
        # 초기화: cancelled 플래그로 _run_scan이 완전 폐기 경로로 진입
        job["cancelled"] = True
        job["paused"]    = False
    else:
        # 중단: paused 플래그로 _run_scan이 일시정지 경로로 진입
        job["paused"] = True

    stop_event = job.get("stop_event")
    if stop_event is not None:
        stop_event.set()
    return jsonify({"ok": True})


@app.route("/api/scan/<job_id>/resume", methods=["POST"])
def resume_scan(job_id):
    """일시정지된 스캔을 완료 모듈 다음부터 재개한다."""
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job.get("status") != "paused":
        return jsonify({"error": "일시정지 상태가 아닙니다."}), 400

    params    = job.get("scan_params", {})
    start_idx = job.get("completed_count", 0)

    job["paused"]    = False
    job["cancelled"] = False
    job["status"]    = "running"

    threading.Thread(
        target=_run_scan,
        args=(job_id,
              params["target"], params["modules"], params["timeout"],
              params["delay"],  params["max_pages"], params["cookies"],
              params["proxies"], params["user_stacks"], params["user_backends"],
              params["auth_headers"], params["render"], params["backend_filter"]),
        kwargs={"start_idx": start_idx},
        daemon=True,
    ).start()
    return jsonify({"ok": True, "resumed_from": start_idx})


@app.route("/api/scan/<job_id>/report/html")
def download_html(job_id):
    """HTML 리포트 다운로드 - send_file로 절대경로 직접 전송"""
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    path = job.get("html_report")
    if not path or not os.path.exists(path):
        return jsonify({"error": "리포트 파일이 없습니다. 스캔 완료 후 다시 시도하세요."}), 404
    return send_file(
        path,
        mimetype="text/html",
        as_attachment=True,
        download_name=os.path.basename(path),
    )


# ══════════════════════════════════════════════════════════════════════════════
# SQLi 추출 모드 백엔드
# ══════════════════════════════════════════════════════════════════════════════

# ── 헬퍼 ────────────────────────────────────────────────────────────────────

def _to_ts(iso_str: str) -> float:
    """ISO 8601 → unix timestamp (TTL GC 비교용). 파싱 실패 시 0 반환."""
    try:
        return datetime.fromisoformat(iso_str).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _gc_extract_jobs() -> None:
    """완료/취소/에러 후 1시간 경과 job을 정리 + 세션 close.

    /api/extract/start 진입부에서 호출되어 메모리 누수를 방지한다.
    """
    now = time.time()
    expired = [
        jid for jid, j in list(extract_jobs.items())
        if j.get("status") in ("completed", "cancelled", "error")
        and j.get("completed_at")
        and (now - _to_ts(j["completed_at"])) > JOB_TTL_SEC
    ]
    for jid in expired:
        ctx = extract_jobs[jid].get("ctx")
        if ctx is not None and getattr(ctx, "_session", None) is not None:
            try:
                ctx._session.close()
            except Exception:
                pass
        del extract_jobs[jid]


def _gc_recon_jobs() -> None:
    """완료/취소/에러 후 1시간 경과 recon job을 정리한다 (메모리 누수 방지).

    /api/recon/start 진입부에서 호출된다.
    """
    now = time.time()
    expired = [
        jid for jid, j in list(recon_jobs.items())
        if j.get("status") in ("completed", "cancelled", "error")
        and j.get("completed_at")
        and (now - _to_ts(j["completed_at"])) > JOB_TTL_SEC
    ]
    for jid in expired:
        del recon_jobs[jid]


def _gc_jsanalysis_jobs() -> None:
    """1시간 경과한 분석 결과를 정리한다 (메모리 누수 방지).

    분석은 동기 처리이므로 생성 시점 = 완료 시점이라 created_at만 비교한다.
    /api/jsanalysis/analyze 진입부에서 호출된다.
    """
    now = time.time()
    expired = [
        aid for aid, a in list(jsanalysis_jobs.items())
        if (now - _to_ts(a["created_at"])) > JOB_TTL_SEC
    ]
    for aid in expired:
        del jsanalysis_jobs[aid]


def _run_recon_job(job_id: str, domain: str, sources: list, timeout: int,
                   max_subdomains: int) -> None:
    """정보수집 백그라운드 실행 — run_recon() 실행 후 HTML/Excel 리포트 생성."""
    job = recon_jobs[job_id]
    job["status"] = "running"

    def progress_cb(current: int, total: int) -> None:
        job["progress"] = min(99, current) if total > 0 else job["progress"]

    try:
        result = recon.run_recon(
            domain, sources, timeout=timeout, max_subdomains=max_subdomains,
            progress_cb=progress_cb, stop_event=job["stop_event"],
        )
        job["result"] = result
        os.makedirs(REPORTS_DIR, exist_ok=True)
        job["html_report"] = recon.generate_recon_html(result, REPORTS_DIR)
        job["excel_report"] = recon.save_recon_to_excel(result, REPORTS_DIR)
        job["progress"] = 100
        job["status"] = "completed"
    except ScanCancelled:
        job["status"] = "cancelled"
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        job["completed_at"] = datetime.now().isoformat()


def _make_extract_progress_cb(job: dict) -> Callable[[int, int], None]:
    """추출 액션 하위 진행률을 job["action_progress"]에 매핑.

    action_progress: 0~100 (-1 = 시작 전 / total 미확정)
    """
    def cb(current: int, total: int) -> None:
        job["action_current"] = current
        job["action_total"] = total
        if total > 0:
            job["action_progress"] = min(100, int(current / total * 100))
    return cb


def _run_extract_fingerprint(job_id: str) -> None:
    """fingerprint 백그라운드 실행 — UnsupportedTechniqueError를 ready+안내로 변환.

    SQLite+Error / UNION visible 실패 등은 status=ready로 두고
    fingerprint.unsupported_techniques에 현재 기법을 기록 → 클라이언트가 재선택 모달.
    """
    job = extract_jobs[job_id]
    ctx = job["ctx"]
    job["status"] = "fingerprinting"
    job["progress"] = 0

    def fp_cb(current: int, total: int) -> None:
        if total > 0:
            job["progress"] = min(99, int(current / total * 100))

    try:
        sqli_extract.fingerprint(ctx, progress_cb=fp_cb)
        job["fingerprint"] = {
            "dbms": ctx.dbms,
            "technique": ctx.technique,
            "context": ctx.quote_context,
            "position": ctx.position or "where",
            "blind_template": ctx.blind_template or "",
            "union_visible_idx": ctx.union_visible_idx,
            "unsupported_techniques": [],
        }
        # fingerprint 결과를 extracted["meta"]에 동기화 — INFO 시트 정확성 보장
        extracted = job["extracted"]
        extracted["meta"]["dbms"]             = ctx.dbms
        extracted["meta"]["context"]          = ctx.quote_context
        extracted["meta"]["position"]         = ctx.position or "where"
        extracted["meta"]["blind_template"]   = ctx.blind_template or ""
        extracted["meta"]["technique"]        = ctx.technique
        extracted["meta"]["union_columns"]    = ctx.union_columns
        extracted["meta"]["union_types"]      = list(ctx.union_types)
        extracted["meta"]["union_visible_idx"] = ctx.union_visible_idx
        # 마스터 파일(INFO + 빈 DBList)을 즉시 생성 — 이후 액션 저장의 베이스
        _save_excel_file(job)
        job["progress"] = 100
        job["status"] = "ready"
    except sqli_extract.UnsupportedTechniqueError as e:
        msg = str(e)
        # 실패 사유 분류 — DBMS 식별 실패 vs 기법 미지원
        if "DBMS 자동 식별 실패" in msg:
            reason, unsupp = "dbms_detection", []
        else:
            reason, unsupp = "technique", [ctx.technique]
        job["fingerprint"] = {
            "dbms": ctx.dbms or "",
            "technique": ctx.technique,
            "context": ctx.quote_context if ctx.quote_context is not None else "",
            "position": ctx.position or "where",
            "blind_template": ctx.blind_template or "",
            "union_visible_idx": ctx.union_visible_idx,
            "unsupported_techniques": unsupp,
            "failure_reason": reason,
            "message": msg,
        }
        job["progress"] = 100
        job["status"] = "ready"
    except sqli_extract.WAFBlockedError as e:
        job["error"] = f"WAF blocked: {e}"
        job["status"] = "error"
        job["completed_at"] = datetime.now().isoformat()
    except InterruptedError:
        # 사용자 취소 — fingerprint 도중에도 안전 종료
        job["status"] = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
    except Exception as e:
        job["error"] = f"fingerprint 실패: {e}"
        job["status"] = "error"
        job["completed_at"] = datetime.now().isoformat()


def _excel_update_summary(extracted: dict, action_id: str) -> str:
    """action_id + extracted 내용으로 엑셀 갱신 요약 문자열을 생성한다."""
    if action_id == "dbms_info":
        info = extracted.get("dbms_info") or {}
        return f"DBMS 정보 ({info.get('version', '-')})"
    if action_id == "list_dbs":
        dbs = extracted.get("databases") or []
        return f"databases 추출 ({len(dbs)}개)"
    if action_id.startswith("list_tables:"):
        db = action_id[len("list_tables:"):]
        tbls = (extracted.get("tables") or {}).get(db) or []
        return f"tables 추출 — {db} ({len(tbls)}개)"
    if action_id.startswith("list_columns:"):
        key = action_id[len("list_columns:"):]
        cols = (extracted.get("columns") or {}).get(key) or []
        return f"columns 추출 — {key} ({len(cols)}개)"
    if action_id.startswith("dump:"):
        key = action_id[len("dump:"):]
        dump = (extracted.get("dumps") or {}).get(key) or {}
        rows = dump.get("rows") or []
        return f"dump 추출 — {key} ({len(rows)}행)"
    if action_id.startswith("search:"):
        hits = ((extracted.get("search") or {}).get("hits")) or []
        return f"검색 완료 ({len(hits)}건)"
    return action_id


def _search_file_prefix(job: dict) -> str:
    """검색모드 파일명 prefix — search(<대상>-<검색어>) 형태로 일반 추출과 격리."""
    meta = job.get("search_meta") or {}
    return f"search({meta.get('target', '')}-{meta.get('keyword', '')})"


def _parse_search_hit(raw: str, target: str) -> dict:
    """검색 결과 raw 문자열(DUMP_DELIM 결합)을 {db,table,column,display} 구조로 분리한다.

    이름에 "."이 포함돼도 파싱 오류가 나지 않도록 "." 결합이 아닌 원본
    DUMP_DELIM 기준으로 분리한다.
    """
    parts = raw.split(sqli_extract.DUMP_DELIM)
    if target == "database":
        return {"db": parts[0], "table": None, "column": None, "display": parts[0]}
    if target == "table":
        return {"db": parts[0], "table": parts[1], "column": None,
                "display": f"{parts[0]}.{parts[1]}"}
    return {"db": parts[0], "table": parts[1], "column": parts[2],
            "display": f"{parts[0]}.{parts[1]}.{parts[2]}"}


def _save_excel_file(job: dict, mode: str = "extract",
                     log_label: Optional[str] = None, log_errors: bool = False) -> None:
    """엑셀 파일 저장 — 기본은 로그 없는 조용한 flush.

    save_excel=False이면 즉시 반환.
    log_label이 주어지면 저장 성공 시 excel_updates에 진행률 로그를 남긴다
    (예: "[중간저장] 진행 1234/5678"). log_errors=True이면 실패도 로그로 남긴다
    (기본은 실패를 무시 — 30초 주기 중간저장 실패로 로그가 도배되는 것을 방지).
    mode="search"이면 검색모드 결과(search_extracted)를 격리된 파일로 저장한다.
    """
    if not job.get("save_excel"):
        return
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if mode == "search":
            saved = sqli_extract.save_to_excel(
                job["search_extracted"], job["target"], REPORTS_DIR,
                excel_name=job.get("excel_name"), file_prefix=_search_file_prefix(job),
            )
            job["search_excel_files"] = saved
        else:
            saved = sqli_extract.save_to_excel(
                job["extracted"], job["target"], REPORTS_DIR,
                excel_name=job.get("excel_name"),
            )
            job["excel_files"] = saved
        if log_label is not None:
            current, total = job.get("action_current", 0), job.get("action_total", 0)
            progress = f"진행 {current}/{total}" if total > 0 else f"진행 {current}"
            summary = f"[{log_label}] {progress}"
            if mode == "search":
                summary = f"[검색] {summary}"
            job["excel_updates"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "summary": summary,
            })
    except Exception as e:
        if log_errors:
            job["excel_updates"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "summary": f"엑셀 저장 실패: {e}",
            })
        # log_errors=False면 flush 실패를 무시 — 추출 흐름 유지


def _save_excel_incremental(job: dict, action_id: str, mode: str = "extract") -> None:
    """액션 완료 시점에 엑셀을 재저장하고 갱신 내역을 기록한다.

    save_excel=False인 job은 즉시 반환. 저장 실패(파일 락 등)는
    오류를 excel_updates에 기록하고 추출 흐름은 유지한다.
    mode="search"이면 검색모드 결과를 격리된 파일로 저장한다.
    """
    if not job.get("save_excel"):
        return
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        if mode == "search":
            saved = sqli_extract.save_to_excel(
                job["search_extracted"], job["target"], REPORTS_DIR,
                excel_name=job.get("excel_name"), file_prefix=_search_file_prefix(job),
            )
            job["search_excel_files"] = saved
            summary = f"[검색] {_excel_update_summary(job['search_extracted'], action_id)}"
        else:
            saved = sqli_extract.save_to_excel(
                job["extracted"], job["target"], REPORTS_DIR,
                excel_name=job.get("excel_name"),
            )
            job["excel_files"] = saved
            summary = _excel_update_summary(job["extracted"], action_id)
        job["excel_updates"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "summary": summary,
        })
    except Exception as e:
        job["excel_updates"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "summary": f"엑셀 저장 실패: {e}",
        })


def _ensure_totals(extracted: dict) -> dict:
    """구버전 엑셀 로드 등으로 totals 키가 없는 extracted를 방어적으로 보정."""
    totals = extracted.setdefault("totals", {"databases": None, "tables": {}, "columns": {}})
    totals.setdefault("databases", None)
    totals.setdefault("tables", {})
    totals.setdefault("columns", {})
    return totals


def _is_list_complete(existing: list, total: Optional[int]) -> bool:
    """total이 확정되어 있고 existing 길이가 이를 충족하면 완료로 간주한다."""
    return total is not None and len(existing) >= total


def _make_flush_cb(job: dict, base_cb: Callable[[int, int], None],
                   interval: float = 30.0, mode: str = "extract") -> Callable[[int, int], None]:
    """진행률 콜백에 주기적(interval초) 엑셀 체크포인트 저장을 덧붙인다.

    저장 성공 시 excel_updates에 "[중간저장]" 로그를 남긴다(실패는 무시 —
    30초마다 반복 실패로 로그가 도배되는 것을 방지).
    """
    ts = [time.time()]  # 클로저 내 mutable 컨테이너

    def cb(current: int, total: int) -> None:
        base_cb(current, total)
        now = time.time()
        if now - ts[0] >= interval:
            ts[0] = now
            _save_excel_file(job, mode=mode, log_label="중간저장")
    return cb


def _finalize_cancelled(job: dict, mode: str = "extract") -> None:
    """중단 공용 마무리 — 취소 플래그 해제 + ready/cancelled 상태 결정.

    협조적 break(정상 반환)와 InterruptedError 두 경로를 통합 처리한다.
    """
    ctx = job.get("ctx")
    if ctx is not None:
        ctx.cancelled = False
    if job.pop("reset_requested", False):
        # [초기화] 의도 — 완전 종료, GC 대상 편입
        job["status"] = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
    else:
        # [중단] 의도 — 부분 데이터 저장 후 ready 복귀 (버튼 재활성화)
        # 이후 재저장 없는 최종 저장이므로 실패도 로그로 남긴다(log_errors=True)
        _save_excel_file(job, mode=mode, log_label="중단", log_errors=True)
        job["cancelled"] = False
        job["status"] = "ready"


def _run_extract_action(job_id: str, action_fn: Callable[[dict], None],
                        action_id: str, mode: str = "extract") -> None:
    """액션 래퍼 — current_action_id 좀비 차단 (try/finally로 None 복귀).

    action_fn 내부에서 예외가 발생해도 current_action_id가 반드시 비워져
    다음 액션 호출이 가능하도록 보장한다.
    mode="search"이면 특수 검색모드 결과를 격리된 파일로 저장한다.
    """
    job = extract_jobs[job_id]
    job["status"] = "extracting"
    job["action_progress"] = -1
    job["action_current"] = 0
    job["action_total"] = 0
    try:
        action_fn(job)
        # 협조적 break(cancelled=True 정상 반환)도 중단으로 처리
        if job.get("cancelled"):
            _finalize_cancelled(job, mode=mode)
        else:
            # dump_estimate는 COUNT만 수행하고 실제 데이터를 추출하지 않으므로
            # 엑셀 재저장을 생략한다 (불필요한 I/O + excel_updates 로그 도배 방지)
            if not action_id.startswith("dump_estimate:"):
                _save_excel_incremental(job, action_id, mode=mode)
            job["status"] = "ready"
    except sqli_extract.WAFBlockedError as e:
        job["error"] = f"WAF blocked: {e}"
        job["status"] = "error"
        job["completed_at"] = datetime.now().isoformat()
    except sqli_extract.UnsupportedTechniqueError as e:
        # 기법 불가 — 메시지 그대로 노출 (prefix 없음)
        job["error"] = str(e)
        job["status"] = "error"
        job["completed_at"] = datetime.now().isoformat()
    except InterruptedError:
        # _send 내부에서 취소 신호를 받아 던진 예외 — 동일 마무리 로직 적용
        _finalize_cancelled(job, mode=mode)
    except Exception as e:
        job["error"] = f"{action_id} 실패: {e}"
        job["status"] = "error"
        job["completed_at"] = datetime.now().isoformat()
    finally:
        # 좀비 차단 — 정상/예외/취소 모두에서 슬롯 해제
        job["current_action_id"] = None


# ── 엔드포인트 ──────────────────────────────────────────────────────────────

@app.route("/api/extract/check-existing", methods=["GET"])
def extract_check_existing():
    """excel_name에 해당하는 기존 엑셀 파일 존재 여부 + 요약 반환.

    ?name=<excel_name> 쿼리 파라미터로 호출.
    파일이 있으면 {exists:true, summary:{dbms,technique,db_count,...}} 반환.
    없으면 {exists:false} 반환.
    """
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name 파라미터가 필요합니다."}), 400
    summary = sqli_extract.find_existing_extract(name, REPORTS_DIR)
    if summary is None:
        return jsonify({"exists": False})
    return jsonify({"exists": True, "summary": summary})


@app.route("/api/extract/search-check-existing", methods=["GET"])
def extract_search_check_existing():
    """특수 검색모드 기존 엑셀 파일에 이어받을 결과가 있는지 확인.

    ?name=<excel_name>&target=<database|table|column>&match=<contains|exact>&keyword=<검색어>
    파일이 있고 target/match/keyword가 모두 일치하면
    {exists:true, total, current_count} 반환. 그 외에는 {exists:false}.
    """
    name = (request.args.get("name") or "").strip()
    target = (request.args.get("target") or "").strip()
    match = (request.args.get("match") or "").strip()
    keyword = (request.args.get("keyword") or "").strip()
    if not name or not target or not match or not keyword:
        return jsonify({"error": "name/target/match/keyword 파라미터가 필요합니다."}), 400

    search_prefix = f"search({target}-{keyword})"
    load_result = sqli_extract.load_search_from_excel(name, search_prefix, REPORTS_DIR)
    if load_result is None:
        return jsonify({"exists": False})
    hits_raw, meta = load_result
    if (meta.get("target") != target or meta.get("match") != match
            or meta.get("keyword") != keyword):
        return jsonify({"exists": False})
    return jsonify({
        "exists": True,
        "total": meta.get("total", 0),
        "current_count": len(hits_raw),
    })


@app.route("/api/extract/start", methods=["POST"])
def extract_start():
    """추출 job 생성 + fingerprint 백그라운드 실행.

    v1 한계 검증: nested body 거부 / 외부 도메인 거부.
    target에 query string이 있으면 자동 분리하여 body_params에 병합.
    """
    _gc_extract_jobs()
    data = request.json or {}

    target_raw = (data.get("target") or "").strip()
    if not target_raw:
        return jsonify({"error": "target URL이 필요합니다."}), 400
    target = normalize_url(target_raw)
    parsed = urlparse(target)
    if not parsed.netloc:
        return jsonify({"error": "URL 형식이 올바르지 않습니다."}), 400

    # query string 자동 분리 — body_params에 병합 (UI에서 이미 분리하지만 서버도 보강)
    body_params: Dict[str, str] = {}
    if parsed.query:
        body_params.update(dict(parse_qsl(parsed.query, keep_blank_values=True)))
    # path까지로 정규화
    target = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    user_body = data.get("body_params") or {}
    if not isinstance(user_body, dict):
        return jsonify({"error": "body_params는 dict 형식이어야 합니다."}), 400
    for k, v in user_body.items():
        if isinstance(v, (dict, list)):
            return jsonify({"error": "v1: nested body unsupported"}), 400
        body_params[str(k)] = str(v)

    method = (data.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        return jsonify({"error": "method는 GET 또는 POST"}), 400
    body_type = (data.get("body_type") or "form").lower()
    if body_type not in ("form", "json", "xml"):
        return jsonify({"error": "body_type는 form/json/xml"}), 400

    vuln_param = (data.get("param") or "").strip()
    if not vuln_param:
        return jsonify({"error": "취약 파라미터명(param)이 필요합니다."}), 400
    if vuln_param not in body_params:
        return jsonify({"error": f"'{vuln_param}'가 body_params에 없습니다."}), 400

    technique = (data.get("technique") or "error").lower()
    if technique not in ("error", "boolean", "union"):
        return jsonify({"error": "technique은 error/boolean/union"}), 400

    union_columns = int(data.get("union_columns") or 0)
    union_types = data.get("union_types") or []
    if technique == "union":
        # 단일 타입 입력 시 컬럼 수만큼 자동 확장
        if len(union_types) == 1 and union_columns > 1:
            union_types = union_types * union_columns
        if union_columns <= 0 or len(union_types) != union_columns:
            return jsonify({"error": "UNION 컬럼 수와 타입 개수가 일치해야 합니다."}), 400

    # UNION visible 컬럼 수동 지정 (사용자는 1-based로 입력, 내부는 0-based로 변환)
    union_visible_manual = None
    if technique == "union":
        raw_uv = data.get("union_visible")
        if raw_uv is not None and str(raw_uv).strip():
            try:
                uv_1based = int(raw_uv)
            except (ValueError, TypeError):
                return jsonify({"error": "union_visible는 정수"}), 400
            if uv_1based < 1 or uv_1based > union_columns:
                return jsonify({"error": f"union_visible는 1~{union_columns} 범위여야 합니다."}), 400
            union_visible_manual = uv_1based - 1  # 0-based 변환

    # DBMS 사전 선택 (선택, 빈 값 = 자동 탐지)
    _VALID_DBMS = {"MySQL", "MariaDB", "MSSQL", "PostgreSQL", "Oracle", "SQLite"}
    preset_dbms = (data.get("dbms") or "").strip()
    if preset_dbms and preset_dbms not in _VALID_DBMS:
        return jsonify({"error": f"지원 DBMS: {', '.join(sorted(_VALID_DBMS))}"}), 400
    if preset_dbms == "SQLite" and technique == "error":
        return jsonify({"error": "SQLite는 Error-based 미지원 — 기법을 boolean 또는 union으로 변경하세요."}), 400

    # 컨텍스트: auto = None(자동 탐지) / manual = 문자열(빈 문자열=numeric)
    ctx_mode = (data.get("context_mode") or "auto").lower()
    if ctx_mode == "auto":
        quote_context = None
    else:
        quote_context = data.get("context_value") or ""

    # 주입 위치: auto = None(자동 탐지) / manual = where|where_case|orderby|custom
    _VALID_POSITIONS = {"where", "where_case", "orderby", "custom"}
    pos_mode = (data.get("position_mode") or "auto").lower()
    blind_template = None
    if pos_mode == "auto":
        position = None
    else:
        position = (data.get("position_value") or "where").strip()
        if position not in _VALID_POSITIONS:
            return jsonify({"error": "position은 where/where_case/orderby/custom"}), 400
        if position in ("where_case", "orderby", "custom") and technique != "boolean":
            return jsonify({"error": "where_case/orderby/custom 위치는 boolean 기법 전용"}), 400
        if position in ("where_case", "orderby") and preset_dbms == "SQLite":
            return jsonify({"error": "SQLite는 CASE WHEN 에러 오라클 미지원"}), 400
        if position == "custom":
            blind_template = (data.get("blind_template") or "").strip()
            if not blind_template:
                return jsonify({"error": "custom 위치는 blind_template이 필요합니다."}), 400
            if "{cond}" not in blind_template:
                return jsonify({"error": "blind_template에 {cond} 자리표시자가 없습니다."}), 400

    speed = int(data.get("speed", 4))
    speed = max(1, min(6, speed))
    delay = EXTRACT_SPEED_DELAY[speed]
    timeout = int(data.get("timeout", 10))

    cookies_str = (data.get("cookies") or "").strip()
    cookies = parse_cookie_string(cookies_str) if cookies_str else {}
    auth_headers = data.get("auth_headers") or {}
    if not isinstance(auth_headers, dict):
        return jsonify({"error": "auth_headers는 dict 형식이어야 합니다."}), 400

    # HEX 인코딩 모드 — Error/Boolean/UNION 세 기법 공통 (멀티바이트 안전, 기본 ON)
    use_hex = bool(data.get("use_hex", True))

    # UNION 행 묶음 크기 — 1이면 기존 1행씩, N이면 N행 묶음 (UNION 기법 전용)
    try:
        union_row_batch = max(1, int(data.get("union_row_batch") or 1))
    except (ValueError, TypeError):
        return jsonify({"error": "union_row_batch는 정수여야 합니다."}), 400

    proxies = _build_proxies(data.get("proxy_host"), data.get("proxy_port"))
    save_excel = bool(data.get("save_excel", False))
    base64_encode = bool(data.get("base64_encode", False))

    # 엑셀 저장 이름 (save_excel=True 시 필수)
    excel_name_raw = (data.get("excel_name") or "").strip()
    if save_excel and not excel_name_raw:
        return jsonify({"error": "엑셀 저장 시 파일 이름(excel_name)이 필요합니다."}), 400
    excel_name_val = excel_name_raw if save_excel else None

    # 재사용 플래그 (기존 엑셀 파일에서 복원)
    reuse = bool(data.get("reuse", False))

    # openpyxl lazy 설치 (실패해도 추출은 진행 — 저장 단계에서만 영향)
    try:
        _ensure_extract_deps()
    except Exception as e:
        # 설치 실패는 치명적이 아니므로 로깅만
        print(f"  [!] openpyxl 설치 실패: {e} — 엑셀 저장이 동작하지 않을 수 있습니다.")

    # ExtractCtx 생성 + 세션 attach
    ctx = sqli_extract.ExtractCtx(
        target_url=target,
        allowed_netloc=parsed.netloc,
        method=method,
        body_type=body_type,
        body_params=body_params,
        vuln_param=vuln_param,
        timeout=timeout,
        delay=delay,
        cookies=cookies,
        technique=technique,
        dbms=preset_dbms,
        quote_context=quote_context,
        position=position,
        blind_template=blind_template,
        auth_headers=auth_headers,
        base64_encode=base64_encode,
        use_hex=use_hex,
        union_columns=union_columns,
        union_types=list(union_types),
        union_visible_manual=union_visible_manual,
        union_row_batch=union_row_batch,
        proxies=proxies or {},
    )
    ctx._session = sqli_extract._build_session(cookies, auth_headers,
                                               proxies=proxies)

    # 재사용 모드: 엑셀에서 이전 결과 복원 + ctx 핵심값 덮어쓰기
    # (DBMS/컨텍스트/UNION 자동탐지 생략 — fingerprint의 비싼 probe 건너뜀)
    loaded_extracted = None
    if reuse and excel_name_val:
        load_result = sqli_extract.load_from_excel(excel_name_val, REPORTS_DIR)
        if load_result:
            loaded_extracted, ctx_meta = load_result
            # 자동탐지 대상 필드를 저장된 값으로 덮어씀
            ctx.dbms           = ctx_meta.get("dbms") or ctx.dbms
            ctx.quote_context  = ctx_meta.get("context", ctx.quote_context)
            ctx.position       = ctx_meta.get("position") or ctx.position
            ctx.blind_template = ctx_meta.get("blind_template") or ctx.blind_template
            if ctx.technique == "union":
                loaded_vis = ctx_meta.get("union_visible_idx", -1)
                if loaded_vis >= 0:
                    ctx.union_visible_manual = loaded_vis

    now = datetime.now()
    job_id = f"extract_{now.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"

    # 초기 extracted: 재사용이면 로드한 데이터, 아니면 새로 초기화
    init_ext = sqli_extract.init_extracted(ctx)
    if loaded_extracted is not None:
        # 현재 세션 정보(target/method/param/started_at)는 현재 ctx 기준으로 유지
        loaded_extracted["meta"]["target"]     = ctx.target_url
        loaded_extracted["meta"]["method"]     = ctx.method
        loaded_extracted["meta"]["body_type"]  = ctx.body_type
        loaded_extracted["meta"]["param"]      = ctx.vuln_param
        loaded_extracted["meta"]["started_at"] = init_ext["meta"]["started_at"]
        loaded_extracted["meta"]["finished_at"] = ""
        init_ext = loaded_extracted

    extract_jobs[job_id] = {
        "job_id": job_id,
        "target": target,
        "method": method,
        "body_type": body_type,
        "body_params": body_params,
        "param": vuln_param,
        "ctx": ctx,
        "status": "pending",
        "progress": 0,
        "current_action_id": None,
        "action_progress": -1,
        "action_current": 0,
        "action_total": 0,
        "estimate": None,
        "estimate_resume_from": None,
        "fingerprint": None,
        "extracted": init_ext,
        "save_excel": save_excel,
        "excel_name": excel_name_val,   # 사용자 입력 이름 (파일명 결정)
        "excel_files": [],
        "excel_updates": [],
        # 특수 검색모드 — 일반 추출(extracted)과 완전히 격리된 상태/결과/엑셀 파일
        "search_extracted": None,
        "search_meta": None,
        "search_excel_files": [],
        "error": None,
        "created_at": now.isoformat(),
        "completed_at": None,
        "cancelled": False,
    }

    threading.Thread(
        target=_run_extract_fingerprint, args=(job_id,), daemon=True
    ).start()
    return jsonify({"job_id": job_id})


@app.route("/api/extract/<job_id>/status")
def extract_status(job_id):
    """job 상태 폴링 — ctx / 세션 / extracted 내부 절대경로 노출 금지."""
    job = extract_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    # 클라이언트에 노출하지 않는 키: ctx, excel_files 절대경로는 basename만 노출
    out = {
        "job_id": job["job_id"],
        "target": job["target"],
        "method": job["method"],
        "body_type": job["body_type"],
        "param": job["param"],
        "status": job["status"],
        "progress": job["progress"],
        "current_action_id": job["current_action_id"],
        "action_progress": job["action_progress"],
        "action_current": job["action_current"],
        "action_total": job["action_total"],
        "estimate": job["estimate"],
        "estimate_resume_from": job.get("estimate_resume_from"),
        "fingerprint": job["fingerprint"],
        "extracted": job["extracted"],
        "error": job["error"],
        "created_at": job["created_at"],
        "completed_at": job["completed_at"],
        "cancelled": job["cancelled"],
        "save_excel": job.get("save_excel", False),
        "excel_name": job.get("excel_name"),
        "excel_files": [os.path.basename(f) for f in (job.get("excel_files") or [])],
        "excel_updates": job.get("excel_updates") or [],
        # 특수 검색모드 — 일반 extracted와 완전히 격리된 결과/파일
        "search_extracted": job.get("search_extracted"),
        "search_meta": job.get("search_meta"),
        "search_excel_files": [os.path.basename(f) for f in (job.get("search_excel_files") or [])],
    }
    return jsonify(out)


def _dispatch_extract_action(action: str, data: dict, ctx, extracted: dict, job: dict,
                             mode: str = "extract"):
    """액션별 (action_id, fn) 쌍을 반환한다.

    에러·캐시 히트 등 조기 종료 케이스는 Flask Response를 직접 반환.
    호출부에서 isinstance(result, tuple) and isinstance(result[0], str)로 구분.
    dump의 confirm=false(estimate) 단계도 COUNT 조회가 오래 걸릴 수 있어 다른 액션과
    동일하게 (action_id, fn) 쌍으로 반환 — 백그라운드 스레드에서 실행되고 결과는
    job["estimate"]/job["estimate_resume_from"]에 기록되어 상태 폴링으로 노출된다.
    mode="search"이면 검색모드 전용 search 액션이 추가로 허용되고,
    체크포인트 flush(_make_flush_cb)가 search_extracted 파일로 격리 저장된다.
    """
    if action == "dbms_info":
        action_id = "dbms_info"

        def fn(j):
            cb = _make_extract_progress_cb(j)
            info = sqli_extract.extract_dbms_info(ctx, progress_cb=cb)
            extracted["dbms_info"] = info

    elif action == "databases":
        action_id = "list_dbs"
        totals = _ensure_totals(extracted)
        existing = extracted.get("databases") or []
        cached_total = totals.get("databases")
        # total을 이미 알 때만 동기적으로 캐시 hit 판정 — COUNT 조회 자체는 fn(백그라운드 스레드)에서
        # 수행해 요청 스레드가 boolean-blind COUNT(15~20 요청) 동안 블로킹되지 않게 한다
        if cached_total is not None and _is_list_complete(existing, cached_total):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            # 기존 부분 목록을 그대로 이어받기 — extracted에 미리 등록해 중단 시에도 보존
            items = extracted.get("databases")
            if items is None:
                items = []
                extracted["databases"] = items
            total = totals.get("databases")
            if total is None:
                total = sqli_extract.count_databases(ctx) or 0
                totals["databases"] = total
            base_cb = _make_extract_progress_cb(j)
            flush_cb = _make_flush_cb(j, base_cb, mode=mode)
            sqli_extract.list_databases(ctx, total, progress_cb=flush_cb, items_out=items)

    elif action == "tables":
        db = (data.get("database") or "").strip()
        if not db:
            return jsonify({"error": "database 필요"}), 400
        action_id = f"list_tables:{db}"
        totals = _ensure_totals(extracted)
        existing = (extracted.get("tables") or {}).get(db) or []
        cached_total = totals["tables"].get(db)
        if cached_total is not None and _is_list_complete(existing, cached_total):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            tables_map = extracted.setdefault("tables", {})
            items = tables_map.get(db)
            if items is None:
                items = []
                tables_map[db] = items
            total = totals["tables"].get(db)
            if total is None:
                total = sqli_extract.count_db_tables(ctx, db) or 0
                totals["tables"][db] = total
            base_cb = _make_extract_progress_cb(j)
            flush_cb = _make_flush_cb(j, base_cb, mode=mode)
            sqli_extract.list_tables(ctx, db, total, progress_cb=flush_cb, items_out=items)

    elif action == "columns":
        db = (data.get("database") or "").strip()
        tbl = (data.get("table") or "").strip()
        if not db or not tbl:
            return jsonify({"error": "database/table 필요"}), 400
        col_key = f"{db}.{tbl}"
        action_id = f"list_columns:{col_key}"
        totals = _ensure_totals(extracted)
        existing = (extracted.get("columns") or {}).get(col_key) or []
        cached_total = totals["columns"].get(col_key)
        if cached_total is not None and _is_list_complete(existing, cached_total):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            columns_map = extracted.setdefault("columns", {})
            items = columns_map.get(col_key)
            if items is None:
                items = []
                columns_map[col_key] = items
            total = totals["columns"].get(col_key)
            if total is None:
                total = sqli_extract.count_table_columns(ctx, db, tbl) or 0
                totals["columns"][col_key] = total
            base_cb = _make_extract_progress_cb(j)
            flush_cb = _make_flush_cb(j, base_cb, mode=mode)
            sqli_extract.list_columns(ctx, db, tbl, total, progress_cb=flush_cb, items_out=items)

    elif action == "dump":
        db = (data.get("database") or "").strip()
        tbl = (data.get("table") or "").strip()
        cols = data.get("columns") or []
        if not db or not tbl or not cols:
            return jsonify({"error": "database/table/columns 필요"}), 400
        confirm = bool(data.get("confirm", False))
        action_id = f"dump:{db}.{tbl}"
        key = f"{db}.{tbl}"
        existing = (extracted.get("dumps") or {}).get(key)

        # 검색모드 컬럼 병합: 기존 dump가 있고 요청 컬럼 구성이 다르면 "같은 테이블에
        # 새 컬럼 추가"로 간주해 이미 뽑은 컬럼은 재추출하지 않고 새 컬럼만 추출한 뒤
        # 행 인덱스 기준으로 기존 시트에 이어붙인다. 일반 추출 모드는 테이블 전체
        # 컬럼을 항상 한 번에 dump하므로 이 분기를 타지 않는다.
        merge_new_cols = None
        if mode == "search" and existing and existing.get("columns") != list(cols):
            existing_cols = existing.get("columns") or []
            merge_new_cols = [c for c in cols if c not in existing_cols]
            if not merge_new_cols:
                # 요청 컬럼이 이미 전부 존재 — 추가 추출 불필요
                return jsonify({"ok": True, "cached": True})

        pending_map = extracted.setdefault("_pending_merges", {}) if merge_new_cols else None
        pending_key = f"{key}::{','.join(merge_new_cols)}" if merge_new_cols else None

        # 1단계: COUNT 추출 후 시간 추정 — Boolean-blind COUNT는 15~20+ 요청이 걸릴 수
        # 있어 Flask 요청 스레드를 블로킹하지 않도록 다른 액션과 동일하게 백그라운드
        # 스레드에서 실행하고, 프론트엔드는 상태 폴링으로 결과(estimate)를 받는다.
        if not confirm:
            action_id = f"dump_estimate:{key}"

            def fn(j):
                total = sqli_extract.count_table(ctx, db, tbl) or 0
                # 테이블별로 키잉 — 다른 테이블 estimate 조회 중 확정 요청이 들어와도
                # 엉뚱한 total이 재사용되지 않도록 방지
                j.setdefault("estimate_totals", {})[key] = total
                if merge_new_cols is not None:
                    # 병합 이어받기: 중단된 새 컬럼 추출 진행분이 있으면 그 길이만큼
                    pending = pending_map.get(pending_key)
                    resume_from = len(pending["rows"]) if pending else 0
                else:
                    # 이어받기: 같은 컬럼 구성의 부분 데이터가 있으면 남은 행 기준으로 추정
                    resume_from = (len(existing["rows"])
                                   if existing and existing.get("columns") == list(cols) else 0)
                remaining = max(total - resume_from, 0)
                j["estimate"] = _estimate_dump(ctx, remaining)
                j["estimate_resume_from"] = resume_from

            return action_id, fn

        # 2단계: 사용자 확인 후 본격 실행 (estimate에서 받은 total 재사용)
        # 현재 dump 대상(key)과 일치하는 값만 재사용 — 불일치 시 None → 재계산 유도
        cached_total = (job.get("estimate_totals") or {}).get(key)

        def fn(j):
            base_cb = _make_extract_progress_cb(j)
            flush_cb = _make_flush_cb(j, base_cb, mode=mode)

            if merge_new_cols is not None:
                # 새 컬럼만 별도로 추출 — pending_map에 진행 상태를 보관해 중단 시
                # 이어받기 가능. 완료 전까지는 메인 dumps에 반영하지 않으므로(=엑셀
                # 미노출) 중단돼도 기존 시트는 그대로 유지된다.
                pending = pending_map.get(pending_key)
                rows_acc = pending["rows"] if pending else []
                if pending is None:
                    pending_map[pending_key] = {"rows": rows_acc}

                sqli_extract.dump_table(ctx, db, tbl, merge_new_cols,
                                        total=cached_total,
                                        progress_cb=flush_cb,
                                        rows_out=rows_acc)
                if ctx.cancelled:
                    # 협조적 중단(예외 없이 반환) — 아직 미완료이므로 병합하지
                    # 않고 pending 상태 그대로 유지해 다음 시도 때 이어서 추출한다.
                    return
                # 여기 도달했다면 취소 없이 끝까지 완료된 것 — 인덱스 기준으로 기존
                # 행에 새 컬럼 값을 이어붙이고 컬럼 목록을 갱신한 뒤 pending을 정리한다.
                target = extracted["dumps"][key]
                target_rows = target["rows"]
                n_ready = min(len(rows_acc), len(target_rows))
                for i in range(n_ready):
                    target_rows[i] = target_rows[i] + rows_acc[i]
                target["columns"] = target["columns"] + merge_new_cols
                del pending_map[pending_key]
                return

            # 같은 컬럼 구성의 부분 데이터가 있으면 기존 rows 재사용하여 이어받기
            if existing and existing.get("columns") == list(cols):
                rows_acc = existing["rows"]
            else:
                # 새 추출 — rows_acc 미리 등록 (취소 시에도 누적 행 보존)
                rows_acc = []
                extracted.setdefault("dumps", {})[key] = {
                    "columns": list(cols), "rows": rows_acc
                }

            sqli_extract.dump_table(ctx, db, tbl, list(cols),
                                    total=cached_total,
                                    progress_cb=flush_cb,
                                    rows_out=rows_acc)
            # rows_acc는 extracted["dumps"][key]["rows"]와 동일 객체 — 별도 대입 불필요

    elif action == "search":
        target = (data.get("search_target") or "").strip()
        match = (data.get("search_match") or "").strip()
        keyword = (data.get("search_keyword") or "").strip()
        if target not in ("database", "table", "column"):
            return jsonify({"error": "search_target은 database/table/column 중 하나여야 합니다"}), 400
        if match not in ("contains", "exact"):
            return jsonify({"error": "search_match는 contains/exact 중 하나여야 합니다"}), 400
        if not keyword:
            return jsonify({"error": "search_keyword 필요"}), 400
        action_id = f"search:{target}:{match}:{keyword}"
        # resume_search=True이면 기존 엑셀 파일에서 hits_raw + total 복원 후 이어서 실행
        resume_search = bool(data.get("resume_search", False))

        def fn(j):
            # ── resume 시도 ──────────────────────────────────────────────────
            # save_excel=True + mode="search" + 파일 존재 + 조건 일치 시 이전 결과 복원
            hits_raw: list = []
            loaded_total = None
            if (resume_search and mode == "search"
                    and j.get("save_excel") and j.get("excel_name")):
                search_prefix = f"search({target}-{keyword})"
                load_result = sqli_extract.load_search_from_excel(
                    j["excel_name"], search_prefix, REPORTS_DIR)
                if load_result is not None:
                    loaded_hits_raw, loaded_meta = load_result
                    # target/match/keyword 모두 일치해야 이어받기 유효
                    if (loaded_meta.get("target") == target
                            and loaded_meta.get("match") == match
                            and loaded_meta.get("keyword") == keyword):
                        hits_raw = loaded_hits_raw
                        loaded_total = loaded_meta.get("total")

            # ── search_extracted 초기화 + 복원 hits 반영 ────────────────────
            search_extracted = sqli_extract.init_extracted(ctx)
            hits: list = []
            # 복원된 hits_raw → hits 재구성 (새 스캔 시 빈 리스트라 무해)
            for raw in hits_raw:
                hits.append(_parse_search_hit(raw, target))
            # 이미 파싱된 개수부터 stream_cb가 이어서 파싱하도록 초기화
            parsed_n = [len(hits_raw)]

            search_extracted["search"] = {
                "target": target, "match": match, "keyword": keyword, "hits": hits,
            }
            j["search_extracted"] = search_extracted
            j["search_meta"] = {"target": target, "match": match, "keyword": keyword}
            base_cb = _make_extract_progress_cb(j)

            # 히트 raw 문자열은 items_out으로 직접 채워지므로, progress_cb에서 새로
            # 늘어난 만큼만 파싱해 hits에 append — 추출 로그가 히트를 실시간으로 반영한다
            def stream_cb(current: int, total_n: int) -> None:
                base_cb(current, total_n)
                while parsed_n[0] < len(hits_raw):
                    hits.append(_parse_search_hit(hits_raw[parsed_n[0]], target))
                    parsed_n[0] += 1

            # stream_cb를 flush_cb로 감싸 30초 주기 중간저장 추가
            flush_cb = _make_flush_cb(j, stream_cb, mode=mode)
            # COUNT: (A)일반 경로는 loaded_total 재사용(요청 생략), (B)MSSQL table/column은
            # _search_mssql_multidb가 per_db_counts를 항상 fresh 재계산하므로 여기서의
            # total 값을 무시함 — 두 경우 모두 여기서 count_search를 생략해도 안전
            if loaded_total is not None:
                total = loaded_total
            else:
                total = sqli_extract.count_search(ctx, target, match, keyword) or 0
            # total을 search_extracted에 저장 — 엑셀 체크포인트·다음 resume COUNT 생략용
            search_extracted["search"]["total"] = total

            sqli_extract.search(ctx, target, match, keyword, total,
                                items_out=hits_raw, progress_cb=flush_cb)
            # 마지막 progress_cb 호출 이후 남은 항목(있다면) 반영
            while parsed_n[0] < len(hits_raw):
                hits.append(_parse_search_hit(hits_raw[parsed_n[0]], target))
                parsed_n[0] += 1

    else:
        return jsonify({"error": f"알 수 없는 action: {action}"}), 400

    return action_id, fn


@app.route("/api/extract/<job_id>/action", methods=["POST"])
def extract_action(job_id):
    """액션 트리거 — 백그라운드 실행 + 동시 호출 시 409 Conflict.

    action ∈ {dbms_info | databases | tables | columns | dump | search}
    dump는 confirm 미설정 시 COUNT 추정(estimate)만 백그라운드로 수행 — 다른 액션과
    동일하게 current_action_id를 점유하며, 완료 후 job["estimate"]로 결과 확인.
    search_mode=true이면 tables/columns/dump가 search_extracted를 대상으로 동작
    (특수 검색모드 드릴다운 — 일반 extracted와 완전히 격리).
    """
    job = extract_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job["status"] not in ("ready", "extracting"):
        return jsonify({"error": f"액션 호출 불가 상태: {job['status']}"}), 400

    data = request.json or {}
    action = (data.get("action") or "").lower()
    search_mode = bool(data.get("search_mode"))
    ctx = job["ctx"]

    if search_mode:
        if action != "search" and job.get("search_extracted") is None:
            return jsonify({"error": "먼저 검색(search)을 실행해야 드릴다운이 가능합니다"}), 400
        extracted = job["search_extracted"] if job.get("search_extracted") is not None else {}
        mode = "search"
    else:
        extracted = job["extracted"]
        mode = "extract"

    # 액션별 action_id + 실행 함수 결정 (에러·캐시·estimate는 즉시 응답)
    dispatch = _dispatch_extract_action(action, data, ctx, extracted, job, mode=mode)
    if not (isinstance(dispatch, tuple) and isinstance(dispatch[0], str)):
        return dispatch
    action_id, fn = dispatch

    # current_action_id check-and-set (동시 액션 차단)
    with extract_lock:
        if job.get("current_action_id"):
            return jsonify({
                "error": "다른 액션 실행 중", "current_action_id": job["current_action_id"]
            }), 409
        job["current_action_id"] = action_id

    threading.Thread(
        target=_run_extract_action, args=(job_id, fn, action_id), kwargs={"mode": mode}, daemon=True
    ).start()
    return jsonify({"ok": True})


@app.route("/api/extract/<job_id>/retechnique", methods=["POST"])
def extract_retechnique(job_id):
    """SQLite Error fallback / UNION visible 실패 후 사용자 재선택.

    ctx 갱신 + fingerprint 재실행 → ready 복귀.
    """
    job = extract_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job["status"] not in ("ready", "error"):
        return jsonify({"error": f"재선택 불가 상태: {job['status']}"}), 400
    # 진행 중인 액션이 있으면 거부
    with extract_lock:
        if job.get("current_action_id"):
            return jsonify({"error": "액션 실행 중에는 재선택 불가"}), 409

    data = request.json or {}
    technique = (data.get("technique") or "").lower()
    dbms = (data.get("dbms") or "").strip()
    position = (data.get("position") or "").strip()

    # technique 또는 dbms 중 하나는 있어야 함
    if not technique and not dbms and not position:
        return jsonify({"error": "technique / dbms / position 중 하나 필요"}), 400
    if technique and technique not in ("error", "boolean", "union"):
        return jsonify({"error": "technique은 error/boolean/union"}), 400
    if position and position not in ("where", "where_case", "orderby", "custom"):
        return jsonify({"error": "position은 where/where_case/orderby/custom"}), 400

    _VALID_DBMS = {"MySQL", "MariaDB", "MSSQL", "PostgreSQL", "Oracle", "SQLite"}
    if dbms and dbms not in _VALID_DBMS:
        return jsonify({"error": f"지원 DBMS: {', '.join(sorted(_VALID_DBMS))}"}), 400

    # custom 위치: blind_template 파싱 및 검증
    blind_template = None
    if position == "custom":
        blind_template = (data.get("blind_template") or "").strip()
        if not blind_template:
            return jsonify({"error": "custom 위치는 blind_template이 필요합니다."}), 400
        if "{cond}" not in blind_template:
            return jsonify({"error": "blind_template에 {cond} 자리표시자가 없습니다."}), 400

    ctx = job["ctx"]
    effective_technique = technique or ctx.technique
    effective_dbms      = dbms or ctx.dbms
    # SQLite 충돌 가드
    if effective_dbms == "SQLite" and effective_technique == "error":
        return jsonify({"error": "SQLite는 Error-based 미지원 — 기법을 boolean 또는 union으로 변경하세요."}), 400
    effective_pos = position or ctx.position or "where"
    if effective_pos in ("where_case", "orderby", "custom") and effective_technique != "boolean":
        return jsonify({"error": "where_case/orderby/custom 위치는 boolean 기법 전용"}), 400
    if effective_pos in ("where_case", "orderby") and effective_dbms == "SQLite":
        return jsonify({"error": "SQLite는 CASE WHEN 에러 오라클 미지원"}), 400

    if dbms:
        ctx.dbms = dbms
    if technique:
        ctx.technique = technique
    if position:
        ctx.position = position
        if blind_template:
            ctx.blind_template = blind_template
    # UNION 컬럼 재검증 — position 지정 여부와 무관하게 technique이 union으로
    # 바뀌는 모든 요청에서 실행되어야 함 (position은 boolean 전용 필드라
    # union 전환 시 함께 오지 않는 경우가 정상 케이스)
    if technique == "union":
        try:
            uc = int(data.get("union_columns") or 0)
        except (ValueError, TypeError):
            return jsonify({"error": "union_columns는 정수"}), 400
        ut = data.get("union_types") or []
        # 단일 타입 입력 시 컬럼 수만큼 자동 확장
        if len(ut) == 1 and uc > 1:
            ut = ut * uc
        if uc <= 0 or len(ut) != uc:
            return jsonify({"error": "UNION 컬럼 수와 타입 개수가 일치해야 합니다."}), 400
        ctx.union_columns = uc
        ctx.union_types = list(ut)
        ctx.union_visible_idx = -1  # 재탐지 트리거
    # fingerprint 재실행 전 이전 에러 메시지 초기화
    job["error"] = None

    threading.Thread(
        target=_run_extract_fingerprint, args=(job_id,), daemon=True
    ).start()
    return jsonify({"ok": True})


@app.route("/api/extract/<job_id>/cancel", methods=["POST"])
def extract_cancel(job_id):
    """추출 취소 — ctx.cancelled / job.cancelled 동기화.

    fingerprint 도중에도 다음 phase에서 즉시 종료. 누적 데이터는 보존.
    """
    job = extract_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job["status"] in ("completed", "cancelled", "error"):
        return jsonify({"error": "이미 종료된 job"}), 400

    data = request.json or {}
    # reset=True이면 초기화 의도 (완전 종료), False이면 중단 의도 (ready 복귀)
    is_reset = bool(data.get("reset", False))

    job["cancelled"] = True
    if is_reset:
        job["reset_requested"] = True  # _run_extract_action InterruptedError에서 참조
    ctx = job.get("ctx")
    if ctx is not None:
        ctx.cancelled = True
    # 진행 중인 액션이 없으면 즉시 종료 마킹 (GC 대상 편입)
    if not job.get("current_action_id"):
        job["status"] = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
    return jsonify({"ok": True})


# ── 엑셀 취합 모드 ────────────────────────────────────────────────────────────

@app.route("/api/merge", methods=["POST"])
def merge_excel():
    """다중 엑셀 파일 스키마-합집합 병합.

    multipart/form-data 수신:
      files   : 업로드 파일 목록 (.xlsx/.xlsm/.xls/.csv)
      out_name: 출력 파일명 기반 (기본값 'result')

    응답 JSON:
      columns, total_rows, per_file, skipped_files, download_name
    """
    _ensure_merge_deps()

    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "업로드된 파일이 없습니다."}), 400

    out_name = (request.form.get("out_name") or "result").strip() or "result"

    # 파일명·바이트 쌍 구성 (빈 파일명은 제외)
    sources = [(f.filename, f.read()) for f in files if f.filename]
    if not sources:
        return jsonify({"error": "유효한 파일이 없습니다."}), 400

    try:
        result = excel_merge.merge_workbooks(sources)
    except Exception as e:
        return jsonify({"error": f"병합 처리 오류: {e}"}), 500

    # 유효 데이터가 전혀 없고 스킵 파일만 있는 경우
    if result["total_rows"] == 0 and len(result["skipped_files"]) == len(sources):
        return jsonify({"error": "읽을 수 있는 데이터가 없습니다. 파일 형식을 확인하세요.",
                        "per_file": result["per_file"]}), 400

    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        saved_path = excel_merge.save_merged(result, REPORTS_DIR, out_name)
    except Exception as e:
        return jsonify({"error": f"파일 저장 오류: {e}"}), 500

    return jsonify({
        "columns":       result["columns"],
        "total_rows":    result["total_rows"],
        "per_file":      result["per_file"],
        "skipped_files": result["skipped_files"],
        "download_name": os.path.basename(saved_path),
    })


@app.route("/api/merge/download")
def download_merge():
    """병합 결과 xlsx 파일 다운로드.

    쿼리 파라미터 name=<파일명> — basename 검증 후 reports/ 에서 서빙.
    """
    name = request.args.get("name", "").strip()
    basename = os.path.basename(name)
    # 안전 검증: merge_ 접두사 + .xlsx 확장자만 허용
    if not basename.startswith("merge_") or not basename.endswith(".xlsx"):
        return jsonify({"error": "잘못된 파일명입니다."}), 400
    filepath = os.path.join(REPORTS_DIR, basename)
    if not os.path.exists(filepath):
        return jsonify({"error": "파일이 존재하지 않습니다."}), 404
    return send_file(
        filepath,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=basename,
    )


# ── 정보수집(OSINT) 모드 ────────────────────────────────────────────────────

@app.route("/api/recon/start", methods=["POST"])
def recon_start():
    """정보수집(OSINT) job 생성 + 백그라운드 실행.

    대상 도메인·서브도메인으로는 어떤 요청도 보내지 않는다 — crt.sh / Wayback
    Machine / 공용 DNS 리졸버(8.8.8.8, 1.1.1.1) / Shodan InternetDB 4개
    제3자 소스만 조회하는 순수 패시브 정찰이다.
    """
    _ensure_recon_deps()
    _gc_recon_jobs()
    data = request.json or {}

    try:
        domain = recon.normalize_domain(data.get("domain", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    sources = data.get("sources") or list(recon.SOURCE_KEYS)
    if not isinstance(sources, list):
        return jsonify({"error": "sources는 배열이어야 합니다."}), 400
    sources = [s for s in sources if s in recon.SOURCE_KEYS]
    if not sources:
        return jsonify({"error": "최소 하나 이상의 소스를 선택해야 합니다."}), 400

    timeout = max(3, min(30, int(data.get("timeout", 8))))
    max_subdomains = max(recon.MIN_MAX_SUBDOMAINS,
                         min(recon.MAX_MAX_SUBDOMAINS,
                             int(data.get("max_subdomains", recon.DEFAULT_MAX_SUBDOMAINS))))

    job_id = f"recon_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"
    recon_jobs[job_id] = {
        "job_id": job_id, "domain": domain, "sources": sources,
        "status": "pending", "progress": 0,
        "stop_event": threading.Event(),
        "result": None, "html_report": None, "excel_report": None,
        "error": None,
        "created_at": datetime.now().isoformat(),
    }
    threading.Thread(
        target=_run_recon_job,
        args=(job_id, domain, sources, timeout, max_subdomains),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id})


@app.route("/api/recon/<job_id>/status")
def recon_status(job_id):
    job = recon_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    # 파일 경로·직렬화 불가 객체(stop_event)는 응답에서 제외
    safe = {k: v for k, v in job.items() if k not in ("stop_event", "html_report", "excel_report")}
    safe["has_html_report"] = bool(job.get("html_report") and os.path.exists(job["html_report"]))
    safe["has_excel_report"] = bool(job.get("excel_report") and os.path.exists(job["excel_report"]))
    return jsonify(safe)


@app.route("/api/recon/<job_id>/cancel", methods=["POST"])
def recon_cancel(job_id):
    job = recon_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job["status"] in ("completed", "cancelled", "error"):
        return jsonify({"error": "이미 종료된 job"}), 400
    job["stop_event"].set()
    return jsonify({"ok": True})


@app.route("/api/recon/<job_id>/report/html")
def recon_report_html(job_id):
    """정보수집 HTML 리포트 다운로드 - send_file로 절대경로 직접 전송."""
    job = recon_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    path = job.get("html_report")
    if not path or not os.path.exists(path):
        return jsonify({"error": "리포트가 아직 생성되지 않았습니다."}), 404
    return send_file(path, mimetype="text/html")


@app.route("/api/recon/<job_id>/report/excel")
def recon_report_excel(job_id):
    """정보수집 Excel 리포트 다운로드."""
    job = recon_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    path = job.get("excel_report")
    if not path or not os.path.exists(path):
        return jsonify({"error": "리포트가 아직 생성되지 않았습니다."}), 404
    return send_file(
        path,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name=os.path.basename(path),
    )


# ── JS/HTML/XFDL 분석 모드 ───────────────────────────────────────────────────

@app.route("/api/jsanalysis/analyze", methods=["POST"])
def jsanalysis_analyze():
    """.js/.html/.xfdl/.xadl/.xjs/.xml 업로드 → 함수 인벤토리 + 호출 그래프 + 데이터플로우 정적 분석.

    완전 오프라인(외부 요청 없음). multipart/form-data 수신:
      files: 업로드 파일 목록 (.js/.html/.htm/.xfdl/.xadl/.xjs/.xml)

    응답 JSON: analysis_id, files(파일별 처리 통계), function_count
    분석 결과는 analysis_id로 서버에 캐시되어(TTL 1시간) 이후 검색/상세/그래프
    요청 시 재업로드·재파싱 없이 재사용된다.
    """
    _ensure_jsanalysis_deps()
    _gc_jsanalysis_jobs()

    files = request.files.getlist("files")
    if not files or all(f.filename == "" for f in files):
        return jsonify({"error": "업로드된 파일이 없습니다."}), 400

    sources = [(f.filename, f.read()) for f in files if f.filename]
    if not sources:
        return jsonify({"error": "유효한 파일이 없습니다."}), 400

    try:
        result = js_analysis.analyze(sources)
    except Exception as e:
        return jsonify({"error": f"분석 처리 오류: {e}"}), 500

    analysis_id = f"jsan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"
    jsanalysis_jobs[analysis_id] = {
        "result": result,
        "created_at": datetime.now().isoformat(),
    }

    return jsonify({
        "analysis_id": analysis_id,
        "files": result["files"],
        "function_count": len(result["functions"]),
        "module_edge_count": len(result["modules"]["edges"]),
        "module_unresolved_count": len(result["modules"]["unresolved"]),
    })


@app.route("/api/jsanalysis/<analysis_id>/modules")
def jsanalysis_modules(analysis_id):
    """파일 간 import/require/include/script-src 의존 관계 목록 조회.

    응답 JSON: edges(해소된 관계: from/to/kind/specifier), unresolved(미해소: from/specifier/kind/reason)
    """
    job = jsanalysis_jobs.get(analysis_id)
    if not job:
        return jsonify({"error": "분석 결과를 찾을 수 없습니다. (만료되었거나 잘못된 id)"}), 404
    modules = job["result"]["modules"]
    return jsonify({"edges": modules["edges"], "unresolved": modules["unresolved"]})


@app.route("/api/jsanalysis/<analysis_id>/search")
def jsanalysis_search(analysis_id):
    """분석 결과 내 함수 검색 — 쿼리파라미터 name(함수명)·file(파일명) 부분/대소문자 무관 일치."""
    job = jsanalysis_jobs.get(analysis_id)
    if not job:
        return jsonify({"error": "분석 결과를 찾을 수 없습니다. (만료되었거나 잘못된 id)"}), 404
    name_q = request.args.get("name", "")
    file_q = request.args.get("file", "")
    results = js_analysis.search_functions(job["result"], name_query=name_q, file_query=file_q)
    return jsonify({"results": results})


@app.route("/api/jsanalysis/<analysis_id>/function")
def jsanalysis_function(analysis_id):
    """함수 상세 조회 — 쿼리파라미터 id=함수id. defs/returns/out_calls/called_by 전체 반환."""
    job = jsanalysis_jobs.get(analysis_id)
    if not job:
        return jsonify({"error": "분석 결과를 찾을 수 없습니다. (만료되었거나 잘못된 id)"}), 404
    func = js_analysis.get_function(job["result"], request.args.get("id", ""))
    if func is None:
        return jsonify({"error": "함수를 찾을 수 없습니다."}), 404
    return jsonify({"function": func})


def _clamp_int(raw: str, default: int, lo: int, hi: int) -> int:
    """쿼리파라미터 문자열을 정수로 변환하고 [lo, hi] 범위로 자른다. 파싱 실패 시 default."""
    try:
        return max(lo, min(hi, int(raw)))
    except (TypeError, ValueError):
        return default


def _is_truthy(raw: str) -> bool:
    """쿼리파라미터 문자열이 "켜짐"을 뜻하는지 판별 (1/true/yes, 대소문자 무관)."""
    return (raw or "").strip().lower() in ("1", "true", "yes")


@app.route("/api/jsanalysis/<analysis_id>/graph")
def jsanalysis_graph(analysis_id):
    """mermaid 그래프 소스 반환.

    kind=call     : 호출 그래프. id 지정 시 해당 함수 중심 depth-hop 서브그래프
                    (depth: 1~5, 기본 1), 미지정 시 전체 그래프(최대 120개 노드).
                    cross_file_only=1이면 파일 경계를 넘는 호출 간선만 표시.
    kind=dataflow : 함수 내부 데이터플로우(파라미터→지역변수→return/외부호출). id 필수.
                    expand=1이면 import/require 등으로 해소된 호출 대상 함수의 데이터플로우까지
                    같은 그래프에 인라인 전개(파일 경계를 넘는 데이터 흐름 확인용).
    kind=module   : 업로드된 파일 간 import/require/include/script-src 의존 관계 그래프.
    """
    job = jsanalysis_jobs.get(analysis_id)
    if not job:
        return jsonify({"error": "분석 결과를 찾을 수 없습니다. (만료되었거나 잘못된 id)"}), 404
    kind = request.args.get("kind", "call")
    func_id = request.args.get("id") or None

    if kind == "dataflow":
        if not func_id:
            return jsonify({"error": "dataflow 그래프는 함수 id가 필요합니다."}), 400
        func = js_analysis.get_function(job["result"], func_id)
        if func is None:
            return jsonify({"error": "함수를 찾을 수 없습니다."}), 404
        expand = _is_truthy(request.args.get("expand", ""))
        mermaid = js_analysis.to_mermaid_dataflow(func, analysis=job["result"], expand=expand)
    elif kind == "module":
        mermaid = js_analysis.to_mermaid_module_graph(job["result"])
    else:
        depth = _clamp_int(request.args.get("depth", ""), default=1, lo=1, hi=5)
        cross_file_only = _is_truthy(request.args.get("cross_file_only", ""))
        mermaid = js_analysis.to_mermaid_call_graph(
            job["result"], center_id=func_id, depth=depth, cross_file_only=cross_file_only
        )

    return jsonify({"mermaid": mermaid})


def _find_free_port(host, start_port, max_tries=20):
    """start_port부터 순차적으로 bind 가능한(비어 있는) 포트를 탐색해 반환한다.
    max_tries 범위에서 빈 포트를 못 찾으면 None을 반환한다."""
    for port in range(start_port, min(start_port + max_tries, 65536)):
        # SO_REUSEADDR를 설정하지 않은 순수 소켓으로 bind를 시도해 실제 점유 여부를 확인
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((host, port))
                return port          # bind 성공 = 비어 있는 포트
            except OSError:
                continue             # 이미 사용 중 → 다음 포트로
    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Space Scan Dashboard")
    parser.add_argument("--host",  default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=7777)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    os.makedirs(REPORTS_DIR, exist_ok=True)

    # 요청 포트가 점유돼 있으면 순차적으로 빈 포트를 탐색
    chosen_port = _find_free_port(args.host, args.port)
    if chosen_port is None:
        print(f"\n  [!] {args.port}~{args.port + 19} 범위에서 사용 가능한 포트를 찾지 못했습니다.")
        print(f"  [!] --port 옵션으로 다른 포트를 지정해 주세요.\n")
        sys.exit(1)
    if chosen_port != args.port:
        print(f"\n  [!] 포트 {args.port}(이)가 사용 중이라 {chosen_port} 포트로 대체합니다.")

    print("\n  [*] Space Scan Dashboard")
    print(f"  [*] http://localhost:{chosen_port}\n")
    # 서버가 뜬 뒤 브라우저를 자동으로 열기 위해 1초 딜레이 적용
    t = threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{chosen_port}"))
    t.daemon = True
    t.start()
    app.run(host=args.host, port=chosen_port, debug=args.debug)
