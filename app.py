#!/usr/bin/env python3
"""
Space Scan - Flask 대시보드
사용법: python app.py [--port 7777]
"""
import os
import sys
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
                   _estimate_dump, _ensure_merge_deps)
from modules import MODULE_MAP, sqli_extract, excel_merge
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
              auth_headers: Optional[dict] = None,
              render: bool = False):
    job = scan_jobs[job_id]
    job["status"] = "running"
    results = []

    # default_pages 스택 사전 탐지 — 자동 탐지 결과 + 사용자 선택 합집합
    stacks_for_default = None
    if "default_pages" in modules:
        dp_mod, _ = MODULE_MAP["default_pages"]
        auto = dp_mod._detect_stacks(target, timeout, cookies, proxies=proxies,
                                     auth_headers=auth_headers)
        # 유효한 스택명만 허용 (TECH_REGISTRY에 없는 값 필터링)
        extra = [s for s in (user_stacks or []) if s in dp_mod.TECH_REGISTRY]
        stacks_for_default = list(set(auto) | set(extra))

    total_modules = len(modules)
    per_module = 100 / total_modules if total_modules else 0

    for module_idx, key in enumerate(modules):
        if job.get("cancelled"):
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
                                   render=render)
        res = run_single_module(mod, label, target, timeout, delay,
                                cookies, proxies=proxies, auth_headers=auth_headers,
                                **extra)
        results.append(res)
        job["results"] = results
        # 모듈 완료 시 정확한 진행률로 갱신 (하위 콜백의 99% 상한 해제)
        job["progress"] = int((module_idx + 1) / total_modules * 100)

    # 취소된 경우 보고서 생성 없이 cancelled 상태로 종료
    if job.get("cancelled"):
        job["status"] = "cancelled"
        job["completed_at"] = datetime.now().isoformat()
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

    if not target:
        return jsonify({"error": "target URL이 필요합니다."}), 400

    job_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{abs(hash(target)) % 9999:04d}"
    scan_jobs[job_id] = {
        "job_id": job_id, "target": target, "modules": modules,
        "status": "pending", "progress": 0, "current_module": None,
        "results": [], "risk": None,
        "html_report": None,
        "created_at": datetime.now().isoformat(),
    }
    threading.Thread(
        target=_run_scan,
        args=(job_id, target, modules, timeout, delay, max_pages,
              cookies or None, proxies, user_stacks, auth_headers or None, render),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>/status")
def scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    # 파일 경로는 클라이언트에 노출하지 않고 존재 여부만 전달
    safe = {k: v for k, v in job.items() if k != "html_report"}
    safe["has_html_report"] = bool(job.get("html_report") and os.path.exists(job["html_report"]))
    return jsonify(safe)


@app.route("/api/scans")
def list_scans():
    out = [
        {"job_id": jid, "target": j.get("target"), "status": j.get("status"),
         "risk": j.get("risk"), "created_at": j.get("created_at"),
         "completed_at": j.get("completed_at"),
         "has_html_report": bool(j.get("html_report") and os.path.exists(j["html_report"]))}
        for jid, j in scan_jobs.items()
    ]
    return jsonify(sorted(out, key=lambda x: x.get("created_at",""), reverse=True))


@app.route("/api/scan/<job_id>/cancel", methods=["POST"])
def cancel_scan(job_id):
    """실행 중인 스캔 취소 — cancelled 플래그를 세팅하면 _run_scan 루프가 다음 모듈 전환 시점에 중단"""
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job.get("status") not in ("pending", "running"):
        return jsonify({"error": "취소할 수 없는 상태입니다."}), 400
    job["cancelled"] = True
    return jsonify({"ok": True})


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
            "union_visible_idx": ctx.union_visible_idx,
            "unsupported_techniques": [],
        }
        # fingerprint 결과를 extracted["meta"]에 동기화 — INFO 시트 정확성 보장
        extracted = job["extracted"]
        extracted["meta"]["dbms"]             = ctx.dbms
        extracted["meta"]["context"]          = ctx.quote_context
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
    return action_id


def _save_excel_file(job: dict) -> None:
    """엑셀 파일만 기록 — 로그 없는 조용한 flush 전용.

    save_excel=False이거나 저장 실패 시 예외를 전파하지 않는다.
    """
    if not job.get("save_excel"):
        return
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        saved = sqli_extract.save_to_excel(
            job["extracted"], job["target"], REPORTS_DIR,
            excel_name=job.get("excel_name"),
        )
        job["excel_files"] = saved
    except Exception:
        pass  # flush 실패는 무시 — 추출 흐름 유지


def _save_excel_incremental(job: dict, action_id: str) -> None:
    """액션 완료 시점에 엑셀을 재저장하고 갱신 내역을 기록한다.

    save_excel=False인 job은 즉시 반환. 저장 실패(파일 락 등)는
    오류를 excel_updates에 기록하고 추출 흐름은 유지한다.
    """
    if not job.get("save_excel"):
        return
    try:
        os.makedirs(REPORTS_DIR, exist_ok=True)
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


def _cleanup_partial_list(action_id: str, extracted: dict) -> None:
    """중단된 리스트 액션의 부분 결과를 extracted에서 제거.

    협조적 break 경로에서 _list_items가 부분 목록을 반환 후 대입되므로
    캐시 히트 방지를 위해 해당 키를 초기화한다. dump는 이어받기를 유지하므로 건드리지 않는다.
    """
    if action_id == "list_dbs":
        extracted["databases"] = []
    elif action_id.startswith("list_tables:"):
        db = action_id[len("list_tables:"):]
        if extracted.get("tables"):
            extracted["tables"].pop(db, None)
    elif action_id.startswith("list_columns:"):
        col_key = action_id[len("list_columns:"):]
        if extracted.get("columns"):
            extracted["columns"].pop(col_key, None)


def _finalize_cancelled(job: dict) -> None:
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
        _save_excel_file(job)
        job["cancelled"] = False
        job["status"] = "ready"


def _run_extract_action(job_id: str, action_fn: Callable[[dict], None],
                        action_id: str) -> None:
    """액션 래퍼 — current_action_id 좀비 차단 (try/finally로 None 복귀).

    action_fn 내부에서 예외가 발생해도 current_action_id가 반드시 비워져
    다음 액션 호출이 가능하도록 보장한다.
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
            _cleanup_partial_list(action_id, job.get("extracted") or {})
            _finalize_cancelled(job)
        else:
            _save_excel_incremental(job, action_id)
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
        _cleanup_partial_list(action_id, job.get("extracted") or {})
        _finalize_cancelled(job)
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

    speed = int(data.get("speed", 4))
    speed = max(1, min(6, speed))
    delay = EXTRACT_SPEED_DELAY[speed]
    timeout = int(data.get("timeout", 10))

    cookies_str = (data.get("cookies") or "").strip()
    cookies = parse_cookie_string(cookies_str) if cookies_str else {}
    auth_headers = data.get("auth_headers") or {}
    if not isinstance(auth_headers, dict):
        return jsonify({"error": "auth_headers는 dict 형식이어야 합니다."}), 400

    union_hex = bool(data.get("union_hex", True))

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
        auth_headers=auth_headers,
        base64_encode=base64_encode,
        union_hex=union_hex,
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
            ctx.dbms          = ctx_meta.get("dbms") or ctx.dbms
            ctx.quote_context = ctx_meta.get("context", ctx.quote_context)
            if ctx.technique == "union":
                loaded_vis = ctx_meta.get("union_visible_idx", -1)
                if loaded_vis >= 0:
                    ctx.union_visible_manual = loaded_vis

    now = datetime.now()
    job_id = f"extract_{now.strftime('%Y%m%d_%H%M%S')}_{abs(hash(target)) % 9999:04d}"

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
        "fingerprint": None,
        "extracted": init_ext,
        "save_excel": save_excel,
        "excel_name": excel_name_val,   # 사용자 입력 이름 (파일명 결정)
        "excel_files": [],
        "excel_updates": [],
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
    }
    return jsonify(out)


def _dispatch_extract_action(action: str, data: dict, ctx, extracted: dict, job: dict):
    """액션별 (action_id, fn) 쌍을 반환한다.

    에러·캐시 히트·dump estimate 등 조기 종료 케이스는 Flask Response를 직접 반환.
    호출부에서 isinstance(result, tuple) and isinstance(result[0], str)로 구분.
    """
    if action == "dbms_info":
        action_id = "dbms_info"

        def fn(j):
            cb = _make_extract_progress_cb(j)
            info = sqli_extract.extract_dbms_info(ctx, progress_cb=cb)
            extracted["dbms_info"] = info

    elif action == "databases":
        action_id = "list_dbs"
        # 캐시 hit — 이미 추출된 경우 즉시 반환 (current_action_id 점유 안 함)
        if extracted.get("databases"):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            cb = _make_extract_progress_cb(j)
            extracted["databases"] = sqli_extract.list_databases(ctx, progress_cb=cb)

    elif action == "tables":
        db = (data.get("database") or "").strip()
        if not db:
            return jsonify({"error": "database 필요"}), 400
        action_id = f"list_tables:{db}"
        if db in (extracted.get("tables") or {}):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            cb = _make_extract_progress_cb(j)
            extracted.setdefault("tables", {})[db] = sqli_extract.list_tables(
                ctx, db, progress_cb=cb
            )

    elif action == "columns":
        db = (data.get("database") or "").strip()
        tbl = (data.get("table") or "").strip()
        if not db or not tbl:
            return jsonify({"error": "database/table 필요"}), 400
        col_key = f"{db}.{tbl}"
        action_id = f"list_columns:{col_key}"
        if col_key in (extracted.get("columns") or {}):
            return jsonify({"ok": True, "cached": True})

        def fn(j):
            cb = _make_extract_progress_cb(j)
            extracted.setdefault("columns", {})[col_key] = sqli_extract.list_columns(
                ctx, db, tbl, progress_cb=cb
            )

    elif action == "dump":
        db = (data.get("database") or "").strip()
        tbl = (data.get("table") or "").strip()
        cols = data.get("columns") or []
        if not db or not tbl or not cols:
            return jsonify({"error": "database/table/columns 필요"}), 400
        confirm = bool(data.get("confirm", False))
        action_id = f"dump:{db}.{tbl}"

        # 1단계: COUNT 추출 후 시간 추정 (current_action_id 점유 안 함)
        if not confirm:
            total = sqli_extract.count_table(ctx, db, tbl) or 0
            job["estimate_total"] = total
            # 이어받기: 같은 컬럼 구성의 부분 데이터가 있으면 남은 행 기준으로 추정
            _key = f"{db}.{tbl}"
            _existing = (extracted.get("dumps") or {}).get(_key)
            resume_from = (len(_existing["rows"])
                           if _existing and _existing.get("columns") == list(cols) else 0)
            remaining = max(total - resume_from, 0)
            est = _estimate_dump(ctx, remaining)
            job["estimate"] = est
            return jsonify({"ok": True, "estimate": est, "resume_from": resume_from})

        # 2단계: 사용자 확인 후 본격 실행 (estimate에서 받은 total 재사용)
        cached_total = job.get("estimate_total")

        def fn(j):
            key = f"{db}.{tbl}"
            existing = (extracted.get("dumps") or {}).get(key)
            # 같은 컬럼 구성의 부분 데이터가 있으면 기존 rows 재사용하여 이어받기
            if existing and existing.get("columns") == list(cols):
                rows_acc = existing["rows"]
            else:
                # 새 추출 — rows_acc 미리 등록 (취소 시에도 누적 행 보존)
                rows_acc = []
                extracted.setdefault("dumps", {})[key] = {
                    "columns": list(cols), "rows": rows_acc
                }

            base_cb = _make_extract_progress_cb(j)
            _flush_ts = [time.time()]  # 클로저 내 mutable 컨테이너

            def flush_cb(current: int, total: int) -> None:
                base_cb(current, total)
                # 30초마다 조용한 체크포인트 저장 (로그 없음)
                now = time.time()
                if now - _flush_ts[0] >= 30:
                    _flush_ts[0] = now
                    _save_excel_file(j)

            sqli_extract.dump_table(ctx, db, tbl, list(cols),
                                    total=cached_total,
                                    progress_cb=flush_cb,
                                    rows_out=rows_acc)
            # rows_acc는 extracted["dumps"][key]["rows"]와 동일 객체 — 별도 대입 불필요
    else:
        return jsonify({"error": f"알 수 없는 action: {action}"}), 400

    return action_id, fn


@app.route("/api/extract/<job_id>/action", methods=["POST"])
def extract_action(job_id):
    """액션 트리거 — 백그라운드 실행 + 동시 호출 시 409 Conflict.

    action ∈ {dbms_info | databases | tables | columns | dump}
    dump는 confirm 미설정 시 estimate만 채우고 즉시 응답 (current_action_id 점유 안 함).
    """
    job = extract_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Not found"}), 404
    if job["status"] not in ("ready", "extracting"):
        return jsonify({"error": f"액션 호출 불가 상태: {job['status']}"}), 400

    data = request.json or {}
    action = (data.get("action") or "").lower()
    ctx = job["ctx"]
    extracted = job["extracted"]

    # 액션별 action_id + 실행 함수 결정 (에러·캐시·estimate는 즉시 응답)
    dispatch = _dispatch_extract_action(action, data, ctx, extracted, job)
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
        target=_run_extract_action, args=(job_id, fn, action_id), daemon=True
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

    # technique 또는 dbms 중 하나는 있어야 함
    if not technique and not dbms:
        return jsonify({"error": "technique 또는 dbms 필요"}), 400
    if technique and technique not in ("error", "boolean", "union"):
        return jsonify({"error": "technique은 error/boolean/union"}), 400

    _VALID_DBMS = {"MySQL", "MariaDB", "MSSQL", "PostgreSQL", "Oracle", "SQLite"}
    if dbms and dbms not in _VALID_DBMS:
        return jsonify({"error": f"지원 DBMS: {', '.join(sorted(_VALID_DBMS))}"}), 400

    ctx = job["ctx"]
    effective_technique = technique or ctx.technique
    # SQLite + Error 충돌 가드
    if dbms == "SQLite" and effective_technique == "error":
        return jsonify({"error": "SQLite는 Error-based 미지원 — 기법을 boolean 또는 union으로 변경하세요."}), 400

    if dbms:
        ctx.dbms = dbms
    if technique:
        ctx.technique = technique
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Space Scan Dashboard")
    parser.add_argument("--host",  default="127.0.0.1")
    parser.add_argument("--port",  type=int, default=7777)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    os.makedirs(REPORTS_DIR, exist_ok=True)
    print("\n  [*] Space Scan Dashboard")
    print(f"  [*] http://localhost:{args.port}\n")
    # 서버가 뜬 뒤 브라우저를 자동으로 열기 위해 1초 딜레이 적용
    t = threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{args.port}"))
    t.daemon = True
    t.start()
    app.run(host=args.host, port=args.port, debug=args.debug)
