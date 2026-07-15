# recon.py — 정보수집(OSINT) 모듈

## 개요

대상 도메인의 서브도메인·DNS 레코드·인증서·아카이브 URL·열린 포트를 **순수 패시브**로 수집한다.

**하드 룰: 대상 도메인·서브도메인·서버로는 어떤 요청도 직접 보내지 않는다.** 직접 접속하는 호스트는 아래 4개뿐이다.

| 소스 | 호스트 | 조회 내용 |
|------|--------|----------|
| `crtsh` | crt.sh | CT(Certificate Transparency) 로그 → 서브도메인 + 인증서 메타 |
| `wayback` | web.archive.org | Wayback Machine CDX 인덱스 → 서브도메인 + 아카이브 URL (스냅샷 본문 미조회) |
| `dns` | 8.8.8.8 / 1.1.1.1 | 공용 DNS 리졸버로 레코드 조회 (대상 네임서버 직접 질의 안 함 — 캐시 미스 시 재귀 질의는 리졸버가 대신 수행) |
| `internetdb` | internetdb.shodan.io | Shodan이 사전 수집해 둔 IP별 포트 정보 (무키, 읽기 전용 — 온디맨드 스캔 아님) |

탐지 모듈(`scan()` 인터페이스)과 무관한 **별도 모드**다. `sqli_extract.py`/`excel_merge.py`와 같이 `MODULE_MAP`에 등록되지 않고 `app.py`에서 직접 호출된다.

---

## 공개 함수

### `normalize_domain(raw) -> str`

사용자 입력(도메인 또는 URL 형태)에서 스킴·포트·경로를 제거하고 호스트명만 추출한다. 형식이 올바르지 않으면 `ValueError`.

### `run_recon(domain, sources, *, timeout=8, max_subdomains=200, progress_cb=None, stop_event=None) -> dict`

| 인자 | 타입 | 설명 |
|------|------|------|
| `domain` | `str` | `normalize_domain()`을 거친 대상 도메인 |
| `sources` | `List[str]` | `SOURCE_KEYS = ("crtsh", "wayback", "dns", "internetdb")` 부분집합 |
| `timeout` | `int` | 각 HTTP/DNS 요청 타임아웃(초) |
| `max_subdomains` | `int` | DNS 확인 대상 서브도메인 상한 (기본 200, 범위 10~1000) |
| `progress_cb` | `Callable[[int, int], None]` | `(current, total=100)` 형식의 백분율 콜백 — 단계 경계마다 호출 |
| `stop_event` | `threading.Event` | set되면 `modules._cancel.ScanCancelled`를 던져 즉시 중단 |

`"internetdb"`가 `sources`에 있으면 IP 확보를 위해 `"dns"`를 자동 포함한다.

반환 dict:

| 키 | 타입 | 설명 |
|----|------|------|
| `domain` | `str` | 대상 도메인 |
| `subdomains` | `List[dict]` | `{"host", "alive", "sources"}` — `sources`는 발견 출처(`crtsh`/`wayback`) 목록 |
| `dns_records` | `Dict[str, Dict[str, List[str]]]` | `{host: {record_type: [값, ...]}}` |
| `certificates` | `List[dict]` | `{"id", "common_name", "issuer", "not_before", "not_after"}` |
| `archive_urls` | `List[str]` | Wayback 아카이브 URL (최대 500개) |
| `ports` | `Dict[str, dict]` | `{ip: {"ip","ports","hostnames","cpes","tags","vulns"}}` |
| `errors` | `List[dict]` | `{"source", "message"}` — crt.sh/Wayback 조회 실패 시에만 기록 |
| `meta` | `dict` | 아래 표 |

`meta` 필드:

| 키 | 설명 |
|----|------|
| `sources_used` | 실제 사용된 소스 목록 (정렬됨) |
| `started_at` / `finished_at` | ISO 타임스탬프 |
| `subdomain_total` | 발견된 서브도메인 총수(도메인 자신 포함) |
| `subdomain_resolved` | DNS 확인을 시도한 서브도메인 수 (`max_subdomains` 적용 후) |
| `subdomain_truncated` | 상한 초과로 잘렸는지 여부 |
| `max_subdomains` | 적용된 상한값 |
| `resolved_ip_count` | DNS로 확인된 고유 IP 수 |

### `query_crtsh(domain, timeout, session) -> dict`

crt.sh JSON API(`output=json`, `q=%.{domain}`) 조회. 반환: `{"subdomains": set, "certificates": list, "error": str|None}`. 실패해도 예외를 올리지 않고 `error` 필드로 알린다.

### `query_wayback(domain, timeout, session) -> dict`

Wayback CDX API(`matchType=domain`)로 도메인 + 전체 서브도메인의 아카이브 URL을 한 번에 조회. 반환: `{"subdomains": set, "urls": list, "error": str|None}`.

### `resolve_dns(host, resolver, record_types) -> Dict[str, List[str]]`

`_make_resolver()`가 생성한 리졸버(공용 DNS 전용, `configure=False`로 OS 설정 무시)로 지정 레코드 타입만 조회. NXDOMAIN/NoAnswer/Timeout은 해당 타입만 건너뛰고 계속 진행한다.

- apex(입력 도메인): `APEX_RECORD_TYPES = (A, AAAA, MX, NS, TXT, SOA, CAA)`
- 서브도메인: `SUBDOMAIN_RECORD_TYPES = (A, AAAA, CNAME)` — 질의량 절감

### `query_internetdb(ip, timeout, session) -> dict | None`

`internetdb.shodan.io/{ip}` 무키 조회. 404(데이터 없음)면 `None`. 실패 시에도 예외 없이 `None` 반환(개별 IP 단위 실패는 조용히 건너뜀).

### `generate_recon_html(result, output_dir) -> str`

정보수집 결과를 다크 테마 HTML 리포트로 저장하고 절대경로를 반환한다. 파일명: `recon_{domain_}_{YYYYMMDD_HHMMSS}.html`. 서브도메인/DNS/인증서/아카이브 URL/포트 5개 섹션 + 상단 통계 카드로 구성.

### `save_recon_to_excel(result, output_dir) -> str`

정보수집 결과를 xlsx로 저장하고 절대경로를 반환한다. 파일명: `recon_{domain_}_{YYYYMMDD_HHMMSS}.xlsx`. 시트 구성: `INFO` / `Subdomains` / `DNS` / `Certificates` / `ArchiveURLs` / `Ports`. 수식 인젝션 방어: `=`/`+`/`-`/`@`/탭/CR로 시작하는 문자열에 `'` prefix 부착(`_safe_cell`).

---

## 알고리즘 상세

### 오케스트레이션 흐름 (`run_recon`)

```
1. crt.sh 조회        → 서브도메인 집합 ∪=, 인증서 목록 확보         [progress 10%]
2. Wayback CDX 조회   → 서브도메인 집합 ∪=, 아카이브 URL 확보        [progress 20%]
3. 서브도메인 정렬 후 max_subdomains로 절단(truncate)
4. DNS 조회 (공용 리졸버) → 절단된 각 host를 A/AAAA/(AAAA/CNAME) 조회
   → 성공한 host는 dns_records에 기록, alive=True, A/AAAA 값을 resolved_ips에 누적  [progress 20→80%]
5. InternetDB 조회 → resolved_ips 각각에 대해 포트/서비스 정보 조회              [progress 80→100%]
```

각 반복 지점에서 `wait_or_cancel(stop_event, 0)`으로 중단 요청을 즉시 검사한다(`modules/_cancel.py` 재사용).

### 스코프 필터링

crt.sh/Wayback에서 얻은 이름 중 대상 도메인 자신이거나 그 서브도메인인 것만(`_is_in_scope`) 채택한다 — CT 로그·CDX 인덱스에 섞여 들어올 수 있는 무관 도메인을 배제한다.

### 서브도메인 출처 병합

`origin: Dict[str, Set[str]]`에 호스트별 발견 소스(`crtsh`/`wayback`)를 누적하여 `subdomains[].sources`로 노출한다 — 동일 호스트가 여러 소스에서 발견되면 모두 표기된다.

---

## 엣지 케이스 처리

| 상황 | 처리 |
|------|------|
| crt.sh/Wayback 요청 실패(네트워크/파싱 오류) | 해당 소스만 건너뛰고 `errors`에 기록, 나머지 소스는 계속 진행 |
| DNS NXDOMAIN/NoAnswer/Timeout | 해당 레코드 타입만 결과에서 생략, 다음 타입 계속 조회 |
| InternetDB 404 또는 조회 실패 | 해당 IP는 `ports`에서 생략 (개별 실패는 `errors`에 기록하지 않음) |
| 서브도메인 수가 `max_subdomains` 초과 | 정렬 후 상한까지만 DNS 조회, `meta.subdomain_truncated=True` |
| `sources`에 `internetdb`만 포함 | `dns`를 자동 포함(IP 확보 필수) |
| 잘못된 도메인 형식 입력 | `normalize_domain()`에서 `ValueError` |
| 중단 요청(`stop_event.set()`) | 각 단계 반복 지점에서 `ScanCancelled` 발생, 즉시 중단 |

---

## 의존성

| 패키지 | 용도 | 설치 |
|--------|------|------|
| `requests` | crt.sh/Wayback/InternetDB HTTP 조회 | 기본 의존성 (`_ensure_deps()`) |
| `dnspython` (import명 `dns`) | 공용 리졸버 DNS 조회 | `_ensure_recon_deps()` lazy 설치 |
| `openpyxl` | Excel 결과 저장 | `_ensure_recon_deps()` lazy 설치 |
