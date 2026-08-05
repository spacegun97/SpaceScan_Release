# recon.py — 정보수집(OSINT) 모듈

## 개요

대상 도메인의 서브도메인·DNS 레코드·인증서·서브도메인별 URL·열린 포트를 **순수 패시브**로 수집한다.

**하드 룰: 대상 도메인·서브도메인·서버로는 어떤 요청도 직접 보내지 않는다.** 직접 접속하는 호스트는 아래 6개뿐이다.

| 소스 | 호스트 | 조회 내용 |
|------|--------|----------|
| `crtsh` | crt.sh | CT(Certificate Transparency) 로그 → 서브도메인 + 인증서 메타 |
| `wayback` | web.archive.org | Wayback Machine CDX 인덱스 → 서브도메인 + 아카이브 URL |
| `commoncrawl` | index.commoncrawl.org | Common Crawl 인덱스(CDX, 무키) → 서브도메인 + 관측 URL |
| `urlscan` | urlscan.io | 기존 공개 스캔 결과 검색(search API, 무키·읽기 전용) → 서브도메인 + 관측 URL |
| `archivepaths` | web.archive.org | robots.txt/sitemap.xml **아카이브 스냅샷 본문** 파싱 → 선언된 엔드포인트 경로 (대상이 아닌 아카이브에서 읽음) |
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
| `sources` | `List[str]` | `SOURCE_KEYS = ("crtsh", "wayback", "dns", "commoncrawl", "urlscan", "archivepaths", "internetdb")` 부분집합 |
| `timeout` | `int` | 각 HTTP/DNS 요청 타임아웃(초) |
| `max_subdomains` | `int` | DNS 확인 대상 서브도메인 상한 (기본 200, 범위 10~1000) |
| `progress_cb` | `Callable[[int, int], None]` | `(current, total=100)` 형식의 백분율 콜백 — 단계 경계마다 호출 |
| `stop_event` | `threading.Event` | set되면 `modules._cancel.ScanCancelled`를 던져 즉시 중단 |

`"internetdb"`가 `sources`에 있으면 IP 확보를 위해 `"dns"`를 자동 포함한다.

반환 dict:

| 키 | 타입 | 설명 |
|----|------|------|
| `domain` | `str` | 대상 도메인 |
| `subdomains` | `List[dict]` | `{"host", "alive", "sources"}` — `sources`는 발견 출처(`crtsh`/`wayback`/`commoncrawl`/`urlscan`) 목록 |
| `dns_records` | `Dict[str, Dict[str, List[str]]]` | `{host: {record_type: [값, ...]}}` |
| `certificates` | `List[dict]` | `{"id", "common_name", "issuer", "not_before", "not_after"}` |
| `subdomain_urls` | `Dict[str, List[dict]]` | `{host: [{"url", "sources"}, ...]}` — 서브도메인별 그룹핑된 URL. `sources`는 `wayback`/`commoncrawl`/`urlscan`/`robots`/`sitemap` 조합. 호스트당 `MAX_URLS_PER_HOST`(200), 전체 `MAX_TOTAL_URLS`(3000) 상한 적용 |
| `ports` | `Dict[str, dict]` | `{ip: {"ip","ports","hostnames","cpes","tags","vulns"}}` |
| `errors` | `List[dict]` | `{"source", "message"}` — crt.sh/Wayback/Common Crawl/urlscan.io 조회 실패 시에만 기록 |
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
| `url_total` | `subdomain_urls`에 최종 포함된 URL 총수 |
| `url_truncated` | 호스트당/전체 URL 상한 초과로 일부가 생략됐는지 여부 |

### `query_crtsh(domain, timeout, session) -> dict`

crt.sh JSON API(`output=json`, `q=%.{domain}`) 조회. 반환: `{"subdomains": set, "certificates": list, "error": str|None}`. 실패해도 예외를 올리지 않고 `error` 필드로 알린다.

### `query_wayback(domain, timeout, session) -> dict`

Wayback CDX API(`matchType=domain`)로 도메인 + 전체 서브도메인의 아카이브 URL을 한 번에 조회. 반환: `{"subdomains": set, "urls": list, "error": str|None}`.

### `query_commoncrawl(domain, timeout, session) -> dict`

`collinfo.json`에서 최신 `CC_INDEX_COUNT`(3)개 크롤 인덱스를 확보(실패 시 하드코딩 fallback)한 뒤, 각 인덱스의 CDX API를 `matchType=domain`으로 조회한다(JSONL 응답 — Wayback CDX와 달리 헤더 행 없음). 개별 인덱스 조회 실패는 건너뛰고 나머지로 계속 진행. 반환: `{"subdomains": set, "urls": list, "error": str|None}`.

### `query_urlscan(domain, timeout, session) -> dict`

urlscan.io search API(`/api/v1/search/?q=domain:{domain}`, 무키)로 기존 공개 스캔 결과를 검색만 한다 — 스캔 제출(`/scan`)은 호출하지 않는다. 반환: `{"subdomains": set, "urls": list, "error": str|None}`.

### `fetch_archive_paths(hosts, domain, timeout, session, stop_event=None) -> List[Tuple[str, str]]`

`hosts` 중 apex(`domain`) 우선 정렬 후 `MAX_ROBOTS_HOSTS`(25)개까지, 각 호스트의 robots.txt/sitemap.xml **아카이브 스냅샷 본문**을 `web.archive.org`에서 읽어 엔드포인트를 추출한다(`_wayback_snapshot_body()` — availability API로 최신 스냅샷 확정 후 `id_` raw 접미사로 본문 조회). robots.txt의 `Disallow`/`Allow`/`Sitemap` 지시문, sitemap.xml의 `<loc>` 태그를 파싱하며, 사이트맵 인덱스(`<sitemapindex>`)는 하위 사이트맵을 `MAX_SITEMAP_FETCH`(10)개까지 1단계 재귀 조회한다. 반환: `[(url, "robots"|"sitemap"), ...]`.

### `resolve_dns(host, resolver, record_types) -> Dict[str, List[str]]`

`_make_resolver()`가 생성한 리졸버(공용 DNS 전용, `configure=False`로 OS 설정 무시)로 지정 레코드 타입만 조회. NXDOMAIN/NoAnswer/Timeout은 해당 타입만 건너뛰고 계속 진행한다.

- apex(입력 도메인): `APEX_RECORD_TYPES = (A, AAAA, MX, NS, TXT, SOA, CAA)`
- 서브도메인: `SUBDOMAIN_RECORD_TYPES = (A, AAAA, CNAME)` — 질의량 절감

### `query_internetdb(ip, timeout, session) -> dict | None`

`internetdb.shodan.io/{ip}` 무키 조회. 404(데이터 없음)면 `None`. 실패 시에도 예외 없이 `None` 반환(개별 IP 단위 실패는 조용히 건너뜀).

### `generate_recon_html(result, output_dir) -> str`

정보수집 결과를 다크 테마 HTML 리포트로 저장하고 절대경로를 반환한다. 파일명: `recon_{domain_}_{YYYYMMDD_HHMMSS}.html`. 서브도메인/DNS/인증서/서브도메인별 URL/포트 5개 섹션 + 상단 통계 카드로 구성.

### `save_recon_to_excel(result, output_dir) -> str`

정보수집 결과를 xlsx로 저장하고 절대경로를 반환한다. 파일명: `recon_{domain_}_{YYYYMMDD_HHMMSS}.xlsx`. 시트 구성: `INFO` / `Subdomains` / `DNS` / `Certificates` / `SubdomainURLs` / `Ports`. 수식 인젝션 방어: `=`/`+`/`-`/`@`/탭/CR로 시작하는 문자열에 `'` prefix 부착(`_safe_cell`).

---

## 알고리즘 상세

### 오케스트레이션 흐름 (`run_recon`)

```
1. crt.sh 조회              → 서브도메인 집합 ∪=, 인증서 목록 확보              [progress 6%]
2. Wayback CDX 조회         → 서브도메인 집합 ∪=, URL 확보(source=wayback)     [progress 12%]
3. Common Crawl 조회        → 서브도메인 집합 ∪=, URL 확보(source=commoncrawl) [progress 20%]
4. urlscan.io 조회          → 서브도메인 집합 ∪=, URL 확보(source=urlscan)    [progress 26%]
5. 아카이브 robots/sitemap 파싱 → 각 서브도메인의 robots.txt/sitemap.xml
   아카이브 본문에서 엔드포인트 추출(source=robots|sitemap)                  [progress 45%]
6. 서브도메인 정렬 후 max_subdomains로 절단(truncate)
7. DNS 조회 (공용 리졸버) → 절단된 각 host를 A/AAAA/(AAAA/CNAME) 조회
   → 성공한 host는 dns_records에 기록, alive=True, A/AAAA 값을 resolved_ips에 누적  [progress 45→85%]
8. InternetDB 조회 → resolved_ips 각각에 대해 포트/서비스 정보 조회              [progress 85→100%]
```

각 반복 지점에서 `wait_or_cancel(stop_event, 0)`으로 중단 요청을 즉시 검사한다(`modules/_cancel.py` 재사용).

수집된 URL은 `url_sources: Dict[str, Set[str]]`에 URL별 발견 소스로 누적된 뒤, 마지막에 호스트(`urlparse(url).netloc`)로 그룹핑되어 `subdomain_urls`로 변환된다(호스트당/전체 상한 적용, 초과분은 `meta.url_truncated=True`로 표시).

### 스코프 필터링

crt.sh/Wayback/Common Crawl/urlscan.io에서 얻은 이름 중 대상 도메인 자신이거나 그 서브도메인인 것만(`_is_in_scope`) 채택한다 — CT 로그·CDX 인덱스·검색 결과에 섞여 들어올 수 있는 무관 도메인을 배제한다. `subdomain_urls`로 그룹핑할 때도 각 URL의 호스트에 동일한 스코프 필터를 적용한다.

### 서브도메인 출처 병합

`origin: Dict[str, Set[str]]`에 호스트별 발견 소스(`crtsh`/`wayback`/`commoncrawl`/`urlscan`)를 누적하여 `subdomains[].sources`로 노출한다 — 동일 호스트가 여러 소스에서 발견되면 모두 표기된다. `archivepaths`(robots/sitemap)는 URL 수집 전용 소스로, 새 서브도메인을 발견하지 않고 이미 알려진 호스트의 엔드포인트만 보강한다.

---

## 엣지 케이스 처리

| 상황 | 처리 |
|------|------|
| crt.sh/Wayback/Common Crawl/urlscan.io 요청 실패(네트워크/파싱 오류) | 해당 소스만 건너뛰고 `errors`에 기록, 나머지 소스는 계속 진행 |
| Common Crawl 일부 인덱스만 실패 | 실패한 인덱스 id를 `error`에 나열하고 나머지 인덱스 결과로 계속 진행 (전체 실패 시에만 소스 전체 실패로 취급) |
| Wayback availability API에 robots.txt/sitemap.xml 스냅샷 없음 | 해당 호스트는 조용히 건너뜀 (`errors`에 기록하지 않음 — 정상적으로 발생 가능한 상황) |
| sitemap.xml 파싱 실패(XML 형식 오류 등) | 해당 사이트맵만 건너뛰고 나머지 호스트/사이트맵 계속 진행 |
| DNS NXDOMAIN/NoAnswer/Timeout | 해당 레코드 타입만 결과에서 생략, 다음 타입 계속 조회 |
| InternetDB 404 또는 조회 실패 | 해당 IP는 `ports`에서 생략 (개별 실패는 `errors`에 기록하지 않음) |
| 서브도메인 수가 `max_subdomains` 초과 | 정렬 후 상한까지만 DNS 조회, `meta.subdomain_truncated=True` |
| URL 수가 호스트당/전체 상한 초과 | 상한까지만 `subdomain_urls`에 포함, `meta.url_truncated=True` |
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
