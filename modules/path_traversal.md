# path_traversal.py

**OWASP:** A01:2021 - Broken Access Control (Path Traversal)
**목적:** 크롤링 중 수집된 파라미터 값과 URL path에서 경로 관련 패턴을 패시브하게 탐지한다. finding은 LFI / SSRF / 파일 다운로드 등의 수동 검증 단서로 활용한다. 모든 finding은 HIGH.

---

## 동작 방식 (2단계 파이프라인)

### Phase 1 — BFS 크롤링 (엔드포인트 수집)

sql_injection 모듈과 동일하게 `_crawl.py`를 공유한다.

1. BFS 시작 전 `robots.txt`와 `sitemap.xml`에서 같은 도메인 URL을 추가 시드로 수집한다. `sitemap.xml`은 `<sitemapindex>` 감지 시 하위 sitemap URL을 재귀 조회한다(깊이 3, 자식 20개 상한).
2. 입력 URL + 시드를 큐에 넣고 BFS 방식으로 같은 도메인 내 URL을 방문한다.
3. 응답 분류는 HTTP 상태 코드와 무관하므로 403·404 등 비200 응답도 CT·본문 스니핑 결과에 따라 파싱된다. HTML 응답에서는 `href`/`src`/`action`(따옴표·미따옴표), `data-url`/`data-href`/`data-action`/`data-src`, `srcset`, `<meta http-equiv="refresh">` url= 값을 추출하고, 스크립트 응답에서는 `fetch`/`axios` 등 JS 호출 URL을 추출해 큐에 추가한다.
4. `allow_redirects=True`로 요청, 리다이렉트 후 외부 도메인 이탈 시 해당 페이지 제외.
5. 로그아웃 경로(`logout`/`log-out`/`signout`/`sign-out`)는 큐 추가 단계에서 제외.
6. 동일 서명(path + 쿼리 파라미터명 집합)의 URL은 최대 3회까지만 방문하여 페이지네이션 트랩을 방지한다. 요청 실패 시 `Timeout`·`ChunkedEncodingError`에 한해 최대 2회 재시도한다.
7. `max_pages` 도달 시 크롤링 종료 (기본값 100).

### Phase 2 — 경로 패턴 매칭 (패시브, 추가 HTTP 요청 없음)

수집된 페이지에서 두 가지 검사를 수행한다.

#### (A) 파라미터 값 검사 (메인)

`_sqli_util.parse_input_points()`를 재사용하여 입력 포인트를 파싱, 각 파라미터 값에 정규식 패턴을 적용한다.

수집 대상:
- URL 쿼리 파라미터 값
- `<a href>` 쿼리 파라미터 값 (HTML 페이지)
- `<form>` 필드 값 (hidden 포함, CSRF 토큰 성격 필드 제외, HTML 페이지)
- `data-url/href/action/src` 속성의 쿼리 파라미터 값 (HTML 페이지)
- JS 호출 URL(`fetch`/`XMLHttpRequest`/`$.ajax`/`axios` 등)의 쿼리 파라미터 값 (HTML·스크립트 페이지)
- JS POST 바디 파라미터 키 (`JSON.stringify({...})` / `axios.post(url, {...})` / `$.post(url, {...})` 등, HTML·스크립트 페이지)

#### (B) URL path 검사 (보조)

크롤러가 방문한 URL의 path 부분에 `traversal` / `wrapper_scheme` 패턴이 있는지 검사한다. 오탐 최소화를 위해 두 카테고리만 검사한다.

---

## 탐지 패턴

파라미터 값 검사(A)와 URL path 검사(B)에 적용되는 패턴이 다르다.

### 파라미터 값 검사(A) 전용 + URL path 검사(B) 공용

| 카테고리 | 패턴 (요지) | 예시 | 수동 테스트 힌트 |
|---------|------------|------|----------------|
| `traversal` | `../`, `..\`, `%2e%2e/`, `%252e%252e`, `..;/`, `..%00` | `../../etc/passwd` | LFI / Path Traversal |
| `wrapper_scheme` | `file://`, `php://`, `data://`, `expect://`, `phar://`, `zip://`, `gopher://`, `dict://`, `ldap://` | `file:///etc/passwd`, `php://filter/...` | SSRF / LFI / Protocol Wrapper |
| `windows_abs` | `\b[A-Z]:[\\/]` | `C:\Users\admin\file.txt` | LFI / 파일 다운로드 |
| `unc_path` | `\\server\share` | `\\192.168.1.1\c$` | SSRF / UNC Path 접근 |
| `unix_system` | `/etc/`, `/var/`, `/usr/`, `/home/`, `/root/`, `/proc/`, `/sys/`, `/boot/`, `/tmp/`, `/dev/` | `/etc/passwd`, `/var/log/access.log` | LFI / 시스템 파일 접근 |

### 파라미터 값 검사(A) 전용 (광범위 탐지 — FP 감수·미탐 최소화)

| 카테고리 | 패턴 (요지) | 예시 | 수동 테스트 힌트 |
|---------|------------|------|----------------|
| `ssrf_url` | `http://`, `https://` | `?url=http://169.254.169.254`, `?next=https://attacker.com` | SSRF / 오픈리다이렉트 |
| `ip_addr` | IPv4 `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` / IPv6 콜론 그룹 2개 이상 (옥텟 검증 없음) | `?host=10.20.50.20`, `?target=192.168.0.1/path.jsp` | SSRF / 내부망 접근 |
| `path_value` | `/` 또는 `\` 경로 구분자 존재 | `?file=/normal/page`, `?dir=dir\sub` | 파일 경로 / LFI |
| `filename` | `word.ext` 형태 (확장자 1~6자) | `?page=config.xml`, `?view=test.jsp` | 파일 접근 / LFI |

**적용 범위:** `ssrf_url` / `ip_addr` / `path_value` / `filename` 4개 패턴은 **파라미터 값에만** 적용된다. URL path 직접 검사(`_check_path`)에는 `traversal` / `wrapper_scheme` 2종만 적용되어, 일반 URL path(`/api/users/`)에서 슬래시·확장자에 의한 오탐이 발생하지 않는다.

**중복 처리:** `(url, method, param)` 기준으로 finding을 deduplicate한다. 동일 파라미터에 여러 패턴이 매칭되면 우선순위 1위(목록 상단)를 primary로 표시하고 나머지는 evidence에 병기한다.

---

## finding 추가 필드

```python
{
    "url":          str,
    "method":       str,        # GET / POST
    "param":        str | None, # 매칭된 파라미터명 (URL path 검사 시 None)
    "description":  str,        # 패턴 + 수동 테스트 힌트 포함 설명
    "evidence":     str,        # 패턴=..., 값=... (최대 100자)
    "response_url": None,       # 패시브 탐지 — 추가 HTTP 요청 없으므로 response_url 없음
}
```

---

## scan() 파라미터

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `target_url` | str | — | 스캔 대상 URL |
| `timeout` | int | 10 | 요청 타임아웃(초) |
| `delay` | float | 0.7 | 요청 간 딜레이(초) |
| `max_pages` | int | 100 | 크롤링 최대 방문 페이지 수 (10~30000) |
| `cookies` | dict \| None | None | 요청에 첨부할 쿠키 |
| `progress_cb` | callable \| None | None | 하위 진행률 보고 콜백 `(current, total)`. 크롤링 0~90%, 패턴 매칭 90~100% 범위로 보고 |
| `proxies` | dict \| None | None | `{"http": ..., "https": ...}` 형식의 프록시 설정 |
| `auth_headers` | dict \| None | None | 모든 HTTP 요청 헤더에 영구 부착 (Authorization 등) |
| `render` | bool | False | JS 렌더링 활성화. DOM 렌더링·네트워크 인터셉션·JSON 채굴. XHR 포인트는 `page["points"]`로 직접 패턴 검사됨 |
