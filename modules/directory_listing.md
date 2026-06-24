# directory_listing.py

**OWASP:** A05:2021 - Security Misconfiguration
**목적:** 크롤링으로 실제 존재하는 경로를 수집한 뒤, 해당 경로들의 상위 디렉토리에 대해 리스팅 여부를 확인한다. 모든 finding은 MEDIUM.

---

## 동작 방식 (2단계 파이프라인)

### Phase 1 — BFS 크롤링 (엔드포인트 수집)

1. BFS 시작 전 `robots.txt`와 `sitemap.xml`에서 같은 도메인 URL을 추가 시드로 수집한다. `robots.txt`의 Disallow/Allow 지시자는 발견 힌트로만 사용하며 차단 규칙을 따르지 않는다. `sitemap.xml`은 `<sitemapindex>`가 감지되면 하위 sitemap URL을 재귀 조회한다(깊이 3, 자식 20개 상한).
2. 입력 URL + 시드를 큐에 넣고 BFS 방식으로 같은 도메인 내 URL을 방문한다.
3. 응답 분류는 HTTP 상태 코드와 무관하므로 403·404 등 비200 응답도 CT·본문 스니핑 결과에 따라 파싱된다. HTML 응답에서는 `href`/`src`/`action`(따옴표·미따옴표), `data-url`/`data-href`/`data-action`/`data-src`, `srcset`, `<meta http-equiv="refresh">` url= 값을 추출하고, 스크립트 응답에서는 `fetch`/`axios` 등 JS 호출 URL을 추출해 큐에 추가한다.
4. `allow_redirects=True`로 요청하고, 리다이렉트 후 최종 URL의 도메인이 다르면 해당 페이지를 결과에서 제외한다.
5. 인증 세션 파기 방지를 위해 로그아웃 성격 경로(`logout`/`log-out`/`signout`/`sign-out`)는 큐 추가 단계에서 자동 제외한다.
6. 동일 서명(path + 쿼리 파라미터명 집합)의 URL은 최대 3회까지만 방문하여 페이지네이션 트랩을 방지한다. 요청 실패 시 `Timeout`·`ChunkedEncodingError`에 한해 최대 2회 재시도한다.
7. 방문 횟수가 `max_pages`에 도달하면 크롤링을 종료한다 (기본값 100, 범위 10~30000).

### Phase 2 — 디렉토리 리스팅 확인

1. 수집된 경로들에서 모든 상위 디렉토리를 추출한다.
   - 예: `/blog/posts/article.html` → `/blog/`, `/blog/posts/`
   - 확장자가 없는 마지막 세그먼트는 디렉토리로 간주 (예: `/api/v2/users` → `/api/v2/users/`)
2. 중복 제거 후 각 디렉토리에 GET 요청 → 200 응답 시 리스팅 시그니처 정규식 매칭:
   - `Index of /`
   - `Directory listing for`
   - `Parent Directory</a>`
   - `[To Parent Directory]`
   - `<title>Index of`
3. 리스팅 확인 시 `href` 속성 파싱으로 노출 파일 목록 추출 (최대 20개 저장).

---

## 민감 경로 판별

경로 내 아래 키워드 포함 시 `description`에 `[민감 경로]` 표기:
`admin`, `backup`, `config`, `log`, `logs`, `temp`, `tmp`, `data`, `old`, `dev`

---

## finding 추가 필드

```python
{
    "url":           str,
    "path":          str,          # 예: "/admin/"
    "status_code":   int,
    "description":   str,          # 자동 생성 (민감 경로 여부 포함)
    "evidence":      str,          # 매칭된 리스팅 시그니처 문자열
    "exposed_files": list[str],    # 추출된 파일명 (최대 20개)
    "total_files":   int,          # 전체 노출 파일 수
}
```

---

## 의도적 미구현 사항

아래 항목은 설계 결정으로 구현하지 않은 것이며, 미탐 검토 시 제외한다.

| 항목 | 사유 |
|------|------|
| 워드리스트 기반 디렉토리 프로빙 (`/backup/`, `/upload/` 등 직접 탐색) | HTML 링크에 없는 숨겨진 디렉토리는 탐지 안됨. default_pages 모듈에서 커버할 예정이므로 의도적 미구현 |

## scan() 파라미터

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `target_url` | str | — | 스캔 대상 URL |
| `timeout` | int | 10 | 요청 타임아웃(초) |
| `delay` | float | 0.7 | 요청 간 딜레이(초) |
| `max_pages` | int | 100 | 크롤링 최대 방문 페이지 수 (10~30000) |
| `cookies` | dict \| None | None | 요청에 첨부할 쿠키 (인증 스캔 시 사용) |
| `proxies` | dict \| None | None | `{"http": ..., "https": ...}` 형식의 프록시 설정 |
| `progress_cb` | callable \| None | None | 하위 진행률 보고 콜백 `(current, total)`. 크롤링 0~50%, 디렉토리 점검 50~100% 범위로 보고 |
| `auth_headers` | dict \| None | None | 모든 HTTP 요청 헤더에 영구 부착 (Authorization 등) |
| `render` | bool | False | JS 렌더링 활성화. SPA 동적 경로를 포함하여 더 많은 디렉토리 후보를 수집한다 |

**GUI:** 스캔 설정 폼의 "최대 크롤링 페이지" 입력 필드
