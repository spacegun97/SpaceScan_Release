# default_pages.py

**OWASP:** A05:2021 - Security Misconfiguration
**목적:** WEB/WAS/Application(CMS·에디터)의 기본·샘플 페이지 노출 탐지

---

## 동작 방식

1. **기술 스택 탐지** (`_detect_stacks`): 대상 URL에 GET 요청 후 응답 헤더(`Server`, `X-Powered-By`, `Link`, `X-Pingback`, `X-Generator`, `X-Drupal-Cache` 등 스택별 고유 헤더)와 바디 패턴으로 스택 자동 식별
2. **스택 합산**: 자동 탐지 결과와 웹 대시보드에서 사용자가 선택한 스택의 합집합을 최종 점검 대상으로 사용. 사용자가 선택하지 않은 경우 자동 탐지 결과만 사용
3. **경로 데이터 로드** (`_load_paths`): `modules/data/<stack>.json` 파일에서 경로 목록 로드
4. **경로 탐색**: 최종 스택별 경로 목록에 GET 요청, 응답 코드 기반으로 노출 판정

## 지원 스택

| 카테고리 | 스택 | 데이터 파일 |
|---------|------|------------|
| WEB | Apache | `modules/data/apache.json` |
| WEB | Nginx | `modules/data/nginx.json` |
| WEB | IIS | `modules/data/iis.json` |
| WAS | Tomcat | `modules/data/tomcat.json` |
| WAS | JBoss | `modules/data/jboss.json` |
| WAS | WebLogic | `modules/data/weblogic.json` |
| WAS | WebSphere | `modules/data/websphere.json` |
| Application | WordPress | `modules/data/wordpress.json` |
| Application | Drupal | `modules/data/drupal.json` |
| Application | CKEditor | `modules/data/ckeditor.json` |
| Application | FCKEditor | `modules/data/fckeditor.json` |
| Application | SmartEditor | `modules/data/smarteditor.json` |
| Application | CrossEditor | `modules/data/crosseditor.json` |

## 경로 데이터 구조 (`modules/data/*.json`)

```json
{
  "paths": [
    {"path": "/server-status", "severity": "MEDIUM", "category": "status_page"},
    {"path": "/icons/",        "severity": "LOW",    "category": "default_resource"}
  ]
}
```

## 카테고리 체계 (`CATEGORIES` in `default_pages.py`)

| category 키 | 한국어 설명 |
|-------------|------------|
| `admin_console` | 관리 콘솔 노출 |
| `status_page` | 서버 상태 모니터링 페이지 노출 |
| `config_exposure` | 서버 설정 정보 노출 |
| `debug_endpoint` | 디버그·진단 엔드포인트 노출 |
| `sample_app` | 샘플 애플리케이션 노출 |
| `default_resource` | 기본 설치 리소스 노출 |
| `sensitive_file` | 민감 파일 접근 가능 |
| `api_endpoint` | 내부 API 엔드포인트 노출 |

## finding 추가 필드

```python
{
    "tech_stack":  str,   # 탐지된 기술 스택명
    "path":        str,   # 탐색한 경로
    "url":         str,   # 전체 URL
    "status_code": int,   # HTTP 응답 코드
    "description": str,   # CATEGORIES[category] 값으로 자동 채워짐
}
```

## 심각도 기준

| 수준 | 해당 경로 유형 | 노출 판정 기준 |
|------|--------------|--------------|
| MEDIUM | 관리 콘솔, 스크립트 실행, 상태 조회, 민감 파일, API 엔드포인트 | 200 / 401 / 403 |
| LOW | 샘플 페이지, 문서, 기본 파일 | 200만 |

MEDIUM에서 401/403을 노출로 판정하는 이유: 접근 제어가 있더라도 해당 리소스가 존재함이 확인되므로 제거 또는 IP 제한 권고 대상이다.

## scan() 파라미터

| 파라미터 | 타입 | 기본값 | 설명 |
|----------|------|--------|------|
| `target_url` | str | — | 스캔 대상 URL |
| `timeout` | int | 10 | 요청 타임아웃(초) |
| `delay` | float | 0.7 | 요청 간 딜레이(초) |
| `stacks` | list[str] \| None | None | 사전 탐지된 기술 스택 목록. 값이 전달되면 내부 `_detect_stacks()` 호출을 건너뜀 |
| `cookies` | dict \| None | None | 요청에 첨부할 쿠키 (인증 스캔 시 사용) |
| `proxies` | dict \| None | None | `{"http": ..., "https": ...}` 형식의 프록시 설정 |
| `progress_cb` | callable \| None | None | 하위 진행률 보고 콜백 `(current, total)`. 전체 경로 수 대비 탐색 진행률을 보고 |
| `auth_headers` | dict \| None | None | 모든 HTTP 요청 헤더에 영구 부착 (Authorization 등) |
