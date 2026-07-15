# default_pages.py

**OWASP:** A05:2021 - Security Misconfiguration
**목적:** WEB/WAS/Application(CMS·에디터)의 기본·샘플 페이지 노출 탐지

---

## 동작 방식

1. **기술 스택 탐지** (`_detect_stacks`): 대상 URL에 GET 요청 후 응답 헤더(`Server`, `X-Powered-By`, `Link`, `X-Pingback`, `X-Generator`, `X-Drupal-Cache` 등 스택별 고유 헤더)와 바디 패턴으로 스택 자동 식별
2. **스택 합산**: 자동 탐지 결과와 웹 대시보드에서 사용자가 선택한 스택의 합집합을 최종 점검 대상으로 사용. 사용자가 선택하지 않은 경우 자동 탐지 결과만 사용
3. **경로 데이터 로드** (`_load_paths`): `modules/data/<stack>.json` 파일에서 경로 목록 로드. 탐지된 스택이 하나 이상이면 `modules/data/common.json`(스택 무관 제네릭 민감파일 목록)을 항상 추가 로드하며, finding에는 `tech_stack: "Common"`으로 표시
4. **백엔드 확장자 필터** (`backend_filter`, 기본 ON): 감지된 스택의 언어 패밀리와 다른 백엔드 실행 확장자(`.jsp`/`.php`/`.aspx` 등) 경로를 점검 대상에서 제외. 상세는 아래 "백엔드 확장자 필터" 절 참고
5. **경로 탐색**: 필터링된 스택별 경로 목록 + common 목록에 GET 요청, 응답 코드 기반으로 노출 판정

## 백엔드 확장자 필터 (`backend_filter`)

에디터(DEXT5·CKEditor 등)나 CMS(WordPress 등) 데이터 파일은 동일 핸들러의 백엔드 언어별 변형(`.jsp`/`.asp`/`.aspx`/`.php` 등)을 모두 나열한다. 실제 서버는 언어 하나만 쓰므로, 감지·선택된 언어와 다른 언어의 실행 확장자 요청은 항상 헛방이다. 이 필터는 확정적으로 무의미한 요청만 제거한다.

- **언어 패밀리 매핑** (`STACK_BACKEND`): Tomcat·JBoss·WebLogic·WebSphere·SAP·Spring → `java` / IIS·ASPNET → `dotnet` / PHP·Laravel·WordPress·Drupal → `php`. Apache·Nginx·NodeJS·Django·에디터류는 언어를 확정하지 않으므로 매핑에 없음(필터에 기여하지 않음)
- **확장자 매핑** (`BACKEND_EXT`): `.jsp`/`.jspx`/`.do`/`.action` → `java` / `.asp`/`.aspx`/`.ashx`/`.asmx`/`.axd` → `dotnet` / `.php`/`.php3`/`.php4`/`.php5`/`.phtml` → `php`. 목록에 없는 확장자(`.js`/`.xml`/`.html`/`.config`/`.ini` 등 정적·스택 무관 리소스)는 언어 무관으로 간주되어 **항상 프로빙**
- **사용자 직접 지정** (`backends`, `BACKEND_FAMILIES = {"java", "dotnet", "php"}`): 대시보드에서 사용자가 직접 고른 언어 패밀리 목록. `BACKEND_FAMILIES`에 없는 값은 무시된다. Apache/Nginx/에디터류처럼 자동 탐지가 언어를 확정하지 못하는 스택만 감지된 경우에도, 사용자가 언어를 지정하면 그 언어로 필터가 강제 활성화된다
- **게이팅 규칙**: 감지된 스택들의 언어 패밀리 합집합 ∪ 사용자가 지정한 언어(`allowed`)를 구성. 경로 확장자가 `BACKEND_EXT`에 있고 `allowed`에 없으면 skip, 그 외(무관 확장자 또는 `allowed`에 포함)는 프로빙
- **안전장치**: `allowed`가 비어있으면(언어 미확정 — 감지된 언어도 없고 사용자 지정도 없는 경우) 필터를 적용하지 않고 전량 프로빙. 여러 언어가 동시에 확정되면(자동 탐지 여러 개 또는 자동 탐지 + 사용자 지정, 예: IIS 감지 + PHP 지정) 합집합으로 모두 허용
- **관측성**: 제외된 경로 수를 `debug_events`에 기록(`백엔드 필터: {허용 언어} 외 확장자 {n}개 제외`)
- `backend_filter=False`로 호출하면 `backends` 값과 무관하게 필터를 완전히 비활성화하여 기존 동작(전량 프로빙)과 동일

## 지원 스택

| 카테고리 | 스택 | 탐지 헤더 / 바디 패턴 | 데이터 파일 |
|---------|------|----------------------|------------|
| WEB | Apache | `Server: Apache` / `It works!` | `modules/data/apache.json` |
| WEB | Nginx | `Server: nginx` / `Welcome to nginx` | `modules/data/nginx.json` |
| WEB | IIS | `Server: Microsoft-IIS`, `X-Powered-By: ASP.NET` / `IIS Windows Server` | `modules/data/iis.json` |
| WAS | Tomcat | `Server: Apache-Coyote` / `Apache Tomcat/x.x` | `modules/data/tomcat.json` |
| WAS | JBoss | `Server: JBoss·WildFly`, `X-Powered-By: Undertow` / `WildFly` | `modules/data/jboss.json` |
| WAS | WebLogic | `Server: WebLogic` / `Oracle WebLogic` | `modules/data/weblogic.json` |
| WAS | WebSphere | `Server: WebSphere` / `IBM WebSphere` | `modules/data/websphere.json` |
| ERP | SAP | `Server: SAP NetWeaver·SAP J2EE Engine`, `Set-Cookie: SAP_SESSIONID·MYSAPSSO2` / `/sap/bc/`, `/sap/public/` | `modules/data/sap.json` |
| Application | WordPress | `Link: wp-json`, `X-Pingback: xmlrpc.php` / `wp-content/` | `modules/data/wordpress.json` |
| Application | Drupal | `X-Generator: Drupal`, `X-Drupal-Cache` / `Drupal.settings` | `modules/data/drupal.json` |
| Application | CKEditor | — / `ckeditor.js`, `CKEDITOR.` | `modules/data/ckeditor.json` |
| Application | FCKEditor | — / `fckeditor.js`, `FCKeditor` | `modules/data/fckeditor.json` |
| Application | SmartEditor | — / `HuskyEZCreator`, `SmartEditor2` | `modules/data/smarteditor.json` |
| Application | CrossEditor | — / `CrossEditor`, `namo_cross_editor` | `modules/data/crosseditor.json` |
| Application | DEXT5 | — / `dext5editor`, `dext5upload`, `DEXT5.` | `modules/data/dext5.json` |
| Framework | Spring | `X-Application-Context` / `Whitelabel Error Page`, `org.springframework` | `modules/data/spring.json` |
| Framework | PHP | `X-Powered-By: PHP/x.x`, `Set-Cookie: PHPSESSID` / `PHPSESSID` | `modules/data/php.json` |
| Framework | NodeJS | `X-Powered-By: Express` / `Cannot GET /` | `modules/data/nodejs.json` |
| Framework | Laravel | `Set-Cookie: laravel_session·XSRF-TOKEN` / `laravel`, `_ignition` | `modules/data/laravel.json` |
| Framework | Django | `Set-Cookie: csrftoken·sessionid` / `csrfmiddlewaretoken`, `__debug__` | `modules/data/django.json` |
| Framework | ASPNET | `X-AspNet-Version`, `X-Powered-By: ASP.NET`, `Set-Cookie: ASP.NET_SessionId` / `__VIEWSTATE` | `modules/data/aspnet.json` |
| Common | (스택 탐지와 무관) | — | `modules/data/common.json` |

`common.json`은 `.git/`·`.svn/`·`.env`·백업 아카이브(`.zip`·`.sql`)·`.DS_Store`·SSH 키 등 호스트·프레임워크에 관계없이 존재할 수 있는 민감 파일을 점검하며, 탐지된 스택이 1개 이상일 때 항상 스캔 대상에 합산된다(탐지 스택이 0개면 스캔 자체가 스킵되므로 common도 실행되지 않음).

## 경로 데이터 구조 (`modules/data/*.json`)

```json
{
  "paths": [
    {"path": "/server-status", "severity": "MEDIUM", "category": "status_page"},
    {"path": "/icons/",        "severity": "LOW",    "category": "default_resource"},
    {"path": "/CTCWebService/CTCWebServiceBean", "severity": "MEDIUM", "category": "api_endpoint", "note": "[JAVA] LM Configuration Wizard 인증우회 (CVE-2020-6287, RECON)"}
  ]
}
```

`note`는 선택 필드로, 엔트리가 특정 서브 기술스택(예: SAP의 JAVA/ABAP/HANA)에 해당하거나 CVE·공개 취약점 정보가 있을 때 부가 설명을 표기한다. finding의 `description`은 `CATEGORIES[category]` 값 뒤에 `· {note}` 형식으로 이어붙여 생성된다.

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
    "description": str,   # CATEGORIES[category] 값 + (note 있으면) " · {note}" 로 자동 채워짐
}
```

## 심각도 기준

| 수준 | 해당 경로 유형 | 노출 판정 기준 |
|------|--------------|--------------|
| MEDIUM | 관리 콘솔, 스크립트 실행, 상태 조회, 민감 파일, API 엔드포인트 | 200 / 301 / 302 / 401 / 403 / 405 / 415 / 500 |
| LOW | 샘플 페이지, 문서, 기본 파일 | 200 / 301 / 302 / 401 / 403 / 405 / 415 / 500 |

노출 판정은 severity와 무관하게 공통 기준을 적용한다 (severity는 finding의 위험도 등급 표기에만 사용). 301/302/401/403/405/415/500 모두 해당 리소스가 존재함을 확인하는 신호이므로 노출로 판정한다: 301/302는 로그인 페이지 등으로의 리다이렉트일 뿐 해당 경로가 서버에 존재함이 확인됨(관리 콘솔류가 미인증 접근 시 흔히 보이는 패턴), 401/403은 접근 제어가 있어도 리소스 존재가 확인됨, 405는 메서드가 거부됐을 뿐 엔드포인트는 존재함, 415는 요청 미디어 타입이 거부됐을 뿐 엔드포인트는 존재함, 500은 서버가 해당 경로를 라우팅·처리하다 발생한 오류로 리소스 존재가 확인됨.

**BurpSuite 프록시 에러 강등**: 응답 본문에 `Burp Suite` 문자열이 포함되면 대상 서버의 실제 응답이 아닌 BurpSuite 프록시 연결 실패 페이지로 판단하여, 해당 finding의 severity를 원래 등급(MEDIUM/LOW) 대신 `INFO`로 강등한다. finding은 삭제하지 않고 남겨 재검증 대상임을 표시하며, description에 `· [프록시 오류 — BurpSuite 응답으로 판정 신뢰 불가, 재검증 필요]`를 덧붙인다.

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
| `stop_event` | Event \| None | None | [중단] 신호. set 시 경로 점검의 요청 직전·딜레이 대기에서 `wait_or_cancel()`이 `ScanCancelled`를 던져 즉시 중단. `_run_scan()`이 주입 |
| `backend_filter` | bool | True | 백엔드 확장자 필터 활성화 여부. 감지된 언어 패밀리와 다른 실행 확장자(`.jsp`/`.php`/`.aspx` 등) 경로를 제외. 언어 미확정 시 자동으로 무시(전량 프로빙) |
