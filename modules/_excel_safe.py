"""
엑셀 셀 값 방어 공용 유틸 — recon / sqli_extract / excel_merge 가 공유한다.

기존에는 3개 모듈이 각자 거의 동일한 로직(수식 인젝션 방어)을 중복 구현했는데,
그 과정에서 sqli_extract만 openpyxl 제어문자 제거가 빠져 있었다(DB 원본 덤프에
0x00~0x1f 제어바이트가 섞이면 openpyxl.IllegalCharacterError로 저장 자체가
실패하는 버그). 이 파일로 단일화해 세 모듈의 방어 강도를 통일한다.

safe_cell()이 하는 일 (문자열 값에 한해 순서대로 적용):
  1) openpyxl 저장 불가 제어문자 제거 (\\x00-\\x08, \\x0b, \\x0c, \\x0e-\\x1f)
  2) 위험 접두사(=, +, -, @, 탭, 캐리지리턴)로 시작하면 앞에 ' 를 붙여
     엑셀이 수식으로 해석하지 못하게 문자열 강제 (CSV/수식 인젝션 방어)
"""
import re
from typing import Any

# 엑셀 수식 인젝션 방어 접두사 — 이 문자로 시작하는 셀 값은 수식으로 해석될 수 있다
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# openpyxl 저장 불가 제어 문자 (openpyxl.utils.ILLEGAL_CHARACTERS_RE 와 동일 범위)
ILLEGAL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def safe_cell(v: Any, *, stringify: bool = False) -> Any:
    """엑셀 셀에 안전하게 쓸 수 있도록 값을 정리한다.

    - v가 None이면 "" 반환.
    - stringify=False(기본, recon/excel_merge 계약): 비문자열(숫자·불린 등)은
      그대로 반환 — 엑셀 셀 타입을 유지해야 하는 호출부용.
    - stringify=True(sqli_extract 계약): 모든 값을 str()로 강제 변환 후 처리 —
      기존 _safe_cell_value가 항상 문자열을 반환하던 동작과 동일하게 유지.
    - 문자열이면 제어문자 제거 후, 위험 접두사로 시작할 때만 앞에 ' 를 붙인다.
    """
    if v is None:
        return ""
    if stringify:
        v = str(v)
    elif not isinstance(v, str):
        return v
    if ILLEGAL_CHARS_RE.search(v):
        v = ILLEGAL_CHARS_RE.sub("", v)
    if v.startswith(FORMULA_PREFIXES):
        return "'" + v
    return v
