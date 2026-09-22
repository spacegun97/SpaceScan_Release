# -*- coding: utf-8 -*-
#
# XPLATFORM / Nexacro  zlib(deflate) SSV codec  -  Burp Suite (Jython) extension
#
# body layout : [ FF AD ][ 78 XX ...zlib stream... ]   (78 XX = zlib 헤더, 레벨 가변)
#
# 기능
#   1) "XPLATFORM SSV" 메시지 에디터 탭 (request/response 공통)
#      상단 "구조 보기" 체크박스(USE_CHECKBOX=True 일 때)로 두 모드 전환:
#      [구조 보기 ON]  SSV 를 파싱해서 표시/편집. 두 포맷 자동 인식:
#          (a) 평평한 변수 리스트 :  ErrorCode <i32> = -10073  /  ErrorMsg <str> = ...
#          (b) TypeDefinition 트리 :  [깊이] 노드명  +  그 아래 "필드 = 값" 줄
#          - 값만 편집하면 문자열 길이/필드개수/자식개수/헤더 길이 전부 저장 시 자동 재계산.
#          - 안전장치: 원본을 파싱->재직렬화한 게 원본 바이트와 같을 때만 그 모드 사용.
#            (문법 불일치 시 자동으로 raw 뷰로 폴백 -> 절대 손상 없음)
#      [구조 보기 OFF] raw 뷰: 문자열은 그대로, 그 외 바이너리는 \xNN, 백슬래시 \\.
#      편집 후 Forward/Send 하면 감지된 레벨로 deflate + 프리픽스 재부착.
#      (응답 편집은 Proxy 응답 인터셉트가 켜져 있어야 잡힘)
#   2) IHttpListener 자동 body 변조: 매 요청/응답 자동 inflate -> REWRITE_RULES -> deflate.
#
# 참고 - "body 손상됨(Burp charset)" 안내가 뜨는 경우:
#   Content-Type 에 charset=UTF-8 이 있으면 Burp 이 바이너리 body 를 텍스트로 재인코딩하면서
#   0x80 이상 바이트를 뭉갭니다(FF AD 78 -> FD FD 78). 이건 Burp 쪽 처리이며, 해결은
#   메시지 에디터 문자셋을 ISO-8859-1(Latin-1)로 두거나 Content-Type 의 charset 제거.
#
# 로드 : Settings > Extensions 에서 Jython jar 지정 -> Extensions > Add > Python > 이 파일

# ============================ 사용자 설정 ============================
REWRITE_REQUESTS  = False   # 요청 body 자동 변조 on/off
REWRITE_RESPONSES = False   # 응답 body 자동 변조 on/off

SHOW_ON_NONTARGET = True    # 비대상 메시지에도 탭 표시(이동 시 내용 안 남게). False=대상에만 표시
STRUCTURED_DEFAULT = True   # "구조 보기" 기본 상태
USE_CHECKBOX = True         # True=상단 체크박스로 구조<->raw 토글, False=편집기 직접(토글 없음)
DEBUG_LOG = False           # True 면 setMessage/getMessage/isEnabled 로그를 확장 Output 탭에 출력

# None = 모든 Burp 도구.  특정 도구만: from burp import IBurpExtenderCallbacks as C; [C.TOOL_PROXY]
TARGET_TOOLS = None

# 평문(inflate된 body)에 순서대로 적용할 (찾기, 바꾸기) 규칙. bytes.
REWRITE_RULES = [
    # (b'\xFF\xFF\xD8\xA7', b'\x00\x00\x00\x00'),   # ErrorCode(int32) 를 0 으로
]

def transform_body(plain, is_request, tool):
    for a, b in REWRITE_RULES:
        plain = plain.replace(a, b)
    return plain
# ===================================================================

import re
import jarray
from java.util import Arrays
from java.util.zip import Inflater, Deflater
from java.io import ByteArrayOutputStream
from java.awt import BorderLayout
from javax.swing import JPanel, JCheckBox
from burp import (IBurpExtender, IMessageEditorTabFactory,
                  IMessageEditorTab, IHttpListener)


# ------------------------------ codec ------------------------------
def _inflate(data):
    inf = Inflater()
    inf.setInput(data)
    out = ByteArrayOutputStream(max(len(data) * 3, 64))
    buf = jarray.zeros(8192, 'b')
    while not inf.finished():
        n = inf.inflate(buf)
        if n <= 0:
            break
        out.write(buf, 0, n)
    inf.end()
    return out.toByteArray()

def _deflate(data, level):
    d = Deflater(level)
    d.setInput(data)
    d.finish()
    out = ByteArrayOutputStream(max(len(data), 64))
    buf = jarray.zeros(8192, 'b')
    while not d.finished():
        out.write(buf, 0, d.deflate(buf))
    d.end()
    return out.toByteArray()

def _flevel_to_deflater_level(flg):
    # zlib FLG 의 FLEVEL(상위2비트) -> 같은 헤더 재생성 레벨: 0(7801)->1,1(785E)->4,2(789C)->6,3(78DA)->9
    return (1, 4, 6, 9)[(flg >> 6) & 0x03]

def _find_zlib_start(data):
    # FF AD 뒤 zlib(78 XX) 시작 오프셋. 레벨 무관. CM=8, (CMF<<8|FLG)%31==0, FDICT=0
    n = len(data); i = 0
    while i < n - 1:
        c = data[i] & 0xFF; f = data[i + 1] & 0xFF
        if (c & 0x0F) == 8 and (c >> 4) <= 7 and (f & 0x20) == 0 and (((c << 8) | f) % 31) == 0:
            return i
        i += 1
    return -1

def _concat(a, b):
    out = ByteArrayOutputStream(len(a) + len(b))
    out.write(a, 0, len(a)); out.write(b, 0, len(b))
    return out.toByteArray()

def _to_pystr(jb):
    if jb is None:
        return ''
    return ''.join(chr(x & 0xFF) for x in jb)

def _to_jbytes(s):
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in s], 'b')

def _ints_to_jb(ints):
    out = ByteArrayOutputStream(len(ints) + 1)
    for v in ints:
        out.write(v & 0xFF)
    return out.toByteArray()

def _ints_to_pystr(ints):
    return ''.join(chr(x & 0xFF) for x in ints)

def _u2jb(u):
    # 유니코드 문자열 -> java byte[] (UTF-8). 한글 등 표시용.
    enc = u.encode('utf-8')
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in enc], 'b')

def _hex_preview(data, n=64):
    m = min(len(data), n)
    return ' '.join('%02X' % (data[i] & 0xFF) for i in range(m))

def _ascii_skeleton(data):
    # charset 손상(0x80+ -> 대체문자)에도 보존되는 부분: ASCII(<0x80) 바이트의 순서열.
    # ASCII 는 UTF-8 에서 유효한 단일바이트라 왕복해도 안 바뀜 -> 손상 전/후 뼈대가 동일.
    out = []
    n = len(data); k = 0
    while k < n:
        b = data[k] & 0xFF
        if b < 0x80:
            out.append(chr(b))
        k += 1
    return ''.join(out)

def _looks_corrupted(data):
    # Burp charset 왕복으로 0x80+ 바이트가 대체문자(0xFD)로 뭉개진 흔적:
    # 원본 FF AD 78 XX -> FD FD 78 FD 처럼 zlib CM(0x78)이 0xFD 와 인접 + 0xFD 다수.
    n = len(data)
    nfd = 0; k = 0
    while k < n:
        if (data[k] & 0xFF) == 0xFD:
            nfd += 1
        k += 1
    if nfd < 2:
        return False
    k = 0
    while k < n - 1:
        a = data[k] & 0xFF; b = data[k + 1] & 0xFF
        if (a == 0x78 and b == 0xFD) or (a == 0xFD and b == 0x78):
            return True
        k += 1
    return False


# --------------------- raw(escaped) 뷰 인코딩/디코딩 ---------------------
def _ishex(c):
    return (u'0' <= c <= u'9') or (u'a' <= c <= u'f') or (u'A' <= c <= u'F')

def _utf8_len(c0):
    if c0 < 0x80: return 1
    if 0xC2 <= c0 <= 0xDF: return 2
    if 0xE0 <= c0 <= 0xEF: return 3
    return 1

def _valid_cont(bs, i, length):
    if i + length > len(bs):
        return False
    k = 1
    while k < length:
        if not (0x80 <= ord(bs[i + k]) <= 0xBF):
            return False
        k += 1
    return True

def _escape_run_str(bs):
    # byte str -> unicode. 유효한 UTF-8 문자열은 그대로, 그 외 \xNN, 백슬래시 \\
    out = []
    n = len(bs); i = 0
    while i < n:
        c0 = ord(bs[i]); length = _utf8_len(c0)
        if length in (2, 3) and _valid_cont(bs, i, length):
            try:
                ch = bs[i:i + length].decode('utf-8')
                if ord(ch) >= 0xA0:
                    out.append(ch); i += length; continue
            except Exception:
                pass
        if 0x20 <= c0 <= 0x7E:
            out.append(u'\\\\' if c0 == 0x5C else unichr(c0))
        else:
            out.append(u'\\x%02X' % c0)
        i += 1
    return u''.join(out)

def _bytes_to_escaped_text(data):
    enc = _escape_run_str(_to_pystr(data)).encode('utf-8')
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in enc], 'b')

def _emit_utf8(lst, ch):
    enc = ch.encode('utf-8')
    k = 0
    while k < len(enc):
        lst.append(ord(enc[k])); k += 1

def _escaped_text_to_bytes(jb):
    # raw 뷰 텍스트 -> java byte[].  \xNN -> 바이트, \\ -> 0x5C, 그 외 문자 -> UTF-8, 줄바꿈 무시
    u = _to_pystr(jb).decode('utf-8', 'replace')
    out = []
    i = 0; L = len(u)
    while i < L:
        ch = u[i]
        if ch == u'\r' or ch == u'\n':
            i += 1; continue
        if ch == u'\\':
            if i + 1 < L and u[i + 1] == u'\\':
                out.append(0x5C); i += 2; continue
            if i + 3 < L and (u[i + 1] == u'x' or u[i + 1] == u'X') \
                    and _ishex(u[i + 2]) and _ishex(u[i + 3]):
                out.append(int(u[i + 2:i + 4], 16)); i += 4; continue
            out.append(0x5C); i += 1; continue
        _emit_utf8(out, ch); i += 1
    return _ints_to_jb(out)


# --------------------- structured(flat SSV) 뷰 파서 ---------------------
_TYPE_I32 = 0x03
_TYPE_STR = 0x15
_LBL_INV = {u'i32': _TYPE_I32, u'str': _TYPE_STR}
_LINE_RE = re.compile(u'^(.*?) <([^>]*)> ?= ?(.*)$')

def _r16(b, i):
    return ((b[i] & 0xFF) << 8) | ((b[i + 1]) & 0xFF)

def _ssv_parse(data):
    # java byte[] -> (prefix_ints, [(name_ints, type, val_ints)]) 또는 None
    n = len(data)
    if n < 8:
        return None
    prefix = [data[k] & 0xFF for k in range(4)]
    lenf = _r16(data, 4); count = _r16(data, 6)
    if lenf != n - 6:
        return None
    fields = []; i = 8; c = 0
    while c < count:
        if i + 2 > n: return None
        nl = _r16(data, i); i += 2
        if i + nl > n: return None
        name = [data[k] & 0xFF for k in range(i, i + nl)]; i += nl
        if i + 2 > n: return None
        typ = _r16(data, i); i += 2
        if typ == _TYPE_STR:
            if i + 2 > n: return None
            vl = _r16(data, i); i += 2
            if i + vl > n: return None
            val = [data[k] & 0xFF for k in range(i, i + vl)]; i += vl
        elif typ == _TYPE_I32:
            if i + 4 > n: return None
            val = [data[k] & 0xFF for k in range(i, i + 4)]; i += 4
        else:
            return None
        fields.append((name, typ, val)); c += 1
    if i != n:
        return None
    return (prefix, fields)

def _ssv_serialize(prefix, fields):
    body = []
    for (name, typ, val) in fields:
        body.append((len(name) >> 8) & 0xFF); body.append(len(name) & 0xFF); body.extend(name)
        body.append((typ >> 8) & 0xFF); body.append(typ & 0xFF)
        if typ == _TYPE_STR:
            body.append((len(val) >> 8) & 0xFF); body.append(len(val) & 0xFF); body.extend(val)
        else:
            body.extend(val)
    count = len(fields)
    lenf = (4 + 2 + 2 + len(body)) - 6
    head = list(prefix) + [(lenf >> 8) & 0xFF, lenf & 0xFF, (count >> 8) & 0xFF, count & 0xFF]
    return _ints_to_jb(head + body)

def _ssv_selfcheck(data, parsed):
    ser = _ssv_serialize(parsed[0], parsed[1])
    if len(ser) != len(data):
        return False
    k = 0
    while k < len(ser):
        if (ser[k] & 0xFF) != (data[k] & 0xFF):
            return False
        k += 1
    return True

def _try_parse(data):
    p = _ssv_parse(data)
    if p is not None and _ssv_selfcheck(data, p):
        return p
    return None

def _int32_signed(ints4):
    v = 0
    for b in ints4:
        v = (v << 8) | (b & 0xFF)
    if v >= 0x80000000:
        v -= 0x100000000
    return v

def _ssv_render(parsed):
    # (prefix, fields) -> java byte[] (UTF-8 뷰 텍스트)
    fields = parsed[1]
    lines = []
    for (name, typ, val) in fields:
        nm = _ints_to_pystr(name).decode('utf-8', 'replace')
        if typ == _TYPE_I32:
            lines.append(u'%s <i32> = %d' % (nm, _int32_signed(val)))
        elif typ == _TYPE_STR:
            lines.append(u'%s <str> = %s' % (nm, _escape_run_str(_ints_to_pystr(val))))
    enc = (u'\n'.join(lines)).encode('utf-8')
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in enc], 'b')

def _unesc_val(s):
    out = []; i = 0; L = len(s)
    while i < L:
        ch = s[i]
        if ch == u'\\':
            if i + 1 < L and s[i + 1] == u'\\':
                out.append(0x5C); i += 2; continue
            if i + 3 < L and (s[i + 1] == u'x' or s[i + 1] == u'X') \
                    and _ishex(s[i + 2]) and _ishex(s[i + 3]):
                out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
            out.append(0x5C); i += 1; continue
        _emit_utf8(out, ch); i += 1
    return out

def _ssv_parse_view(jb, prefix):
    # 구조 뷰 텍스트 + prefix ints -> java byte[] (SSV) 또는 None
    u = _to_pystr(jb).decode('utf-8', 'replace')
    fields = []
    for line in u.split(u'\n'):
        if line.endswith(u'\r'):
            line = line[:-1]
        if line.strip() == u'':
            continue
        m = _LINE_RE.match(line)
        if not m:
            return None
        name = _unesc_val(m.group(1))
        lbl = m.group(2); valstr = m.group(3)
        if lbl not in _LBL_INV:
            return None
        typ = _LBL_INV[lbl]
        if typ == _TYPE_STR:
            val = _unesc_val(valstr)
        else:
            try:
                vv = int(valstr.strip()) & 0xFFFFFFFF
            except Exception:
                return None
            val = [(vv >> 24) & 0xFF, (vv >> 16) & 0xFF, (vv >> 8) & 0xFF, vv & 0xFF]
        fields.append((name, typ, val))
    return _ssv_serialize(prefix, fields)


# --------------------- TypeDefinition(트리) 뷰 파서 ---------------------
_TD_NODE_RE = re.compile(u'^\\[(\\d+)\\] (.*)$')

def _td_r16(d, i):
    return ((d[i] & 0xFF) << 8) | (d[i + 1] & 0xFF)

def _td_r32(d, i):
    return ((d[i] & 0xFF) << 24) | ((d[i + 1] & 0xFF) << 16) | ((d[i + 2] & 0xFF) << 8) | (d[i + 3] & 0xFF)

def _w16(o, v):
    o.append((v >> 8) & 0xFF); o.append(v & 0xFF)

def _w32(o, v):
    o.append((v >> 24) & 0xFF); o.append((v >> 16) & 0xFF)
    o.append((v >> 8) & 0xFF); o.append(v & 0xFF)

def _td_node(data, i, dic):
    n = len(data)
    if i + 8 > n: return None, i
    nameidx = _td_r16(data, i + 2)      # [marker:2][nameidx:2][fieldcount:4]...
    i += 4
    if nameidx >= len(dic): return None, i
    fc = _td_r32(data, i); i += 4
    fields = []; k = 0
    while k < fc:
        if i + 4 > n: return None, i
        fidx = _td_r16(data, i); i += 2
        L = _td_r16(data, i); i += 2
        if fidx >= len(dic) or i + L > n: return None, i
        fields.append((dic[fidx], [data[q] & 0xFF for q in range(i, i + L)])); i += L
        k += 1
    if i + 2 > n: return None, i
    cc = _td_r16(data, i); i += 2
    children = []; k = 0
    while k < cc:
        ch, i = _td_node(data, i, dic)
        if ch is None: return None, i
        children.append(ch); k += 1
    return {'name': dic[nameidx], 'fields': fields, 'children': children}, i

def _td_parse(data):
    # java byte[] -> (prefix_ints, dic[str], roots) 또는 None
    n = len(data)
    if n < 6: return None
    prefix = [data[k] & 0xFF for k in range(4)]
    i = 4; dcount = _td_r16(data, i); i += 2
    dic = []; c = 0
    while c < dcount:
        if i + 2 > n: return None
        L = _td_r16(data, i); i += 2
        if i + L > n: return None
        dic.append(_ints_to_pystr([data[k] & 0xFF for k in range(i, i + L)]).decode('utf-8', 'replace'))
        i += L; c += 1
    roots = []
    while i < n:
        node, i = _td_node(data, i, dic)
        if node is None: return None
        roots.append(node)
    if i != n: return None
    return (prefix, dic, roots)

def _td_emit(nodes, rev, out):
    for nd in nodes:
        nm = nd['name']
        if nm not in rev: return False
        _w16(out, 0x30 if nd['children'] else 0x31)   # marker: 자식有 0x30, 자식無 0x31
        _w16(out, rev[nm])
        _w32(out, len(nd['fields']))
        for (fn, val) in nd['fields']:
            if fn not in rev: return False
            _w16(out, rev[fn]); _w16(out, len(val)); out.extend(val)
        _w16(out, len(nd['children']))
        if not _td_emit(nd['children'], rev, out):
            return False
    return True

def _td_serialize(prefix, dic, roots):
    rev = {}; idx = 0
    for nm in dic:
        if nm not in rev: rev[nm] = idx
        idx += 1
    body = []
    if not _td_emit(roots, rev, body):
        return None
    out = []
    out.extend(prefix)
    _w16(out, len(dic))
    for sfrag in dic:
        b = sfrag.encode('utf-8')
        _w16(out, len(b))
        k = 0
        while k < len(b):
            out.append(ord(b[k])); k += 1
    out.extend(body)
    return _ints_to_jb(out)

def _td_selfcheck(data, td):
    ser = _td_serialize(td[0], td[1], td[2])
    if ser is None or len(ser) != len(data):
        return False
    k = 0
    while k < len(ser):
        if (ser[k] & 0xFF) != (data[k] & 0xFF):
            return False
        k += 1
    return True

def _td_render_nodes(nodes, depth, lines):
    for nd in nodes:
        lines.append(u'[%d] %s' % (depth, nd['name']))
        for (fn, val) in nd['fields']:
            lines.append(u'%s = %s' % (fn, _escape_run_str(_ints_to_pystr(val))))
        _td_render_nodes(nd['children'], depth + 1, lines)

def _td_render(parsed):
    lines = []
    _td_render_nodes(parsed[2], 0, lines)
    enc = (u'\n'.join(lines)).encode('utf-8')
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in enc], 'b')

def _td_parse_view(jb, prefix, dic):
    # 뷰 텍스트 + prefix/dic -> java byte[] (SSV) 또는 None
    u = _to_pystr(jb).decode('utf-8', 'replace')
    roots = []; stack = {}; cur = [None]
    for line in u.split(u'\n'):
        if line.endswith(u'\r'):
            line = line[:-1]
        if line.strip() == u'':
            continue
        m = _TD_NODE_RE.match(line)
        if m:
            depth = int(m.group(1))
            nd = {'name': m.group(2), 'fields': [], 'children': []}
            if depth == 0:
                roots.append(nd)
            else:
                p = stack.get(depth - 1)
                if p is None:
                    return None
                p['children'].append(nd)
            stack[depth] = nd
            for dd in list(stack.keys()):
                if dd > depth:
                    del stack[dd]
            cur[0] = nd
        else:
            pos = line.find(u' = ')
            if pos < 0:
                if line.endswith(u' ='):
                    fn = line[:-2]; vs = u''
                else:
                    return None
            else:
                fn = line[:pos]; vs = line[pos + 3:]
            if cur[0] is None:
                return None
            cur[0]['fields'].append((fn.strip(), _unesc_val(vs)))
    return _td_serialize(prefix, dic, roots)


# ------------------------- extension core -------------------------
class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XPLATFORM zlib SSV Codec")
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerHttpListener(self)

    def createNewInstance(self, controller, editable):
        return XplatformTab(self, editable)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest and not REWRITE_REQUESTS:
            return
        if (not messageIsRequest) and not REWRITE_RESPONSES:
            return
        if TARGET_TOOLS is not None and toolFlag not in TARGET_TOOLS:
            return
        h = self._helpers
        msg = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
        if msg is None:
            return
        if messageIsRequest:
            off = h.analyzeRequest(msg).getBodyOffset()
        else:
            off = h.analyzeResponse(msg).getBodyOffset()
        body = Arrays.copyOfRange(msg, off, len(msg))
        idx = _find_zlib_start(body)
        if idx == -1:
            return
        prefix = Arrays.copyOfRange(body, 0, idx)
        level = _flevel_to_deflater_level(body[idx + 1] & 0xFF)
        try:
            plain = _to_pystr(_inflate(Arrays.copyOfRange(body, idx, len(body))))
        except Exception:
            return
        new_plain = transform_body(plain, messageIsRequest, toolFlag)
        if new_plain == plain:
            return
        new_body = _concat(prefix, _deflate(_to_jbytes(new_plain), level))
        if messageIsRequest:
            headers = h.analyzeRequest(msg).getHeaders()
            messageInfo.setRequest(h.buildHttpMessage(headers, new_body))
        else:
            headers = h.analyzeResponse(msg).getHeaders()
            messageInfo.setResponse(h.buildHttpMessage(headers, new_body))


# --------------------------- editor tab ---------------------------
class XplatformTab(IMessageEditorTab):
    def __init__(self, ext, editable):
        self._helpers = ext._helpers
        self._cb = ext._callbacks
        self._editable = editable
        self._txt = ext._callbacks.createTextEditor()
        self._txt.setEditable(editable)
        self._msg = None
        self._isRequest = True
        self._prefix = None        # zlib 앞 FF AD (java byte[])
        self._level = 6
        self._plain = None         # inflate 된 raw SSV (java byte[])
        self._parsed = None        # 평평한 포맷 파싱결과 or None
        self._td = None            # TypeDefinition 트리 파싱결과 or None
        self._structured = STRUCTURED_DEFAULT
        self._mode = 'raw'
        self._baseline = None      # setText 직후 텍스트 스냅샷(수정 여부 직접 추적용)
        # Burp charset 손상 복구용 캐시 (마지막 정상 디코딩)
        self._corrupted = False
        self._good_skel = None     # 정상 압축 body 의 ASCII 뼈대
        self._good_plain = None    # 정상 압축해제 SSV (java byte[])
        self._good_prefix = None   # 정상 FF AD (java byte[])
        self._good_level = 6

        self._check = None
        self._panel = None
        if USE_CHECKBOX:
            self._panel = JPanel(BorderLayout())
            self._check = JCheckBox(u"\uad6c\uc870 \ubcf4\uae30  (Structured: name <type> = value)",
                                    self._structured)
            self._check.addActionListener(self._on_toggle)
            self._panel.add(self._check, BorderLayout.NORTH)
            self._panel.add(self._txt.getComponent(), BorderLayout.CENTER)

    def _log(self, s):
        if DEBUG_LOG:
            try:
                self._cb.printOutput(s)
            except Exception:
                pass

    def _clear(self):
        self._corrupted = False
        self._prefix = None; self._plain = None
        self._parsed = None; self._td = None; self._baseline = None

    def _reparse(self, plain):
        self._parsed = _try_parse(plain)            # 1) 평평한 포맷
        self._td = None
        if self._parsed is None:                    # 2) TypeDefinition 트리
            td = _td_parse(plain)
            if td is not None and _td_selfcheck(plain, td):
                self._td = td

    def _render(self):
        if self._plain is None:
            self._baseline = None
            return
        if self._structured and self._parsed is not None:
            self._mode = 'flat'; jb = _ssv_render(self._parsed)
        elif self._structured and self._td is not None:
            self._mode = 'td'; jb = _td_render(self._td)
        else:
            self._mode = 'raw'; jb = _bytes_to_escaped_text(self._plain)
        self._txt.setText(jb)
        self._baseline = _to_pystr(self._txt.getText())
        self._txt.setEditable(self._editable)

    def _dirty(self):
        # Burp 의 isTextModified() 대신 baseline 대비 실제 변경 여부로 판단
        if self._baseline is None:
            return False
        try:
            return _to_pystr(self._txt.getText()) != self._baseline
        except Exception:
            return False

    def _decode_current(self):
        # 현재 편집 텍스트 -> raw SSV(java byte[]). 실패 시 None
        if self._mode == 'flat' and self._parsed is not None:
            return _ssv_parse_view(self._txt.getText(), self._parsed[0])
        if self._mode == 'td' and self._td is not None:
            return _td_parse_view(self._txt.getText(), self._td[0], self._td[1])
        return _escaped_text_to_bytes(self._txt.getText())

    def _on_toggle(self, event):
        if self._check is None:
            return
        self._structured = self._check.isSelected()
        if self._plain is None:
            return
        raw = None
        try:
            raw = self._decode_current()
        except Exception:
            raw = None
        if raw is None:
            raw = self._plain
        self._plain = raw
        self._reparse(raw)
        self._render()

    def getTabCaption(self):
        return "XPLATFORM SSV"

    def getUiComponent(self):
        if self._panel is not None:
            return self._panel
        return self._txt.getComponent()

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            if self._find(self._body(content, isRequest)) != -1:
                return True
        except Exception:
            pass
        return SHOW_ON_NONTARGET      # 비대상도 표시 -> 이동 시 setMessage 매번 호출

    def setMessage(self, content, isRequest):
        self._msg = content
        self._isRequest = isRequest
        if content is None:
            self._clear()
            self._txt.setText(None); self._txt.setEditable(False)
            return
        try:
            body = self._body(content, isRequest)
        except Exception:
            self._clear()
            self._txt.setText(_u2jb(u"(XPLATFORM SSV)  -- 표시할 수 없는 메시지 --"))
            self._txt.setEditable(False)
            return
        idx = self._find(body)
        self._log("[setMessage] req=%s len=%d first12=%s zlib_idx=%d" % (
            isRequest, len(body), _hex_preview(body, 12), idx))
        if idx == -1:
            # Burp charset 손상? 마지막 정상 메시지의 손상본이면 ASCII 뼈대로 복구
            if self._good_skel is not None and len(self._good_skel) >= 16 \
                    and _ascii_skeleton(body) == self._good_skel:
                self._log("[setMessage] corrupted (skeleton match) -> recover cached decode")
                self._corrupted = True
                self._prefix = self._good_prefix
                self._level = self._good_level
                self._plain = self._good_plain
                self._reparse(self._good_plain)
                self._render()
                return
            self._clear()
            if _looks_corrupted(body):
                info = (u"(XPLATFORM SSV)  -- body 손상됨 (Burp charset 문제) --\n"
                        u"0x80 이상 바이트가 대체문자(0xFD)로 뭉개졌습니다. 예: FF AD 78 -> FD FD 78\n"
                        u"Burp 이 Content-Type 의 charset(UTF-8)에 맞춰 바이너리 body 를 텍스트로\n"
                        u"재인코딩하면서 생긴 손상입니다(이 확장이 아니라 Burp 쪽 처리).\n"
                        u"해결: 메시지 에디터 문자셋을 ISO-8859-1(Latin-1)로 설정하거나\n"
                        u"      Content-Type 의 charset=UTF-8 제거.\n"
                        u"body[0:48] = %s" % _hex_preview(body, 48))
            else:
                info = (u"(XPLATFORM SSV)  -- 디코딩 대상 아님 --\n"
                        u"이 메시지 body 는 FF AD + zlib(78 XX) XPLATFORM 압축 포맷이 아닙니다.\n"
                        u"body length = %d\nbody[0:48] = %s" % (len(body), _hex_preview(body, 48)))
            self._txt.setText(_u2jb(info))
            self._txt.setEditable(False)
            return
        self._prefix = Arrays.copyOfRange(body, 0, idx)
        self._level = _flevel_to_deflater_level(body[idx + 1] & 0xFF)
        try:
            plain = _inflate(Arrays.copyOfRange(body, idx, len(body)))
        except Exception as e:
            self._clear()
            self._txt.setText(_u2jb(u"[inflate error] %s" % e))
            self._txt.setEditable(False)
            return
        self._corrupted = False
        self._plain = plain
        self._reparse(plain)
        # 복구용 캐시 갱신 (정상 디코딩)
        self._good_skel = _ascii_skeleton(body)
        self._good_plain = plain
        self._good_prefix = self._prefix
        self._good_level = self._level
        self._render()

    def getMessage(self):
        if self._corrupted and self._good_prefix is not None:
            raw = None
            if self._dirty():
                try:
                    raw = self._decode_current()
                except Exception:
                    raw = None
            if raw is None:
                raw = self._good_plain
            body = _concat(self._good_prefix, _deflate(raw, self._good_level))
            if _find_zlib_start(body) == -1:
                raw = self._good_plain
                body = _concat(self._good_prefix, _deflate(raw, self._good_level))
            # [FIX] 이번 편집본을 복구 캐시에 반영 (뼈대는 왕복 불변이라 다음 왕복 때 복구 가능)
            self._good_plain = raw
            self._good_skel = _ascii_skeleton(body)
            try:
                if self._isRequest:
                    headers = self._helpers.analyzeRequest(self._msg).getHeaders()
                else:
                    headers = self._helpers.analyzeResponse(self._msg).getHeaders()
            except Exception:
                return self._msg
            return self._helpers.buildHttpMessage(headers, body)
        if self._prefix is None or not self._dirty():
            return self._msg
        raw = None
        try:
            raw = self._decode_current()
        except Exception:
            raw = None
        if raw is None:                    # 편집이 형식에 안 맞으면 원본 유지(손상 방지)
            return self._msg
        body = _concat(self._prefix, _deflate(raw, self._level))
        if _find_zlib_start(body) == -1:   # 재인코딩 결과가 대상 아니면 원본 유지
            return self._msg
        # [FIX] 편집본을 복구 캐시에 반영 -> Pretty/Raw 왕복으로 charset 손상돼도
        #       ASCII 뼈대로 이 편집 상태를 되살릴 수 있게 함 (핵심 수정)
        self._good_plain = raw
        self._good_prefix = self._prefix
        self._good_level = self._level
        self._good_skel = _ascii_skeleton(body)
        if self._isRequest:
            headers = self._helpers.analyzeRequest(self._msg).getHeaders()
        else:
            headers = self._helpers.analyzeResponse(self._msg).getHeaders()
        return self._helpers.buildHttpMessage(headers, body)

    def isModified(self):
        return self._dirty()

    def getSelectedData(self):
        return self._txt.getSelectedText()

    def _body(self, content, isRequest):
        if isRequest:
            off = self._helpers.analyzeRequest(content).getBodyOffset()
        else:
            off = self._helpers.analyzeResponse(content).getBodyOffset()
        return Arrays.copyOfRange(content, off, len(content))

    def _find(self, data):
        try:
            return _find_zlib_start(data)
        except Exception:
            return -1