# -*- coding: utf-8 -*-
#
# XPLATFORM / Nexacro  text-SSV viewer & editor  -  Burp Suite (Jython) extension
#
# 대상 : 평문 텍스트 SSV  ( 헤더 "SSV:utf-8" + 0x1E(행)/0x1F(컬럼) 구분자 )
#        ※ FF AD + zlib 로 압축된 바이너리 SSV 는 "Xplatform zlib decoder.py" 담당(별개).
#
# 기능
#   메시지 에디터에 "XPLATFORM SSV" 탭 추가 (request/response 공통).
#   상단 [편집 모드] 체크박스로 두 화면 전환:
#     - OFF (기본) : 데이터셋/컬럼/행을 HTML 표로 예쁘게 보여줌 (읽기 전용)
#     - ON        : Burp 텍스트 에디터로 편집. 편집 후 Forward/Send 하면 재조립되어 전송.
#         · 구조 뷰 : 0x1E→줄바꿈, 0x1F→'␟'(U+241F) 로 표시. 값만 고치면 됨.
#                     정상 SSV 에 대해 byte-exact 로 왕복됨(자기검증 통과 시 자동 선택).
#         · raw 뷰  : 자기검증 실패(값에 줄바꿈/␟ 포함 등) 시 자동 폴백.
#                     제어문자를 \xNN, 백슬래시를 \\ 로 이스케이프 → 어떤 입력도 손상 없음.
#
# 안전장치
#   - 수정하지 않았거나, 편집 결과가 형식에 안 맞으면 getMessage() 는 원본 바이트를 그대로 반환.
#   - 편집 화면(구조/raw)은 모두 가역 변환이라 값을 건드리지 않는 한 원본 바이트가 보존됨.
#
# 로드 : Settings > Extensions 에서 Jython jar 지정 -> Extensions > Add > Python > 이 파일

import jarray
from java.lang import String
from java.util import Arrays
from java.awt import BorderLayout, CardLayout, FlowLayout
from javax.swing import JPanel, JCheckBox, JScrollPane, JEditorPane
from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab

RS = u'\x1e'         # Record Separator : 행 구분자
US = u'\x1f'         # Unit Separator   : 컬럼 구분자
SENT = u'\u241f'     # 구조 뷰에서 US 를 표시할 문자 (␟)
BOM = '\xef\xbb\xbf' # UTF-8 BOM (byte string)
MAX_ROWS = 2000      # 데이터셋당 HTML 표시 최대 행 수 (응답이 매우 클 때 방어)


# =============================== byte helpers ===============================
def _to_pystr(jb):
    # java byte[] -> python str(각 문자 = 바이트 0..255)
    if jb is None:
        return ''
    return ''.join(chr(x & 0xFF) for x in jb)

def _to_jbytes(s):
    # python str(0..255) -> java byte[]
    return jarray.array([(ord(c) - 256 if ord(c) > 127 else ord(c)) for c in s], 'b')

def _dec(bstr, cs):
    # byte str -> unicode (원본 charset 으로 디코드, 실패 시 UTF-8)
    try:
        return unicode(String(_to_jbytes(bstr), cs))
    except Exception:
        return unicode(String(_to_jbytes(bstr), "UTF-8"))

def _enc(u, cs):
    # unicode -> byte str (원본 charset 으로 인코드, 실패 시 UTF-8)
    try:
        return _to_pystr(String(u).getBytes(cs))
    except Exception:
        return _to_pystr(String(u).getBytes("UTF-8"))

def _view_to_jb(u):
    # 편집기에 넣을 java byte[] (편집기 내용은 항상 UTF-8 로 표시)
    return String(u).getBytes("UTF-8")

def _jb_to_view(jb):
    # 편집기에서 꺼낸 java byte[](UTF-8) -> unicode
    return unicode(String(jb, "UTF-8"))


# ============================ 구조 뷰 (structured) ============================
def _struct_render(u_ssv):
    # unicode SSV -> 편집용 unicode (US->␟, RS->줄바꿈)
    return u_ssv.replace(US, SENT).replace(RS, u'\n')

def _struct_parse(u_view):
    # 편집용 unicode -> unicode SSV (줄바꿈->RS, ␟->US). 편집기가 넣은 \r 은 정규화.
    u = u_view.replace(u'\r\n', u'\n').replace(u'\r', u'\n')
    return u.replace(u'\n', RS).replace(SENT, US)

def _struct_exact(bstr, cs):
    # 구조 뷰가 byte-exact 로 왕복되는지 검증 (정상 SSV 면 True)
    try:
        u = _dec(bstr, cs)
        return _enc(_struct_parse(_struct_render(u)), cs) == bstr
    except Exception:
        return False


# =============================== raw 뷰 (escape) ===============================
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
    # byte str -> unicode. 유효한 UTF-8 문자는 그대로, 그 외는 \xNN, 백슬래시는 \\
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
    # 가독성용 줄바꿈: 이스케이프된 RS 뒤에 개행 삽입(파싱 시 무시되므로 byte-exact 유지)
    return u''.join(out).replace(u'\\x1E', u'\\x1E\n')

def _unescape_to_bytestr(u):
    # raw 뷰 unicode -> byte str. \xNN->바이트, \\->0x5C, 그 외 문자->UTF-8, 줄바꿈 무시
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
        for b in ch.encode('utf-8'):
            out.append(ord(b))
        i += 1
    return ''.join(chr(v & 0xFF) for v in out)


# ============================ SSV 구조 파싱 (HTML용) ============================
def _ssv_fields(text):
    # unicode SSV -> (header, [(name,value)] 전역변수, [dataset dict])
    if RS not in text:
        records = text.replace(u'\r\n', u'\n').split(u'\n')  # 개행 폴백
    else:
        records = text.split(RS)
    header = None
    gvars = []
    datasets = []
    cur = None
    for rec in records:
        rec = rec.replace(u'\r', u'').replace(u'\n', u'')
        if rec == u'':
            continue
        if rec.startswith(u'SSV:'):
            header = rec[4:]
        elif rec.startswith(u'Dataset:'):
            cur = {'name': rec[len(u'Dataset:'):], 'cols': [], 'rows': []}
            datasets.append(cur)
        elif rec.startswith(u'_RowType_'):
            cols = []
            for f in rec.split(US)[1:]:
                if u':' in f:
                    nm, ty = f.split(u':', 1)
                else:
                    nm, ty = f, u''
                cols.append((nm, ty))
            if cur is not None:
                cur['cols'] = cols
            else:
                cur = {'name': u'(unnamed)', 'cols': cols, 'rows': []}
                datasets.append(cur)
        elif cur is not None and cur['cols']:
            cur['rows'].append(rec.split(US))
        elif u'=' in rec:
            nm, val = rec.split(u'=', 1)
            gvars.append((nm, val))
        else:
            gvars.append((u'(raw)', rec))
    return header, gvars, datasets

def _esc(s):
    if s is None:
        return u''
    s = unicode(s)
    return (s.replace(u'&', u'&amp;')
             .replace(u'<', u'&lt;')
             .replace(u'>', u'&gt;')
             .replace(u'"', u'&quot;'))

def _html_page(u_text, charset):
    header, gvars, datasets = _ssv_fields(u_text)
    out = []
    out.append(u"<html><head><style>")
    out.append(u"body{font-family:Consolas,'D2Coding',monospace;font-size:11px;margin:6px;color:#222;}")
    out.append(u"table{border-collapse:collapse;margin:2px 0 10px 0;}")
    out.append(u"th,td{border:1px solid #ccc;padding:1px 6px;text-align:left;vertical-align:top;}")
    out.append(u"th{background:#f2f2f2;font-weight:normal;color:#333;}")
    out.append(u"caption{text-align:left;padding:3px 0 2px 0;font-size:11px;color:#333;}")
    out.append(u".meta{color:#888;margin-bottom:6px;font-size:11px;}")
    out.append(u".rt{text-align:center;color:#666;}")
    out.append(u"</style></head><body>")

    out.append(u"<div class='meta'>")
    out.append(u"Format: <b>SSV</b> &nbsp; Charset: <b>%s</b> &nbsp; Datasets: <b>%d</b><br>"
               % (_esc(header or charset), len(datasets)))
    out.append(u"RowType &nbsp; N=Normal &nbsp; I=Insert &nbsp; U=Update &nbsp; D=Delete")
    out.append(u"</div>")

    if gvars:
        out.append(u"<table><caption>Global Variables</caption>")
        out.append(u"<tr><th>Name</th><th>Value</th></tr>")
        for nm, val in gvars:
            out.append(u"<tr><td>%s</td><td>%s</td></tr>" % (_esc(nm), _esc(val)))
        out.append(u"</table>")

    for ds in datasets:
        cols, rows = ds['cols'], ds['rows']
        out.append(u"<table>")
        out.append(u"<caption>Dataset: %s &nbsp;(cols: %d, rows: %d)</caption>"
                   % (_esc(ds['name']), len(cols), len(rows)))
        out.append(u"<tr><th>_RowType_</th>")
        for nm, ty in cols:
            if ty:
                out.append(u"<th>%s <span style='color:#aaa'>%s</span></th>"
                           % (_esc(nm), _esc(ty)))
            else:
                out.append(u"<th>%s</th>" % _esc(nm))
        out.append(u"</tr>")
        for fields in rows[:MAX_ROWS]:
            flag = fields[0] if fields else u''
            vals = fields[1:]
            out.append(u"<tr><td class='rt'>%s</td>" % _esc(flag))
            for i in range(max(len(cols), len(vals))):
                v = vals[i] if i < len(vals) else u''
                out.append(u"<td>%s</td>" % _esc(v))
            out.append(u"</tr>")
        if len(rows) > MAX_ROWS:
            out.append(u"<tr><td colspan='%d'>... %d more rows (truncated)</td></tr>"
                       % (len(cols) + 1, len(rows) - MAX_ROWS))
        out.append(u"</table>")

    out.append(u"</body></html>")
    return u"".join(out)


# ================================ extension ================================
class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XPLATFORM SSV Viewer/Editor")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return SsvTab(self, editable)


class SsvTab(IMessageEditorTab):
    def __init__(self, ext, editable):
        self._helpers = ext._helpers
        self._editable = editable
        self._orig_msg = None
        self._orig_body = ''      # 원본 바디 (byte str)
        self._plain = ''          # 현재 바디 (byte str, 편집 반영)
        self._charset = 'UTF-8'
        self._isRequest = True
        self._edit_mode = False
        self._edit_sub = 'struct' # 'struct' 또는 'raw'

        # 편집용 Burp 텍스트 에디터
        self._txt = ext._callbacks.createTextEditor()
        self._txt.setEditable(editable)
        # 읽기용 HTML 표
        self._html = JEditorPane()
        self._html.setEditable(False)
        self._html.setContentType("text/html")

        # 상단 체크박스 + 카드(뷰/편집) 레이아웃
        self._cards = CardLayout()
        self._center = JPanel(self._cards)
        self._center.add(JScrollPane(self._html), "view")
        self._center.add(self._txt.getComponent(), "edit")

        self._check = JCheckBox(u"\ud3b8\uc9d1 \ubaa8\ub4dc  (\ucef4\ub7fc \uad6c\ubd84 = \u241f, \uac12\ub9cc \uc218\uc815)")
        self._check.setSelected(False)
        self._check.addActionListener(self._on_toggle)
        topbar = JPanel(FlowLayout(FlowLayout.LEFT))
        topbar.add(self._check)

        self._root = JPanel(BorderLayout())
        self._root.add(topbar, BorderLayout.NORTH)
        self._root.add(self._center, BorderLayout.CENTER)

    # ---------------------- Burp IMessageEditorTab ----------------------
    def getTabCaption(self):
        return "XPLATFORM SSV"

    def getUiComponent(self):
        return self._root

    def isEnabled(self, content, isRequest):
        if content is None:
            return False
        try:
            body = self._body(content, isRequest)
        except Exception:
            return False
        if body[:3] == BOM:
            body = body[3:]
        return body[:4] == 'SSV:'

    def setMessage(self, content, isRequest):
        self._orig_msg = content
        self._isRequest = isRequest
        if content is None:
            self._orig_body = ''; self._plain = ''
            self._html.setText(""); self._txt.setText(None)
            return
        try:
            body = self._body(content, isRequest)
        except Exception:
            self._orig_body = ''; self._plain = ''
            self._html.setText(u"<html><body>(SSV) 표시할 수 없는 메시지</body></html>")
            self._txt.setText(None); self._txt.setEditable(False)
            self._cards.show(self._center, "view")
            return
        self._orig_body = body
        self._plain = body
        self._charset = self._detect_charset(body)
        self._edit_sub = 'struct' if _struct_exact(body, self._charset) else 'raw'
        # 현재 활성 카드만 렌더
        if self._edit_mode:
            self._render_edit(); self._cards.show(self._center, "edit")
        else:
            self._render_view(); self._cards.show(self._center, "view")

    def getMessage(self):
        if self._orig_msg is None:
            return self._orig_msg
        plain = self._current_plain()
        if plain == self._orig_body:      # 변경 없음 -> 원본 그대로
            return self._orig_msg
        try:
            if self._isRequest:
                headers = self._helpers.analyzeRequest(self._orig_msg).getHeaders()
            else:
                headers = self._helpers.analyzeResponse(self._orig_msg).getHeaders()
        except Exception:
            return self._orig_msg
        return self._helpers.buildHttpMessage(headers, _to_jbytes(plain))

    def isModified(self):
        try:
            return self._current_plain() != self._orig_body
        except Exception:
            return False

    def getSelectedData(self):
        if self._edit_mode:
            return self._txt.getSelectedText()
        try:
            sel = self._html.getSelectedText()
            if sel:
                return self._helpers.stringToBytes(sel)
        except Exception:
            pass
        return None

    # ---------------------------- 내부 로직 ----------------------------
    def _body(self, content, isRequest):
        if isRequest:
            off = self._helpers.analyzeRequest(content).getBodyOffset()
        else:
            off = self._helpers.analyzeResponse(content).getBodyOffset()
        return _to_pystr(Arrays.copyOfRange(content, off, len(content)))

    def _detect_charset(self, body):
        head = body[3:] if body[:3] == BOM else body
        if head[:4] != 'SSV:':
            return 'UTF-8'
        token = head[4:70]
        for sep in ('\x1e', '\x1f', '\r', '\n', ' '):
            p = token.find(sep)
            if p != -1:
                token = token[:p]
        token = token.strip()
        return token if token else 'UTF-8'

    def _render_view(self):
        u = _dec(self._plain, self._charset)
        self._html.setText(_html_page(u, self._charset))
        self._html.setCaretPosition(0)

    def _render_edit(self):
        if self._edit_sub == 'struct':
            u = _struct_render(_dec(self._plain, self._charset))
        else:
            u = _escape_run_str(self._plain)
        self._txt.setText(_view_to_jb(u))
        self._txt.setEditable(self._editable)

    def _current_plain(self):
        # 현재 편집기 내용 -> 바디 byte str (편집 모드가 아니면 마지막 커밋값)
        if not self._edit_mode:
            return self._plain
        u = _jb_to_view(self._txt.getText())
        if self._edit_sub == 'struct':
            return _enc(_struct_parse(u), self._charset)
        return _unescape_to_bytestr(u)

    def _on_toggle(self, event):
        want_edit = self._check.isSelected()
        if want_edit == self._edit_mode:
            return
        if want_edit:
            self._edit_mode = True
            self._render_edit()
            self._cards.show(self._center, "edit")
        else:
            self._plain = self._current_plain()  # 편집 내용 커밋 후 표에 반영
            self._edit_mode = False
            self._render_view()
            self._cards.show(self._center, "view")
