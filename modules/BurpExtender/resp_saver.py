# resp_saver.py  -  Burp Jython extension
# Saves only the "response body" of selected history items to disk.
#  - filename  = last segment of the request URL path (the filename in the request line)
#  - directory = chosen via a dialog on each run (remembers the last path)
#
# NOTE: Standalone tool run inside BurpSuite (Extender > Jython), not part of the
# SpaceScan app — intentionally unreferenced by app.py / modules/__init__.py.
# Used to quickly dump JS files for the JS 데이터플로우 분석 module.
# Do NOT delete as "dead code" during refactoring. See CLAUDE.md 프로젝트 개요.

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JFileChooser
from java.io import File, FileOutputStream
from java.util import Arrays
import os, re


class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._cb = callbacks
        self._h = callbacks.getHelpers()
        self._last_dir = None
        callbacks.setExtensionName("Response Body Saver")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, inv):
        self._inv = inv          # store the invocation of this right-click
        return [JMenuItem("Save selected responses (body) -> disk",
                          actionPerformed=lambda e: self.dump())]

    def dump(self):
        msgs = self._inv.getSelectedMessages()
        if not msgs:
            return
        outdir = self._choose_dir()
        if outdir is None:                # cancelled
            return

        n, skipped = 0, 0
        for m in msgs:
            resp = m.getResponse()
            if resp is None:              # skip items with no response
                skipped += 1
                continue
            info = self._h.analyzeResponse(resp)
            url = self._h.analyzeRequest(m).getUrl()

            # strip headers, write only the body as raw byte[] (no encoding/binary loss)
            body = Arrays.copyOfRange(resp, info.getBodyOffset(), len(resp))
            path = self._unique(outdir, self._name(url))
            fos = FileOutputStream(File(path)); fos.write(body); fos.close()
            n += 1

        print("[Resp Saver] saved %d file(s) -> %s (skipped %d)" % (n, outdir, skipped))

    def _choose_dir(self):
        fc = JFileChooser()
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        fc.setDialogTitle("Select output directory")
        if self._last_dir:
            fc.setCurrentDirectory(File(self._last_dir))
        if fc.showDialog(None, "Select") != JFileChooser.APPROVE_OPTION:
            return None
        self._last_dir = fc.getSelectedFile().getAbsolutePath()
        return self._last_dir

    def _name(self, url):
        segs = [s for s in url.getPath().split("/") if s]
        name = segs[-1] if segs else url.getHost()    # fall back to host if path ends with '/'
        return re.sub(r'[\\/:*?"<>|]', '_', name)      # replace only FS-illegal chars, keep the rest

    def _unique(self, outdir, base):
        # on filename collision, append _1, _2 ... (avoid overwriting existing files)
        path = os.path.join(outdir, base)
        if not os.path.exists(path):
            return path
        root, ext = os.path.splitext(base)
        i = 1
        while os.path.exists(os.path.join(outdir, "%s_%d%s" % (root, i, ext))):
            i += 1
        return os.path.join(outdir, "%s_%d%s" % (root, i, ext))