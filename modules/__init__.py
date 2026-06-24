from . import directory_listing, default_pages, sql_injection, path_traversal

# 모듈 키 → (모듈 객체, 표시명) 매핑 — app.py 공용
MODULE_MAP = {
    "directory_listing": (directory_listing, "Directory Listing"),
    "default_pages":     (default_pages,     "Default & Sample Pages"),
    "sql_injection":     (sql_injection,     "SQL Injection"),
    "path_traversal":    (path_traversal,    "Path Traversal"),
}
