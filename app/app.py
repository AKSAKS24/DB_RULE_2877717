from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="CIN Table Migration Scanner (SAP Note 2877717 style)",
    version="1.0"
)

# --- Constants for CIN tables ---
TABLES_CIN = {"J_1IMOCUST", "J_1IMOVEND"}
OLD_TO_NEW_TABLE_MAP = {
    "J_1IMOCUST": {"new_table": "KNA1"},
    "J_1IMOVEND": {"new_table": "LFA1"},
}

# --- Regex for any keyword or literal usage, all statement types (SELECT, UPDATE, JOIN, declarations, etc) ---
# This will catch direct table use even outside a SELECT!
TABLE_LITERAL_RE = re.compile(
    r'\b(' + '|'.join(map(re.escape, TABLES_CIN)) + r')\b',
    re.IGNORECASE
)

# --- Pydantic Models ---
class Finding(BaseModel):
    pgm_name: Optional[str] = None
    inc_name: Optional[str] = None
    type: Optional[str] = None
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    issue_type: Optional[str] = None
    severity: Optional[str] = None
    line: Optional[int] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: Optional[str] = ""
    cin_migration_findings: Optional[List[Finding]] = None

# --- Helpers ---
def line_of_offset(text: str, off: int) -> int:
    # Returns 1-based line number of character offset
    return text.count("\n", 0, off) + 1

def snippet_at(text: str, start: int, end: int) -> str:
    s = max(0, start - 60)
    e = min(len(text), end + 60)
    return text[s:e].replace("\n", "\\n")

def pack_finding(unit: Unit, issue_type, message, severity, start, end, suggestion, meta=None):
    src = unit.code or ""
    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "start_line": unit.start_line,
        "end_line": unit.end_line,
        "issue_type": issue_type,
        "severity": severity,
        "line": line_of_offset(src, start),
        "message": message,
        "suggestion": suggestion or "",
        "snippet": snippet_at(src, start, end),
        "meta": meta or {}
    }

# --- Core logic as scanner ---
def migrate_table_literal(table: str) -> str:
    table_up = table.upper()
    if table_up in OLD_TO_NEW_TABLE_MAP:
        new_table = OLD_TO_NEW_TABLE_MAP[table_up]["new_table"]
        msg = (
            f"Obsolete table '{table_up}' detected. "
            f"Replace it with '{new_table}' as per SAP Note 2877717 and review field mapping."
        )
        suggestion = (
            f"Replace '{table_up}' with '{new_table}' "
            f"and adapt code logic per SAP BP Table migration. Please check all related joins, fields, and conditions."
        )
        return msg, suggestion
    return None, None

def scan_unit(unit_idx: int, unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings = []

    # Search for all table literals (catching use in SELECT/JOIN/UPDATE, and as declarations)
    for m in TABLE_LITERAL_RE.finditer(src):
        table = m.group(1).upper()
        msg, suggestion = migrate_table_literal(table)
        # Gather the full statement or declaration where it occurs, for better snippet context
        # Look back for start-of-line, forward to semicolon/dot/newline/etc for snippet
        stmt_start = src.rfind('\n', 0, m.start())
        stmt_start = stmt_start + 1 if stmt_start != -1 else 0
        stmt_end_dot = src.find('.', m.end())
        stmt_end_nl = src.find('\n', m.end())
        if stmt_end_dot == -1: stmt_end_dot = len(src)
        if stmt_end_nl == -1: stmt_end_nl = len(src)
        stmt_end = min(stmt_end_dot, stmt_end_nl)
        snippet = src[stmt_start:stmt_end+1].strip()
        findings.append(pack_finding(
            unit,
            "CinTableUsage",
            msg,
            "error",
            m.start(),
            m.end(),
            suggestion,
            {"table": table, "offset": m.start()},
        ))

    res = unit.model_dump()
    if findings:
        res["cin_migration_findings"] = findings
    else:
        res["cin_migration_findings"] = []
    return res

def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    out = []
    for idx, u in enumerate(units):
        res = scan_unit(idx, u)
        if res.get("cin_migration_findings"):
            out.append(res)
    return out

# --- FastAPI Endpoint ---
@app.post("/remediate-array")
async def scan_cin_migration(units: List[Unit]):
    return analyze_units(units)

@app.get("/health")
def health():
    return {"ok": True}