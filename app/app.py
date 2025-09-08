# abap_table_migration_scan_style.py

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import re

app = FastAPI(
    title="CIN Table Migration Scanner (SAP Note 2877717 style)",
    version="1.0"
)

# --- Regexes and constants ---
ABAP_STMT_SPLIT_RE = re.compile(r"([^.]*\.)", re.DOTALL)
DECL_START_RE = re.compile(r"^\s*(DATA|TYPES)\s*:", re.IGNORECASE)

TABLES_CIN = {"J_1IMOCUST", "J_1IMOVEND"}
OLD_TO_NEW_TABLE_MAP = {
    "J_1IMOCUST": {"new_table": "KNA1", "key_field": "KUNNR"},
    "J_1IMOVEND": {"new_table": "LFA1", "key_field": "LIFNR"},
}
CIN_OLD_FIELDS = {"VEN_CLASS", "J_1IPANNO", "J_1IEXCIVE"}

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
def migrate_cin_table(stmt: str, table: str) -> str:
    table_up = table.upper()
    if table_up not in OLD_TO_NEW_TABLE_MAP:
        return stmt  # no change

    mapping = OLD_TO_NEW_TABLE_MAP[table_up]
    new_table = mapping["new_table"]

    todo_msg = (
        f"* TODO (SAP Note 2877717): Replace direct usage of {table_up} with "
        f"{new_table} as per SAP recommendations. Map required fields accordingly."
    )

    updated_stmt = re.sub(
        rf"\b{table_up}\b",
        new_table,
        stmt,
        flags=re.IGNORECASE,
    )

    if "SELECT" in stmt.upper():
        field_section = re.search(r"SELECT\s+(.*?)\s+FROM\b", stmt, re.IGNORECASE | re.DOTALL)
        if field_section:
            fields_str = field_section.group(1)
            fields = [f.strip().split()[0] for f in fields_str.split(",")]
            removed_fields = [f for f in fields if f.upper() in CIN_OLD_FIELDS]
            if removed_fields:
                todo_msg += (
                    f" Review field(s): {', '.join(removed_fields)}. "
                    f"Map these to corresponding fields from {new_table}."
                )

    if "JOIN" in stmt.upper():
        todo_msg += " Review all join conditions and migrate CIN table joins according to Note 2877717."
        return f"{todo_msg}\n{updated_stmt.strip()}"

    return f"{todo_msg}\n{updated_stmt.strip()}"

def migrate_declaration(decl: str) -> Optional[str]:
    text = decl.strip()
    type_ref_re = re.compile(r"\bTYPE\s+(J_1IMOCUST|J_1IMOVEND)(?:-(\w+))?", re.IGNORECASE)

    matches = list(type_ref_re.finditer(text))
    if not matches:
        return None

    todo_msgs = []
    for m in matches:
        old_table = m.group(1).upper()
        field = m.group(2).upper() if m.group(2) else None
        new_table = OLD_TO_NEW_TABLE_MAP[old_table]["new_table"]
        if re.search(r"\bBEGIN\s+OF\b", text, re.IGNORECASE):
            todo_msgs.append(
                f"* TODO (SAP Note 2877717): Replace structure field usage of {old_table}"
                f"{('-' + field) if field else ''} with equivalent field from {new_table}"
                f"{('-' + field) if field else ''}."
            )
        else:
            todo_msgs.append(
                f"* TODO (SAP Note 2877717): Replace {old_table}"
                f"{('-' + field) if field else ''} with {new_table}"
                f"{('-' + field) if field else ''}."
            )
    def _sub(m):
        old_table = m.group(1).upper()
        field = m.group(2).upper() if m.group(2) else None
        new_table = OLD_TO_NEW_TABLE_MAP[old_table]["new_table"]
        return f"TYPE {new_table}{('-' + field) if field else ''}"

    new_text = type_ref_re.sub(_sub, text)
    return ("\n".join(todo_msgs) + "\n" + new_text).strip()

def iter_statements_with_offsets(src: str):
    buf = []
    start = 0
    for i, ch in enumerate(src):
        buf.append(ch)
        if ch == ".":
            yield "".join(buf), start, i + 1
            buf = []
            start = i + 1
    if buf:
        yield "".join(buf), start, len(src)

def iter_declarations_with_offsets(src: str):
    # Yields (decl-string, start, end)
    lines = src.splitlines(keepends=True)
    n = len(lines)
    i = 0
    pos = 0
    while i < n:
        line = lines[i]
        # Simple DATA:/TYPES:
        if DECL_START_RE.match(line):
            buf = [line]
            end_rel = len(line)
            j = i
            # Struct?
            if re.search(r"\bBEGIN\s+OF\b", line, re.IGNORECASE):
                while j + 1 < n:
                    j += 1
                    buf.append(lines[j])
                    end_rel += len(lines[j])
                    if re.search(r"\bEND\s+OF\s+\w+\s*\.\s*$", lines[j], re.IGNORECASE):
                        break
            else:
                while j + 1 < n and not re.search(r"\.\s*$", lines[j], re.IGNORECASE):
                    j += 1
                    buf.append(lines[j])
                    end_rel += len(lines[j])
                    if re.search(r"\.\s*$", lines[j], re.IGNORECASE):
                        break
            full = "".join(buf)
            yield full, pos, pos+end_rel
            i = j + 1
            pos += end_rel
            continue
        i += 1
        pos += len(line)

# --- The actual scan ---
def scan_unit(unit_idx: int, unit: Unit) -> Dict[str, Any]:
    src = unit.code or ""
    findings: List[Dict[str, Any]] = []

    # 1. Table-use statements (SELECT/INSERT/UPDATE/MODIFY)
    for stmt, s_off, s_end in iter_statements_with_offsets(src):
        # Look for statements referencing CIN tables
        # Simple: look for FROM/JOIN/INTO/UPDATE/MODIFY + table
        found = False
        for t in TABLES_CIN:
            if re.search(rf"\b(FROM|JOIN|INTO|UPDATE|MODIFY)\s+{t}\b", stmt, re.IGNORECASE):
                found = True
                break
            # or, if table appears at any position (insert, e.g.)
            if re.search(rf"\b{t}\b", stmt, re.IGNORECASE):
                found = True
                break
        if not found:
            continue

        # Which table?
        table_match = None
        for t in TABLES_CIN:
            if re.search(rf"\b{t}\b", stmt, re.IGNORECASE):
                table_match = t
                break

        if not table_match:
            continue

        # Run migration logic for message & suggestion
        suggested = migrate_cin_table(stmt, table_match)
        if suggested != stmt:
            msg = f"Direct usage of CIN table {table_match}."
            findings.append(pack_finding(
                unit,
                "CinTableDirectUsage",
                msg,
                "error",
                s_off,
                s_end,
                "Migrate to BP master data tables (see SAP Note 2877717).\n" + suggested,
                {"table": table_match}
            ))

    # 2. Declarations referencing CIN tables
    for decl, d_off, d_end in iter_declarations_with_offsets(src):
        # Only process DATA:/TYPES: with CIN table type references
        m = re.search(r"\bTYPE\s+(J_1IMOCUST|J_1IMOVEND)\b", decl, re.IGNORECASE)
        if not m:
            continue
        migrated = migrate_declaration(decl)
        if migrated and migrated != decl:
            tbl = m.group(1).upper()
            findings.append(pack_finding(
                unit,
                "CinTableTypeReference",
                f"Declaration references CIN table type {tbl}.",
                "error",
                d_off,
                d_end,
                f"Change referenced type to BP table (per SAP Note 2877717):\n{migrated}",
                {"table": tbl}
            ))

    # Return unit + findings
    res = unit.model_dump()
    res["cin_migration_findings"] = findings
    return res

# --- Orchestrator ---
def analyze_units(units: List[Unit]) -> List[Dict[str, Any]]:
    out = []
    for idx, u in enumerate(units):
        res = scan_unit(idx, u)
        # Only include unit if findings present
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
