# abap_table_migration.py

from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional
import re

app = FastAPI(title="ABAP Table Migration for SAP Note 2877717 (CIN to BP Master)")

# --- Config/Constants ---
ABAP_STMT_SPLIT_RE = re.compile(r"([^.]*.)", re.DOTALL)

SELECT_TABLE_RE = re.compile(
    r"""
    ^\s*
    (SELECT|INSERT|UPDATE|MODIFY)
    [\s\S]*?
    (FROM|JOIN)\s+
    (?P<table>J_1IMOCUST|J_1IMOVEND)\b
    """,
    re.IGNORECASE | re.VERBOSE
)

DECL_START_RE = re.compile(r"^\s*(DATA|TYPES)\s*:\s*", re.IGNORECASE)

TABLE_FIELDS = {
    "J_1IMOCUST": ["KUNNR", "VEN_CLASS", "J_1IPANNO", "J_1IEXCIVE"],
    "J_1IMOVEND": ["LIFNR", "VEN_CLASS", "J_1IPANNO", "J_1IEXCIVE"],
    "KNA1": ["KUNNR", "NAME1", "ORT01", "PSTLZ"],
    "LFA1": ["LIFNR", "NAME1", "ORT01", "PSTLZ"],
}

OLD_TO_NEW_TABLE_MAP = {
    "J_1IMOCUST": {"new_table": "KNA1", "key_field": "KUNNR"},
    "J_1IMOVEND": {"new_table": "LFA1", "key_field": "LIFNR"},
}

CIN_OLD_FIELDS = {"VEN_CLASS", "J_1IPANNO", "J_1IEXCIVE"}


# --- Pydantic Model ---
class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""


# --- Migration Logic ---
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


def migrate_declaration(decl: str, _code: str) -> Optional[str]:
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


def find_table_stmts(code: str):
    stmts = []
    pos = 0
    for m in ABAP_STMT_SPLIT_RE.finditer(code):
        stmt = m.group(1)
        start = pos
        end = pos + len(stmt)
        pos = end

        stmt_type_match = re.match(r"^\s*(SELECT|INSERT|UPDATE|MODIFY)\b", stmt, re.IGNORECASE)
        if not stmt_type_match:
            continue
        stmt_type = stmt_type_match.group(1).upper()

        if stmt_type == "SELECT":
            for tm in re.finditer(r"\b(?:FROM|JOIN)\s+(J_1IMOCUST|J_1IMOVEND)\b", stmt, re.IGNORECASE):
                table = tm.group(1).upper()
                stmts.append(
                    {"full": stmt, "table": table, "span": (start, end), "stmt_type": stmt_type}
                )
        else:
            for tm in re.finditer(r"\b(J_1IMOCUST|J_1IMOVEND)\b", stmt, re.IGNORECASE):
                table = tm.group(1).upper()
                stmts.append(
                    {"full": stmt, "table": table, "span": (start, end), "stmt_type": stmt_type}
                )
    return stmts


def find_declarations(code: str):
    decls = []
    lines = code.splitlines(keepends=True)
    n = len(lines)
    i = 0
    pos = 0

    while i < n:
        line = lines[i]
        if DECL_START_RE.match(line):
            if re.search(r"\bBEGIN\s+OF\b", line, re.IGNORECASE):
                buf = [line]
                end_rel = len(line)
                j = i
                while j + 1 < n:
                    j += 1
                    buf.append(lines[j])
                    end_rel += len(lines[j])
                    if re.search(r"\bEND\s+OF\s+\w+\s*\.\s*$", lines[j], re.IGNORECASE):
                        break
                full = "".join(buf)
                decls.append({"full": full, "span": (pos, pos + end_rel)})
                i = j + 1
                pos += end_rel
                continue
            else:
                buf = [line]
                end_rel = len(line)
                j = i
                while j + 1 < n and not re.search(r"\.\s*$", lines[j], re.IGNORECASE):
                    j += 1
                    buf.append(lines[j])
                    end_rel += len(lines[j])
                    if re.search(r"\.\s*$", lines[j], re.IGNORECASE):
                        break
                full = "".join(buf)
                decls.append({"full": full, "span": (pos, pos + end_rel)})
                i = j + 1
                pos += end_rel
                continue
        i += 1
        pos += len(line)
    return decls


# --- FastAPI Endpoint ---
@app.post("/remediate-array")
async def remediate_array(units: List[Unit]):
    results = []
    for u in units:
        src = u.code or ""
        stmts = find_table_stmts(src)
        decls = find_declarations(src)
        selects_metadata = []

        for stmt in stmts:
            tbl = stmt["table"]
            sel_info = {
                "table": tbl,
                "target_type": None,
                "target_name": None,
                                "start_char_in_unit": stmt["span"][0],
                "end_char_in_unit": stmt["span"][1],
                "used_fields": [],
                "ambiguous": False,
                "suggested_fields": None,
                "suggested_statement": None,
            }
            new_stmt = migrate_cin_table(stmt["full"], tbl)
            if new_stmt != stmt["full"]:
                sel_info["suggested_statement"] = new_stmt
            selects_metadata.append(sel_info)

        for decl in decls:
            migrated = migrate_declaration(decl["full"], src)
            if migrated and migrated != decl["full"]:
                decl_info = {
                    "table": None,
                    "target_type": None,
                    "target_name": None,
                    "start_char_in_unit": decl["span"][0],
                    "end_char_in_unit": decl["span"][1],
                    "used_fields": [],
                    "ambiguous": False,
                    "suggested_fields": None,
                    "suggested_statement": migrated,
                }
                selects_metadata.append(decl_info)

        # Support for both Pydantic v1 and v2
        try:
            obj = u.model_dump()  # Pydantic v2
        except AttributeError:
            obj = u.dict()         # Pydantic v1
        obj["selects"] = selects_metadata
        results.append(obj)

    return results