from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Tuple
import re
import json

app = FastAPI(title="ABAP Table Migration for SAP Note 2877717 (CIN to BP Master)")

TABLE_STMT_RE = re.compile(
    r"""(?P<full>
            \b(SELECT|INSERT|UPDATE|MODIFY)\b
            (?P<before_table>.*?\bFROM\b|\s+)   
            \s*(?P<table>J_1IMOCUST|J_1IMOVEND)\b
            (?P<after_table>.*?)
        )\.""",
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)

OLD_TO_NEW_TABLE_MAP = {
    "J_1IMOCUST": {"new_table": "KNA1", "key_field": "KUNNR"},
    "J_1IMOVEND": {"new_table": "LFA1", "key_field": "LIFNR"},
}

CIN_OLD_FIELDS = {"VEN_CLASS", "J_1IPANNO", "J_1IEXCIVE"}

class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    code: Optional[str] = ""

def migrate_cin_table(stmt: str, table: str) -> str:
    """Replace old CIN table usages with KNA1/LFA1 and adjust fields with TODOs."""
    table_up = table.upper()
    mapping = OLD_TO_NEW_TABLE_MAP[table_up]
    new_table = mapping["new_table"]
    key_field = mapping["key_field"]

    new_stmt = re.sub(rf"\b{table}\b", new_table, stmt, flags=re.IGNORECASE)

    stmt_type_match = re.match(r"(SELECT|INSERT|UPDATE|MODIFY)", stmt.strip(), re.IGNORECASE)
    stmt_type = stmt_type_match.group(1).upper() if stmt_type_match else ""

    todo_comment = ""

    if stmt_type == "SELECT":
        m = re.match(r"SELECT\s+(.*?)\s+FROM", stmt, re.IGNORECASE | re.DOTALL)
        if m:
            fields_str = m.group(1).strip()
            if fields_str != "*":
                fields = [f.strip() for f in fields_str.split(",")]
                removed_fields = [f for f in fields if f.upper() in CIN_OLD_FIELDS]
                filtered_fields = [f for f in fields if f.upper() not in CIN_OLD_FIELDS]
                # Force include key field if removed everything or key missing
                if not filtered_fields or key_field not in map(str.upper, filtered_fields):
                    filtered_fields = [key_field]
                new_fields_str = ", ".join(filtered_fields)
                new_stmt = re.sub(re.escape(fields_str), new_fields_str, new_stmt, count=1)
                if removed_fields:
                    todo_comment = f"* TODO: Add equivalent field(s) from {new_table} for removed CIN fields: {', '.join(removed_fields)}"
            else:
                # SELECT *
                todo_comment = f"* TODO: Review fields from {new_table} to replace CIN fields where relevant."

    elif stmt_type in ("UPDATE", "MODIFY", "INSERT"):
        # Overwrite all field lists with key field only
        # Find SET clause fields
        set_match = re.search(r"\bSET\b\s+(.*?)\s+WHERE", new_stmt, flags=re.IGNORECASE | re.DOTALL)
        if set_match:
            new_stmt = re.sub(r"\bSET\b\s+(.*?)\s+WHERE", f"SET {key_field} = <value> WHERE", new_stmt, flags=re.IGNORECASE | re.DOTALL)
        todo_comment = f"* TODO: Add equivalent field(s) from {new_table} for CIN fields to be maintained."

    if todo_comment:
        new_stmt = todo_comment + "\n" + new_stmt

    return re.sub(r"\s+", " ", new_stmt).strip()

def find_table_stmts(code: str):
    out = []
    for m in TABLE_STMT_RE.finditer(code):
        out.append({
            "full": m.group("full"),
            "table": m.group("table"),
            "span": m.span(0),
            "stmt_type": re.match(r"(SELECT|INSERT|UPDATE|MODIFY)", m.group("full"), re.IGNORECASE).group(1).upper()
        })
    return out

def apply_span_replacements(src: str, repls: List[Tuple[Tuple[int, int], str]]) -> str:
    out = src
    for (s, e), r in sorted(repls, key=lambda x: x[0][0], reverse=True):
        out = out[:s] + r + out[e:]
    return out

@app.post("/remediate-array")
def remediate_array(units: List[Unit]):
    results = []
    for u in units:
        src = u.code or ""
        stmts = find_table_stmts(src)
        replacements = []
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
                "suggested_statement": None
            }
            new_stmt = migrate_cin_table(stmt["full"], tbl)
            if new_stmt != stmt["full"]:
                replacements.append((stmt["span"], new_stmt))
                sel_info["suggested_statement"] = new_stmt
            selects_metadata.append(sel_info)

        _ = apply_span_replacements(src, replacements)

        obj = json.loads(u.model_dump_json())
        obj["selects"] = selects_metadata
        results.append(obj)

    return results