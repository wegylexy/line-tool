use crate::schema::Schema;
use anyhow::{anyhow, Result};
use rusqlite::types::{ToSql, ValueRef};
use rusqlite::Connection;
use serde_json::{Map, Value};

const ROWID_KEY: &str = "__lt_rowid__";

/// One parsed query-string filter: `field <op> value`, e.g. `("createdTime", ">=", "12345")`.
pub struct Filter {
    pub field: String,
    pub op: String,
    pub value: String,
}

fn bind_for(decl_type: &str, raw: &str) -> Box<dyn ToSql> {
    let ty = decl_type.to_ascii_uppercase();
    if ty.contains("INT") {
        if let Ok(v) = raw.parse::<i64>() {
            return Box::new(v);
        }
    } else if ty.contains("REAL") || ty.contains("FLOA") || ty.contains("DOUB") {
        if let Ok(v) = raw.parse::<f64>() {
            return Box::new(v);
        }
    }
    Box::new(raw.to_string())
}

fn value_ref_to_json(v: ValueRef) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => Value::from(f),
        ValueRef::Text(t) => Value::from(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::from(format!("<blob:{}bytes>", b.len())),
    }
}

fn json_value_to_cursor_part(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

pub struct QueryResult {
    pub rows: Vec<Map<String, Value>>,
    pub next_cursor: Option<String>,
}

/// One `$sort=` term, either caller-specified or an implicit trailing
/// tiebreaker we append automatically (the table's primary key, or `rowid`
/// if it has none) so keyset pagination is a total order even when the
/// caller's own sort columns aren't unique.
struct SortKey {
    key: String,       // JSON row key this term reads back from
    real_name: String, // SQL identifier/expression: a real column, or bare `rowid`
    decl_type: String,
    desc: bool,
    exposed: bool, // false only for the synthetic rowid fallback - not a real column
}

/// Builds and runs `SELECT * FROM {table} WHERE ... ORDER BY ... LIMIT ...`
/// from parsed query-string filters, validating every column name against
/// `schema` before it ever reaches the SQL string. Table/column identifiers
/// are only ever the whitelisted real names from `schema` - all filter/cursor
/// values stay bound as parameters.
pub fn query_table(
    con: &Connection,
    schema: &Schema,
    table_key: &str,
    filters: &[Filter],
    reserved: &[(&str, &str)],
) -> Result<QueryResult> {
    let table = schema
        .tables
        .get(table_key)
        .ok_or_else(|| anyhow!("unknown table '{table_key}'"))?;

    let mut wheres = Vec::new();
    let mut binds: Vec<Box<dyn ToSql>> = Vec::new();

    for f in filters {
        if let Some(col_key) = f.field.strip_suffix("$date") {
            let col = table
                .columns
                .get(col_key)
                .ok_or_else(|| anyhow!("unknown column '{col_key}' on table '{table_key}'"))?;
            // `=` means "that whole local calendar day": expand to a range.
            // For a one-sided bound, `>=`/`<` anchor on the day's start and
            // `<=`/`>` on the day's end, so `$date>2026-08-18` excludes the
            // whole day rather than admitting its later hours.
            match f.op.as_str() {
                "=" => {
                    let start = crate::extract::to_epoch_ms(&f.value, false)?;
                    let end = crate::extract::to_epoch_ms(&f.value, true)?;
                    wheres.push(format!(
                        "(\"{}\" >= ? AND \"{}\" <= ?)",
                        col.real_name, col.real_name
                    ));
                    binds.push(Box::new(start));
                    binds.push(Box::new(end));
                }
                ">=" | "<" => {
                    let v = crate::extract::to_epoch_ms(&f.value, false)?;
                    wheres.push(format!("\"{}\" {} ?", col.real_name, f.op));
                    binds.push(Box::new(v));
                }
                "<=" | ">" => {
                    let v = crate::extract::to_epoch_ms(&f.value, true)?;
                    wheres.push(format!("\"{}\" {} ?", col.real_name, f.op));
                    binds.push(Box::new(v));
                }
                other => {
                    return Err(anyhow!(
                        "unsupported operator '{other}' with $date on field '{col_key}'"
                    ))
                }
            }
            continue;
        }

        // CSS-attribute-selector-style string matches: `^=` starts-with,
        // `*=` contains, `$=` ends-with - each is `LIKE` with the wildcard
        // placed for the caller, so callers never need to embed `%` themselves.
        let (sql_op, like_value): (&str, Option<String>) = match f.op.as_str() {
            "=" | ">" | "<" | ">=" | "<=" | "!=" => (f.op.as_str(), None),
            "^=" => ("LIKE", Some(format!("{}%", f.value))),
            "*=" => ("LIKE", Some(format!("%{}%", f.value))),
            "$=" => ("LIKE", Some(format!("%{}", f.value))),
            other => {
                return Err(anyhow!(
                    "unsupported operator '{other}' on field '{}'",
                    f.field
                ))
            }
        };

        let col = table
            .columns
            .get(f.field.as_str())
            .ok_or_else(|| anyhow!("unknown column '{}' on table '{table_key}'", f.field))?;
        wheres.push(format!("\"{}\" {} ?", col.real_name, sql_op));
        match like_value {
            Some(v) => binds.push(Box::new(v)),
            None => binds.push(bind_for(&col.decl_type, &f.value)),
        }
    }

    let get_reserved = |key: &str| reserved.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);

    // `$sort=-createdTime,name` -> ORDER BY "createdTime" DESC, "name" ASC
    let mut sort_keys: Vec<SortKey> = Vec::new();
    if let Some(spec) = get_reserved("sort") {
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (desc, col_key) = match part.strip_prefix('-') {
                Some(c) => (true, c),
                None => (false, part),
            };
            let col = table
                .columns
                .get(col_key)
                .ok_or_else(|| anyhow!("unknown sort column '{col_key}' on table '{table_key}'"))?;
            sort_keys.push(SortKey {
                key: col_key.to_string(),
                real_name: col.real_name.clone(),
                decl_type: col.decl_type.clone(),
                desc,
                exposed: true,
            });
        }
    }

    // Any explicit $sort gets an implicit trailing tiebreaker so keyset
    // pagination is a total order even when the caller's own sort columns
    // aren't unique (e.g. `_message.createdTime` has real collisions in
    // practice - two messages can share the same millisecond). Prefer the
    // table's declared primary key (skipping any PK column already given
    // explicitly); fall back to SQLite's implicit `rowid` only if the table
    // has no declared PK at all.
    if !sort_keys.is_empty() {
        if !table.primary_key.is_empty() {
            for pk_key in &table.primary_key {
                if sort_keys.iter().any(|sk| &sk.key == pk_key) {
                    continue;
                }
                let col = &table.columns[pk_key];
                sort_keys.push(SortKey {
                    key: pk_key.clone(),
                    real_name: col.real_name.clone(),
                    decl_type: col.decl_type.clone(),
                    desc: false,
                    exposed: true,
                });
            }
        } else {
            sort_keys.push(SortKey {
                key: ROWID_KEY.to_string(),
                real_name: "rowid".to_string(),
                decl_type: "INTEGER".to_string(),
                desc: false,
                exposed: false,
            });
        }
    }

    // Keyset pagination: strictly "after" the cursor's tuple of sort-key
    // values, in sort order - equality on every earlier term, strict
    // inequality only on the first term that doesn't tie:
    // (k1 >< v1) OR (k1=v1 AND k2 >< v2) OR (k1=v1 AND k2=v2 AND k3 >< v3) OR ...
    if let Some(cursor) = get_reserved("cursor") {
        if sort_keys.is_empty() {
            return Err(anyhow!("'cursor' requires 'sort' to be set"));
        }
        let cursor_vals: Vec<&str> = cursor.split(',').collect();
        if cursor_vals.len() != sort_keys.len() {
            return Err(anyhow!(
                "'cursor' must be echoed back verbatim from a previous response's next_cursor \
                 (expected {} comma-separated value(s), got {})",
                sort_keys.len(),
                cursor_vals.len()
            ));
        }

        let mut or_clauses = Vec::with_capacity(sort_keys.len());
        for i in 0..sort_keys.len() {
            let mut and_parts = Vec::with_capacity(i + 1);
            for sk in &sort_keys[..i] {
                and_parts.push(format!("\"{}\" = ?", sk.real_name));
            }
            let sk = &sort_keys[i];
            and_parts.push(format!(
                "\"{}\" {} ?",
                sk.real_name,
                if sk.desc { "<" } else { ">" }
            ));
            or_clauses.push(format!("({})", and_parts.join(" AND ")));
        }
        wheres.push(format!("({})", or_clauses.join(" OR ")));

        for i in 0..sort_keys.len() {
            for (sk, val) in sort_keys[..=i].iter().zip(cursor_vals[..=i].iter()) {
                binds.push(bind_for(&sk.decl_type, val));
            }
        }
    }

    let needs_rowid_alias = sort_keys.iter().any(|sk| !sk.exposed);
    let mut sql = if needs_rowid_alias {
        format!(
            "SELECT *, rowid AS \"{ROWID_KEY}\" FROM \"{}\"",
            table.real_name
        )
    } else {
        format!("SELECT * FROM \"{}\"", table.real_name)
    };
    if !wheres.is_empty() {
        sql += " WHERE ";
        sql += &wheres.join(" AND ");
    }
    if !sort_keys.is_empty() {
        sql += " ORDER BY ";
        sql += &sort_keys
            .iter()
            .map(|sk| {
                format!(
                    "\"{}\" {}",
                    sk.real_name,
                    if sk.desc { "DESC" } else { "ASC" }
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
    }
    // Default to a page when $limit is omitted entirely (an unbounded query
    // would otherwise dump the whole table - _message alone has ~400k rows).
    // A request that explicitly asks for more than MAX_LIMIT is rejected
    // rather than silently truncated - unlike a multi-tenant public API,
    // this is queried by hand most of the time, and a silently short page
    // is more likely to mislead than a clear 400.
    const DEFAULT_LIMIT: i64 = 20;
    const MAX_LIMIT: i64 = 100;
    let limit = match get_reserved("limit") {
        Some(s) => s
            .parse::<i64>()
            .map_err(|_| anyhow!("'limit' must be an integer"))?,
        None => DEFAULT_LIMIT,
    };
    if limit < 1 || limit > MAX_LIMIT {
        return Err(anyhow!(
            "'limit' must be between 1 and {MAX_LIMIT}, got {limit}"
        ));
    }
    sql += &format!(" LIMIT {limit}");

    let mut stmt = con.prepare(&sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let bind_refs: Vec<&dyn ToSql> = binds.iter().map(|b| b.as_ref()).collect();

    let mut rows_out = Vec::new();
    let mut rows = stmt.query(bind_refs.as_slice())?;
    while let Some(row) = rows.next()? {
        let mut obj = Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let key = if name == ROWID_KEY {
                name.clone()
            } else {
                name.strip_prefix('_').unwrap_or(name).to_string()
            };
            obj.insert(key, value_ref_to_json(row.get_ref(i)?));
        }
        rows_out.push(obj);
    }

    let next_cursor = if !sort_keys.is_empty() && rows_out.len() as i64 >= limit {
        let last = rows_out.last();
        let parts: Vec<String> = sort_keys
            .iter()
            .map(|sk| json_value_to_cursor_part(last.and_then(|r| r.get(&sk.key))))
            .collect();
        Some(parts.join(","))
    } else {
        None
    };

    // The rowid fallback is an internal tiebreaker, never a real column -
    // strip it back out before returning rows to the client.
    if needs_rowid_alias {
        for row in &mut rows_out {
            row.remove(ROWID_KEY);
        }
    }

    Ok(QueryResult {
        rows: rows_out,
        next_cursor,
    })
}
