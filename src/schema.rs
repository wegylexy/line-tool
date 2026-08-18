use anyhow::Result;
use rusqlite::Connection;
use std::collections::HashMap;

pub struct ColumnInfo {
    pub real_name: String,
    pub decl_type: String,
}

pub struct TableInfo {
    pub real_name: String,
    pub columns: HashMap<String, ColumnInfo>,
    /// Stripped (no leading `_`) column keys making up the declared PRIMARY
    /// KEY, in key-column order (from `PRAGMA table_info`'s `pk` field) -
    /// directly usable to look up `columns`. Empty if the table has none
    /// declared (rare - falls back to SQLite's implicit `rowid`).
    pub primary_key: Vec<String>,
}

pub struct Schema {
    pub tables: HashMap<String, TableInfo>,
}

fn strip_prefix_underscore(s: &str) -> String {
    s.strip_prefix('_').unwrap_or(s).to_string()
}

/// Introspects every `_`-prefixed table and its columns once at startup, so
/// the generic REST route only ever interpolates identifiers taken from this
/// whitelist into SQL text - never from a request - while values stay bound
/// as parameters.
pub fn load(con: &Connection) -> Result<Schema> {
    let mut tables = HashMap::new();

    let mut stmt = con.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '\\_%' ESCAPE '\\'",
    )?;
    let table_names: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    drop(stmt);

    for real_table in table_names {
        let quoted = real_table.replace('"', "\"\"");
        let mut col_stmt = con.prepare(&format!("PRAGMA table_info(\"{quoted}\")"))?;
        // table_info columns: cid, name, type, notnull, dflt_value, pk
        let cols: Vec<(String, String, i64)> = col_stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(5)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut columns = HashMap::new();
        let mut pk_cols: Vec<(i64, String)> = Vec::new(); // (pk index, stripped column key)
        for (real_col, decl_type, pk) in cols {
            let key = strip_prefix_underscore(&real_col);
            if pk > 0 {
                pk_cols.push((pk, key.clone()));
            }
            columns.insert(
                key,
                ColumnInfo {
                    real_name: real_col,
                    decl_type,
                },
            );
        }
        pk_cols.sort_by_key(|(idx, _)| *idx);
        let primary_key = pk_cols.into_iter().map(|(_, name)| name).collect();

        tables.insert(
            strip_prefix_underscore(&real_table),
            TableInfo {
                real_name: real_table,
                columns,
                primary_key,
            },
        );
    }

    Ok(Schema { tables })
}
