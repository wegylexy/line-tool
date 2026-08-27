use crate::generic::{self, Filter};
use crate::schema::Schema;
use rusqlite::Connection;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tiny_http::{Header, Response, Server};

#[derive(Serialize)]
struct ErrorOut {
    error: String,
}

pub struct ServerConfig {
    pub edb_path: PathBuf,
    pub tmp_db_path: PathBuf,
    pub passphrase: String,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
}

pub struct DbState {
    pub config: ServerConfig,
    pub last_mtime: SystemTime,
    pub con: Connection,
    pub schema: Schema,
}

impl DbState {
    /// Returns true if the incoming query explicitly restricts the results to records
    /// created/modified at or before `self.last_mtime`, making re-decryption unnecessary.
    fn can_skip_reload(&self, parsed_filters: &[(String, String, String)]) -> bool {
        let last_mtime_ms = match self.last_mtime.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_millis() as i64,
            Err(_) => return false,
        };

        for (field, op, value) in parsed_filters {
            // Check 1: $date filter with upper bound
            // createdTime$date=2026-08-18 (day end <= last_mtime)
            // createdTime$date<=2026-08-18 (day end <= last_mtime)
            // createdTime$date<2026-08-18 (day start <= last_mtime)
            if let Some(_col) = field.strip_suffix("$date") {
                let upper_bound = match op.as_str() {
                    "=" | "<=" => crate::extract::to_epoch_ms(value, true).ok(),
                    "<" => crate::extract::to_epoch_ms(value, false).ok(),
                    _ => None,
                };
                if let Some(bound_ms) = upper_bound {
                    if bound_ms <= last_mtime_ms {
                        return true;
                    }
                }
            }

            // Check 2: Direct numeric timestamp filter (e.g. createdTime<=1700000000000, createdTime<1700000000000, createdTime=...)
            let lower = field.to_ascii_lowercase();
            if lower.contains("time") || lower.contains("date") {
                if matches!(op.as_str(), "=" | "<=" | "<") {
                    if let Ok(bound_ms) = value.parse::<i64>() {
                        if bound_ms <= last_mtime_ms {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Checks if the underlying .edb file has been modified since last read.
    /// If changed (and not skipped by an upper-bound filter), re-decrypts the database.
    /// If decryption fails (e.g. key rotated/changed), re-scans process memory for the new key.
    pub fn ensure_fresh(
        &mut self,
        parsed_filters: &[(String, String, String)],
    ) -> anyhow::Result<()> {
        let meta = match std::fs::metadata(&self.config.edb_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!(
                    "[!] Warning: failed to check metadata for {}: {e}",
                    self.config.edb_path.display()
                );
                return Ok(());
            }
        };

        let current_mtime = match meta.modified() {
            Ok(t) => t,
            Err(_) => return Ok(()),
        };

        if current_mtime <= self.last_mtime {
            return Ok(());
        }

        if self.can_skip_reload(parsed_filters) {
            return Ok(());
        }

        eprintln!("[*] Source .edb modified on disk, refreshing decrypted database...");

        // Try decrypting with cached passphrase
        let decrypt_result = crate::crypto::decrypt_sqlite_file(
            &self.config.edb_path,
            &self.config.tmp_db_path,
            &self.config.passphrase,
        );

        let mut success = false;
        if decrypt_result.is_ok() {
            if let Ok(new_con) = Connection::open(&self.config.tmp_db_path) {
                if let Ok(new_schema) = crate::schema::load(&new_con) {
                    self.con = new_con;
                    self.schema = new_schema;
                    self.last_mtime = current_mtime;
                    success = true;
                    eprintln!("[*] Database successfully reloaded.");
                }
            }
        }

        if !success {
            eprintln!("[!] Decryption/schema reload failed with cached passphrase; re-scanning process memory for key...");
            let new_key =
                crate::resolve_passphrase(self.config.process_name.as_deref(), self.config.pid)?;
            self.config.passphrase = new_key;
            crate::crypto::decrypt_sqlite_file(
                &self.config.edb_path,
                &self.config.tmp_db_path,
                &self.config.passphrase,
            )?;
            let new_con = Connection::open(&self.config.tmp_db_path)?;
            let new_schema = crate::schema::load(&new_con)?;
            self.con = new_con;
            self.schema = new_schema;
            self.last_mtime = current_mtime;
            eprintln!("[*] Database successfully re-decrypted with recovered key and reloaded.");
        }

        Ok(())
    }
}

/// Minimal percent-decoder for query-string values (application/x-www-form-urlencoded `+` and `%XX`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits a fully percent-decoded `field<op>value` string into its parts,
/// checking 3-char operators (`>!=`, `<!=`), 2-char operators (`>=`, `<=`, `!=`, `^=`, `*=`, `$=`),
/// and 1-char operators (`>`, `<`, `=`). Also handles bare boolean flags (e.g. `isArchived` -> `isArchived=1`,
/// `!isArchived` -> `isArchived=0`).
fn split_operator(s: &str) -> (String, String, String) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'>' if bytes.get(i + 1) == Some(&b'!') && bytes.get(i + 2) == Some(&b'=') => {
                return (s[..i].to_string(), ">".to_string(), s[i + 3..].to_string())
            }
            b'<' if bytes.get(i + 1) == Some(&b'!') && bytes.get(i + 2) == Some(&b'=') => {
                return (s[..i].to_string(), "<".to_string(), s[i + 3..].to_string())
            }
            b'>' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), ">=".to_string(), s[i + 2..].to_string())
            }
            b'<' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), "<=".to_string(), s[i + 2..].to_string())
            }
            b'!' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), "!=".to_string(), s[i + 2..].to_string())
            }
            b'^' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), "^=".to_string(), s[i + 2..].to_string())
            }
            b'*' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), "*=".to_string(), s[i + 2..].to_string())
            }
            b'$' if bytes.get(i + 1) == Some(&b'=') => {
                return (s[..i].to_string(), "$=".to_string(), s[i + 2..].to_string())
            }
            b'>' => return (s[..i].to_string(), ">".to_string(), s[i + 1..].to_string()),
            b'<' => return (s[..i].to_string(), "<".to_string(), s[i + 1..].to_string()),
            b'=' => return (s[..i].to_string(), "=".to_string(), s[i + 1..].to_string()),
            _ => i += 1,
        }
    }
    // No operator found: handle boolean shorthand:
    // `!flag` -> (field: "flag", op: "=", value: "0")
    // `flag`  -> (field: "flag", op: "=", value: "1")
    if let Some(stripped) = s.strip_prefix('!') {
        (stripped.to_string(), "=".to_string(), "0".to_string())
    } else {
        (s.to_string(), "=".to_string(), "1".to_string())
    }
}

/// Parses `?a=1&b>=2&c*=foo` into `(field, op, value)` triples. Each
/// `key=value` pair from `&`-splitting is percent-decoded as a whole BEFORE
/// operator-scanning, so an encoded `%3E` (`>`) is recognized the same as a
/// literal `>`.
fn parse_query(url: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    if let Some((_, q)) = url.split_once('?') {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let decoded = percent_decode(pair);
            out.push(split_operator(&decoded));
        }
    }
    out
}

fn json_response(status: u16, body: &impl Serialize) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::from_data(data)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json; charset=utf-8"[..],
            )
            .unwrap(),
        )
}

fn json_raw(status: u16, body: serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::from_data(data)
        .with_status_code(status)
        .with_header(
            Header::from_bytes(
                &b"Content-Type"[..],
                &b"application/json; charset=utf-8"[..],
            )
            .unwrap(),
        )
}

/// Percent-encodes everything outside the URL-unreserved set, so the
/// reconstructed field text (which may itself contain `>`, `$`, etc. as part
/// of an operator) round-trips safely as a single query-string component.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Rebuilds this request's query string with `$cursor` replaced (or added)
/// so a `Link: <url>; rel="next"` header can point straight at the next page
/// without the client having to hand-assemble it. Each pair is `field + op +
/// value` concatenated raw (not `field=value`) because our operators already
/// carry their own `=` where needed (`>=`, `$sort=`, ...) - there's no
/// separate structural delimiter to reinsert on top of that.
fn build_next_link(path: &str, parsed: &[(String, String, String)], next_cursor: &str) -> String {
    let mut pairs: Vec<String> = parsed
        .iter()
        .filter(|(field, _, _)| field != "$cursor")
        .map(|(field, op, value)| percent_encode(&format!("{field}{op}{value}")))
        .collect();
    pairs.push(percent_encode(&format!("$cursor={next_cursor}")));
    format!("{path}?{}", pairs.join("&"))
}

/// GET /{table}?{col}=v&{col}>=v&{col}^=v&{col}*=v&{col}$=v&$sort=&$limit=&$cursor=... -
/// generic reflection over any `_`-prefixed table, validated against
/// `schema`. A leading `$` marks a reserved control param (`$sort`, `$limit`,
/// `$cursor`) so it can never collide with a real column name - every real
/// column here starts with `_`, never `$`, so there's no ambiguity to resolve.
/// See README for the full param grammar.
fn handle_table(
    con: &Connection,
    schema: &Schema,
    table_key: &str,
    parsed: &[(String, String, String)],
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut reserved: Vec<(&str, &str)> = Vec::new();
    let mut filters: Vec<Filter> = Vec::new();
    for (field, op, value) in parsed {
        if let Some(name) = field.strip_prefix('$') {
            reserved.push((name, value.as_str()));
        } else {
            filters.push(Filter {
                field: field.clone(),
                op: op.clone(),
                value: value.clone(),
            });
        }
    }

    match generic::query_table(con, schema, table_key, &filters, &reserved) {
        Ok(result) => {
            let mut resp = json_raw(
                200,
                serde_json::json!({
                    "rows": result.rows,
                    "next_cursor": result.next_cursor,
                }),
            );
            // No `rel="prev"`: pure forward keyset pagination has no
            // well-defined "previous page" without extra state (the client
            // would need to have kept its own earlier cursors, or the
            // request would need to flip $sort and requery from the start).
            if let Some(next_cursor) = &result.next_cursor {
                let link = build_next_link(&format!("/{table_key}"), parsed, next_cursor);
                if let Ok(header) =
                    Header::from_bytes(&b"Link"[..], format!("<{link}>; rel=\"next\"").as_bytes())
                {
                    resp = resp.with_header(header);
                }
            }
            resp
        }
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.starts_with("unknown table") {
                404
            } else if msg.starts_with("unknown column")
                || msg.starts_with("unknown sort column")
                || msg.starts_with("'cursor'")
                || msg.starts_with("'limit'")
            {
                400
            } else {
                500
            };
            json_response(status, &ErrorOut { error: msg })
        }
    }
}

fn html_response(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_data(body.as_bytes().to_vec())
        .with_status_code(status)
        .with_header(
            Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
        )
}

/// Serves one already-bound listener until the process exits. Runs on
/// whichever thread calls it - the caller decides which listener owns the
/// current thread and which run in spawned background threads.
fn serve_on(server: Server, state: Arc<Mutex<DbState>>) {
    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let parsed = parse_query(&url);
        let table_key = path.trim_start_matches('/');

        // Docs / UI routes
        if table_key == "docs" || table_key == "scalar" || table_key.is_empty() {
            let html = crate::openapi::generate_scalar_html("/openapi.json");
            let _ = request.respond(html_response(200, &html));
            continue;
        }

        let mut guard = state.lock().unwrap();

        // OpenAPI JSON route
        if table_key == "openapi.json" || table_key == "openapi" {
            let spec = crate::openapi::generate_openapi_spec(&guard.schema);
            let resp = json_raw(200, spec);
            drop(guard);
            let _ = request.respond(resp);
            continue;
        }

        if let Err(e) = guard.ensure_fresh(&parsed) {
            eprintln!("[!] Database refresh error: {e}");
        }

        let response = handle_table(&guard.con, &guard.schema, table_key, &parsed);
        drop(guard);

        let _ = request.respond(response);
    }
}

/// Binds every address in `addrs`, logging (not failing) any individual bind
/// that doesn't come up - e.g. IPv6 disabled/unsupported on this host - and
/// only erroring out if none of them bind. All listeners share one managed
/// database state.
pub fn run(
    addrs: &[String],
    config: ServerConfig,
    last_mtime: SystemTime,
    con: Connection,
    schema: Schema,
) -> anyhow::Result<()> {
    let mut servers = Vec::new();
    for addr in addrs {
        match Server::http(addr) {
            Ok(s) => {
                eprintln!("[*] Listening on http://{addr}");
                servers.push(s);
            }
            Err(e) => eprintln!("[!] Skipping {addr}: {e}"),
        }
    }
    if servers.is_empty() {
        return Err(anyhow::anyhow!(
            "failed to bind any of: {}",
            addrs.join(", ")
        ));
    }

    let mut table_names: Vec<&String> = schema.tables.keys().collect();
    table_names.sort();
    eprintln!(
        "[*] Tables: {}",
        table_names
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let no_pk: Vec<&str> = table_names
        .iter()
        .filter(|k| schema.tables[k.as_str()].primary_key.is_empty())
        .map(|s| s.as_str())
        .collect();
    if !no_pk.is_empty() {
        eprintln!(
            "[*] No declared PRIMARY KEY, falling back to rowid as the $sort/$cursor tiebreaker: {}",
            no_pk.join(", ")
        );
    }
    eprintln!(
        "[*] GET /{{table}}?{{col}}=v&{{col}}>=v&{{col}}<=v&{{col}}!=v&{{col}}^=v&{{col}}*=v&{{col}}$=v&{{col}}$date=v&$sort=-createdTime,other&$limit=&$cursor="
    );
    if let Some(first_addr) = addrs.first() {
        eprintln!("[*] API Docs (Scalar UI): http://{first_addr}/docs");
        eprintln!("[*] OpenAPI 3.1 Spec:     http://{first_addr}/openapi.json");
    }

    let state = Arc::new(Mutex::new(DbState {
        config,
        last_mtime,
        con,
        schema,
    }));

    // Run every listener but the last on its own thread; the last one runs
    // on this thread so `run` blocks for the caller like a single-listener
    // server would.
    let mut handles = Vec::new();
    let last = servers.pop().unwrap();
    for server in servers {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || serve_on(server, state)));
    }
    serve_on(last, state);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_can_skip_reload() {
        // Assume last_mtime is fixed at epoch + 1,700,000,000,000 ms (approx 2023-11-14 22:13:20 UTC)
        let last_mtime = UNIX_EPOCH + Duration::from_millis(1_700_000_000_000);
        let state = DbState {
            config: ServerConfig {
                edb_path: PathBuf::from("dummy.edb"),
                tmp_db_path: PathBuf::from("dummy.db"),
                passphrase: "dummy".into(),
                process_name: None,
                pid: None,
            },
            last_mtime,
            con: Connection::open_in_memory().unwrap(),
            schema: Schema {
                tables: HashMap::new(),
            },
        };

        // Query with explicit createdTime upper bound <= last_mtime -> should skip
        let filters_older = vec![(
            "createdTime".to_string(),
            "<=".to_string(),
            "1600000000000".to_string(),
        )];
        assert!(state.can_skip_reload(&filters_older));

        // Query with explicit createdTime upper bound > last_mtime -> should NOT skip
        let filters_newer = vec![(
            "createdTime".to_string(),
            "<=".to_string(),
            "1800000000000".to_string(),
        )];
        assert!(!state.can_skip_reload(&filters_newer));

        // Query with lower bound only (>=) -> should NOT skip
        let filters_lower_only = vec![(
            "createdTime".to_string(),
            ">=".to_string(),
            "1600000000000".to_string(),
        )];
        assert!(!state.can_skip_reload(&filters_lower_only));

        // Query with $date in 2020 (way before 2023) -> should skip
        let filters_date_old = vec![(
            "createdTime$date".to_string(),
            "=".to_string(),
            "2020-01-01".to_string(),
        )];
        assert!(state.can_skip_reload(&filters_date_old));

        // Query with $date in 2030 (after 2023) -> should NOT skip
        let filters_date_future = vec![(
            "createdTime$date".to_string(),
            "=".to_string(),
            "2030-01-01".to_string(),
        )];
        assert!(!state.can_skip_reload(&filters_date_future));
    }

    #[test]
    fn test_split_operator_and_booleans() {
        // Strict operators
        assert_eq!(
            split_operator("createdTime>!=100"),
            (
                "createdTime".to_string(),
                ">".to_string(),
                "100".to_string()
            )
        );
        assert_eq!(
            split_operator("createdTime<!=100"),
            (
                "createdTime".to_string(),
                "<".to_string(),
                "100".to_string()
            )
        );

        // Standard 2-char operators
        assert_eq!(
            split_operator("createdTime>=100"),
            (
                "createdTime".to_string(),
                ">=".to_string(),
                "100".to_string()
            )
        );
        assert_eq!(
            split_operator("createdTime<=100"),
            (
                "createdTime".to_string(),
                "<=".to_string(),
                "100".to_string()
            )
        );
        assert_eq!(
            split_operator("name*=test"),
            ("name".to_string(), "*=".to_string(), "test".to_string())
        );

        // Booleans
        assert_eq!(
            split_operator("isArchived"),
            ("isArchived".to_string(), "=".to_string(), "1".to_string())
        );
        assert_eq!(
            split_operator("!isArchived"),
            ("isArchived".to_string(), "=".to_string(), "0".to_string())
        );
        assert_eq!(
            split_operator("isArchived=true"),
            (
                "isArchived".to_string(),
                "=".to_string(),
                "true".to_string()
            )
        );
    }
}
