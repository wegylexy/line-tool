use crate::generic::{self, Filter};
use crate::schema::Schema;
use rusqlite::Connection;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Response, Server};

#[derive(Serialize)]
struct ErrorOut {
    error: String,
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
/// checking every 2-char operator (`>=`, `<=`, `!=`, `^=`, `*=`, `$=`) before
/// the 1-char ones so e.g. `createdTime>=12345` doesn't get mis-split as
/// `createdTime>` `=12345`. `^=`/`*=`/`$=` are CSS-attribute-selector-style
/// string matches: starts-with / contains / ends-with.
fn split_operator(s: &str) -> (String, String, String) {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
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
    (s.to_string(), "=".to_string(), String::new())
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

/// Serves one already-bound listener until the process exits. Runs on
/// whichever thread calls it - the caller decides which listener owns the
/// current thread and which run in spawned background threads.
fn serve_on(server: Server, con: Arc<Mutex<Connection>>, schema: Arc<Schema>) {
    for request in server.incoming_requests() {
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_string();
        let parsed = parse_query(&url);
        let table_key = path.trim_start_matches('/');

        let guard = con.lock().unwrap();
        let response = if table_key.is_empty() {
            json_response(
                404,
                &ErrorOut {
                    error: "specify a table, e.g. /message?chatId=...".into(),
                },
            )
        } else {
            handle_table(&guard, &schema, table_key, &parsed)
        };
        drop(guard);

        let _ = request.respond(response);
    }
}

/// Binds every address in `addrs`, logging (not failing) any individual bind
/// that doesn't come up - e.g. IPv6 disabled/unsupported on this host - and
/// only erroring out if none of them bind. All listeners share one decrypted
/// connection and schema.
pub fn run(addrs: &[String], con: Connection, schema: Schema) -> anyhow::Result<()> {
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

    let con = Arc::new(Mutex::new(con));
    let schema = Arc::new(schema);

    // Run every listener but the last on its own thread; the last one runs
    // on this thread so `run` blocks for the caller like a single-listener
    // server would.
    let mut handles = Vec::new();
    let last = servers.pop().unwrap();
    for server in servers {
        let con = Arc::clone(&con);
        let schema = Arc::clone(&schema);
        handles.push(std::thread::spawn(move || serve_on(server, con, schema)));
    }
    serve_on(last, con, schema);
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
