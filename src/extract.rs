use anyhow::{anyhow, Result};
use chrono::{Local, NaiveDate, TimeZone};
use rusqlite::Connection;

pub struct Row {
    pub from_mid: String,
    pub created_ms: i64,
    pub text: Option<String>,
}

/// Group chats only — never touches `_contact`.
pub fn lookup_group_candidates(con: &Connection, name: &str) -> Result<Vec<(String, String)>> {
    let like = format!("%{name}%");
    let mut stmt =
        con.prepare("SELECT _chatMid, _chatName FROM _groupChat WHERE _chatName LIKE ?1")?;
    let rows = stmt
        .query_map([&like], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// 1:1 contacts only — never touches `_groupChat`. Same underlying query as
/// `lookup_sender_candidates`, kept as a separate name since callers use it
/// for a different purpose (resolving the target chat, not the message sender).
pub fn lookup_contact_candidates(con: &Connection, name: &str) -> Result<Vec<(String, String)>> {
    lookup_sender_candidates(con, name)
}

pub fn lookup_sender_candidates(con: &Connection, name: &str) -> Result<Vec<(String, String)>> {
    let like = format!("%{name}%");
    let mut stmt =
        con.prepare("SELECT _mid, _displayName FROM _contact WHERE _displayName LIKE ?1")?;
    let rows = stmt
        .query_map([&like], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            ))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Resolves the target chat's mid from exactly one source: an exact id, a
/// group name, or a contact name. Never merges group/contact name search —
/// giving more than one of these is a caller error, not a priority order.
pub fn resolve_chat_id(
    con: &Connection,
    chat_id: Option<&str>,
    group_name: Option<&str>,
    contact_name: Option<&str>,
) -> Result<String> {
    if let Some(id) = chat_id {
        return Ok(id.to_string());
    }
    match (group_name, contact_name) {
        (Some(_), Some(_)) => Err(anyhow!(
            "specify only one of --group / --contact (or --chat-id) — not both"
        )),
        (Some(name), None) => {
            let rows = lookup_group_candidates(con, name)?;
            if rows.is_empty() {
                return Err(anyhow!("no group chat matching '{name}' found"));
            }
            if rows.len() > 1 {
                eprintln!("[*] Multiple group matches found, using the first one (use --chat-id to pin one):");
                for r in &rows {
                    eprintln!("    {:?}", r);
                }
            }
            Ok(rows[0].0.clone())
        }
        (None, Some(name)) => {
            let rows = lookup_contact_candidates(con, name)?;
            if rows.is_empty() {
                return Err(anyhow!("no contact matching '{name}' found"));
            }
            if rows.len() > 1 {
                eprintln!("[*] Multiple contact matches found, using the first one (use --chat-id to pin one):");
                for r in &rows {
                    eprintln!("    {:?}", r);
                }
            }
            Ok(rows[0].0.clone())
        }
        (None, None) => Err(anyhow!("no --chat-id/--group/--contact given")),
    }
}

pub fn resolve_sender_id(
    con: &Connection,
    sender_id: Option<&str>,
    sender_name: Option<&str>,
) -> Result<Option<String>> {
    if let Some(id) = sender_id {
        return Ok(Some(id.to_string()));
    }
    let Some(name) = sender_name else {
        return Ok(None);
    };
    let rows = lookup_sender_candidates(con, name)?;
    if rows.is_empty() {
        return Err(anyhow!("no contact matching '{name}' found"));
    }
    if rows.len() > 1 {
        eprintln!(
            "[*] Multiple sender matches found, using the first one (use --sender-id to pin one):"
        );
        for r in &rows {
            eprintln!("    {:?}", r);
        }
    }
    Ok(Some(rows[0].0.clone()))
}

/// Interprets date_str as a LOCAL calendar date and returns UTC epoch ms.
pub fn to_epoch_ms(date_str: &str, end_of_day: bool) -> Result<i64> {
    let date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")?;
    let naive_dt = if end_of_day {
        date.and_hms_milli_opt(23, 59, 59, 999).unwrap()
    } else {
        date.and_hms_opt(0, 0, 0).unwrap()
    };
    let local = Local
        .from_local_datetime(&naive_dt)
        .single()
        .ok_or_else(|| anyhow!("ambiguous local datetime"))?;
    Ok(local.timestamp_millis())
}

pub fn today_local_date() -> String {
    Local::now().format("%Y-%m-%d").to_string()
}

pub fn extract(
    con: &Connection,
    chat_id: &str,
    sender_id: Option<&str>,
    start_ms: Option<i64>,
    end_ms: Option<i64>,
    limit: Option<i64>,
    ascending: bool,
    cursor_ms: Option<i64>,
) -> Result<Vec<Row>> {
    let mut query =
        String::from("SELECT _from, _createdTime, _text FROM _message WHERE _chatId = ?1");
    let mut idx = 2;
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(chat_id.to_string())];

    if let Some(s) = sender_id {
        query += &format!(" AND _from = ?{idx}");
        params.push(Box::new(s.to_string()));
        idx += 1;
    }
    if let Some(s) = start_ms {
        query += &format!(" AND _createdTime >= ?{idx}");
        params.push(Box::new(s));
        idx += 1;
    }
    if let Some(e) = end_ms {
        query += &format!(" AND _createdTime <= ?{idx}");
        params.push(Box::new(e));
        idx += 1;
    }
    // Keyset pagination: strictly past the last row's timestamp from the
    // previous page, in whichever direction we're paging.
    if let Some(c) = cursor_ms {
        query += if ascending {
            format!(" AND _createdTime > ?{idx}")
        } else {
            format!(" AND _createdTime < ?{idx}")
        }
        .as_str();
        params.push(Box::new(c));
        idx += 1;
    }
    query += if ascending {
        " ORDER BY _createdTime ASC"
    } else {
        " ORDER BY _createdTime DESC"
    };
    if let Some(l) = limit {
        query += &format!(" LIMIT ?{idx}");
        params.push(Box::new(l));
    }

    let mut stmt = con.prepare(&query)?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |r| {
        Ok(Row {
            from_mid: r.get(0)?,
            created_ms: r.get(1)?,
            text: r.get(2)?,
        })
    })?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}
