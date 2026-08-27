use crate::crypto;
use crate::discover;
use crate::extract;
use crate::generic::{query_table, Filter};
use crate::schema;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub line: LineConfig,
    #[serde(default)]
    pub chats: Vec<ChatSourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LineConfig {
    pub edb: Option<PathBuf>,
    pub key: Option<String>,
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSourceConfig {
    pub group: Option<String>,
    pub contact: Option<String>,
    #[serde(alias = "chatId")]
    pub chat_id: Option<String>,
    pub sender: Option<String>,
    #[serde(alias = "senderId")]
    pub sender_id: Option<String>,
    pub since: Option<String>,
}

pub fn parse_config_files(paths: &[PathBuf]) -> Result<Vec<Config>> {
    let mut configs = Vec::new();
    for p in paths {
        let content = fs::read_to_string(p)
            .with_context(|| format!("failed to read config file '{}'", p.display()))?;
        for doc in serde_yaml::Deserializer::from_str(&content) {
            let cfg = Config::deserialize(doc)
                .with_context(|| format!("failed to parse YAML document in '{}'", p.display()))?;
            configs.push(cfg);
        }
    }
    Ok(configs)
}

pub fn find_default_config_path() -> Option<PathBuf> {
    for candidate in &["config.yml", "config.yaml"] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in &["config.yml", "config.yaml"] {
                let p = dir.join(candidate);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Decrypt database once and run synchronization across all configs/targets.
pub fn run_sync(configs: &[Config]) -> Result<()> {
    if configs.is_empty() {
        return Err(anyhow!("no configuration targets provided"));
    }

    // Use connection options from the first config that specifies them, or defaults
    let first_line = configs
        .iter()
        .map(|c| &c.line)
        .find(|l| l.edb.is_some() || l.key.is_some() || l.process_name.is_some())
        .cloned()
        .unwrap_or_default();

    let edb = match first_line.edb {
        Some(p) => p,
        None => discover::discover_edb()?,
    };

    let key = match first_line.key {
        Some(k) => k,
        None => crate::resolve_passphrase(first_line.process_name.as_deref(), None)?,
    };

    let temp_db = std::env::temp_dir().join(format!("line-tool-sync-{}.db", std::process::id()));
    crypto::decrypt_sqlite_file(&edb, &temp_db, &key)?;

    let con = Connection::open(&temp_db)?;
    let schema = schema::load(&con)?;

    let total_configs = configs.len();
    for (ci, config) in configs.iter().enumerate() {
        if total_configs > 1 {
            println!("[*] Processing config {}/{}", ci + 1, total_configs);
        }
        for target in &config.chats {
            if let Err(e) = sync_single_target(&con, &schema, &config.webhook, target) {
                eprintln!("[!] Error syncing chat {:?}: {e}", target);
            }
        }
    }

    let _ = fs::remove_file(&temp_db);
    Ok(())
}

fn sync_single_target(
    con: &Connection,
    schema: &schema::Schema,
    webhook: &WebhookConfig,
    target: &ChatSourceConfig,
) -> Result<()> {
    let chat_id = extract::resolve_chat_id(
        con,
        target.chat_id.as_deref(),
        target.group.as_deref(),
        target.contact.as_deref(),
    )?;

    let sender_id =
        extract::resolve_sender_id(con, target.sender_id.as_deref(), target.sender.as_deref())?;

    let endpoint_url = webhook
        .url
        .replace("{chatId}", &chat_id)
        .replace("{chat_id}", &chat_id);

    println!("[*] Syncing chat_id: {} -> {}", chat_id, endpoint_url);

    // 1. Probe webhook with OPTIONS to determine latest message timestamp
    let probe_since_ms = probe_last_timestamp(&endpoint_url, &webhook.headers);
    let since_ms = probe_since_ms.or_else(|| {
        target.since.as_deref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.timestamp_millis())
                .or_else(|| {
                    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                        .ok()
                        .and_then(|d| d.and_hms_opt(0, 0, 0))
                        .map(|dt| {
                            DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).timestamp_millis()
                        })
                })
        })
    });

    if let Some(ms) = since_ms {
        println!(
            "    Syncing messages since: {} ({} ms)",
            DateTime::<Utc>::from_timestamp_millis(ms).unwrap_or_default(),
            ms
        );
    } else {
        println!("    No prior sync date found. Extracting all available messages...");
    }

    // 2. Query messages from SQLite
    let mut filters = vec![Filter {
        field: "chatId".to_string(),
        op: "=".to_string(),
        value: chat_id.clone(),
    }];

    if let Some(sid) = sender_id {
        filters.push(Filter {
            field: "from".to_string(),
            op: "=".to_string(),
            value: sid,
        });
    }

    if let Some(ms) = since_ms {
        filters.push(Filter {
            field: "createdTime".to_string(),
            op: ">=".to_string(),
            value: ms.to_string(),
        });
    }

    let reserved = vec![("sort", "createdTime")];
    let result = query_table(con, schema, "message", &filters, &reserved)?;

    if result.rows.is_empty() {
        println!("    No new messages to push.");
        return Ok(());
    }

    println!(
        "    Extracted {} messages. Posting to webhook...",
        result.rows.len()
    );

    // 3. POST JSON array to webhook
    let payload = Value::Array(result.rows.into_iter().map(Value::Object).collect());
    post_payload(&endpoint_url, &webhook.headers, &payload)?;

    println!("    Sync complete for chat {}.", chat_id);
    Ok(())
}

fn probe_last_timestamp(url: &str, headers: &HashMap<String, String>) -> Option<i64> {
    let mut req = ureq::request("OPTIONS", url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let resp = req.call().ok()?;

    if let Some(raw_header) = resp.header("Last-Modified") {
        if let Ok(dt) = DateTime::parse_from_rfc2822(raw_header) {
            return Some(dt.timestamp_millis());
        }
    }
    None
}

fn post_payload(url: &str, headers: &HashMap<String, String>, payload: &Value) -> Result<()> {
    let mut req = ureq::post(url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let resp = req
        .send_json(payload)
        .with_context(|| format!("failed to send POST payload to '{}'", url))?;

    if resp.status() >= 400 {
        return Err(anyhow!("webhook returned error HTTP {}", resp.status()));
    }
    Ok(())
}
