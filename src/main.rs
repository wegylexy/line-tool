mod crypto;
mod discover;
mod extract;
mod findkey;
mod generic;
mod openapi;
mod procmem;
mod schema;
mod server;
mod sync;

use anyhow::{anyhow, Result};
use chrono::{Local, TimeZone};
use clap::{Parser, Subcommand};
use rusqlite::Connection;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "line-tool",
    about = "LINE encrypted-db passphrase finder & message extractor",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,

    /// Positional config YAML files (supports Explorer drag-and-drop or default config.yml)
    #[arg(value_name = "CONFIG_FILES")]
    config_files: Vec<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Find the LINE encryption passphrase by scanning a live process's memory
    #[command(alias = "extract-passphrase")]
    FindKey {
        /// Process image name, e.g. LINE.exe
        #[arg(long, default_value = "LINE.exe")]
        process_name: String,
        /// Attach by PID instead of by name
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Decrypt the .edb and extract messages for a chat/sender/date
    Extract {
        #[arg(long)]
        edb: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
        /// Scan this live process's memory for the passphrase instead of --passphrase
        #[arg(long)]
        process_name: Option<String>,
        #[arg(long)]
        pid: Option<u32>,

        /// Exact chat mid (group or contact)
        #[arg(long = "chat-id")]
        chat_id: Option<String>,
        /// Group chat name (substring match)
        #[arg(long)]
        group: Option<String>,
        /// Contact name (substring match)
        #[arg(long)]
        contact: Option<String>,

        /// Message sender's display name (substring match)
        #[arg(long)]
        sender: Option<String>,
        #[arg(long = "sender-id")]
        sender_id: Option<String>,

        #[arg(long)]
        date: Option<String>,
        #[arg(long)]
        start: Option<String>,
        #[arg(long)]
        end: Option<String>,
        #[arg(long)]
        limit: Option<i64>,

        /// Print candidate group/contact mids for NAME instead of extracting
        #[arg(long)]
        lookup: Option<String>,
    },
    /// Decrypt the .edb once and serve a REST API for lookups/message queries
    Serve {
        #[arg(long)]
        edb: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        process_name: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value_t = 5463)]
        port: u16,
    },
    /// Inspect the database schema and generate an OpenAPI 3.1 JSON specification
    Openapi {
        #[arg(long)]
        edb: Option<PathBuf>,
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        process_name: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Sync messages to a webhook endpoint using config YAML files
    Sync {
        #[arg(value_name = "CONFIG_FILES")]
        config_files: Vec<PathBuf>,
    },
}

pub fn resolve_passphrase(process_name: Option<&str>, pid: Option<u32>) -> Result<String> {
    let target_pid = match pid {
        Some(p) => p,
        None => procmem::find_pid_by_name(process_name.unwrap_or("LINE.exe"))?,
    };
    eprintln!("[*] Scanning process memory of PID {target_pid} ...");

    let mut candidates = std::collections::BTreeSet::new();
    let mut prev_tail: Vec<u8> = Vec::new();
    procmem::scan_process_memory(target_pid, |chunk| {
        let mut buf = Vec::with_capacity(prev_tail.len() + chunk.len());
        buf.extend_from_slice(&prev_tail);
        buf.extend_from_slice(chunk);
        for c in findkey::scan_buffer(&buf) {
            candidates.insert(c);
        }
        let keep = 256.min(chunk.len());
        prev_tail.clear();
        prev_tail.extend_from_slice(&chunk[chunk.len() - keep..]);
    })?;

    if candidates.is_empty() {
        return Err(anyhow!("no passphrase candidates found in process memory"));
    }

    let edb_path = discover::discover_edb()?;
    eprintln!(
        "[*] Found {} candidates, testing against {} ...",
        candidates.len(),
        edb_path.display()
    );

    for cand in candidates {
        if crypto::test_decrypt_key(&edb_path, &cand) {
            return Ok(cand);
        }
    }
    Err(anyhow!(
        "none of the memory candidates decrypted the first database page"
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        None => {
            // Drag-and-drop or zero-arg default sync
            let paths = if !cli.config_files.is_empty() {
                cli.config_files
            } else if let Some(default_cfg) = sync::find_default_config_path() {
                println!("[*] Using default config: {}", default_cfg.display());
                vec![default_cfg]
            } else {
                return Err(anyhow!(
                    "no config files provided and no config.yml / config.yaml found in current directory.\nRun 'line-tool --help' for usage."
                ));
            };
            let configs = sync::parse_config_files(&paths)?;
            sync::run_sync(&configs)?;
        }
        Some(Command::Sync { config_files }) => {
            let paths = if !config_files.is_empty() {
                config_files
            } else if let Some(default_cfg) = sync::find_default_config_path() {
                println!("[*] Using default config: {}", default_cfg.display());
                vec![default_cfg]
            } else {
                return Err(anyhow!(
                    "no config files provided and no config.yml / config.yaml found in current directory."
                ));
            };
            let configs = sync::parse_config_files(&paths)?;
            sync::run_sync(&configs)?;
        }
        Some(Command::FindKey { process_name, pid }) => {
            let key = resolve_passphrase(Some(&process_name), pid)?;
            println!("{key}");
        }
        Some(Command::Extract {
            edb,
            passphrase,
            process_name,
            pid,
            chat_id,
            group,
            contact,
            sender,
            sender_id,
            date,
            start,
            end,
            limit,
            lookup,
        }) => {
            let edb = match edb {
                Some(p) => p,
                None => {
                    let found = discover::discover_edb()?;
                    eprintln!("[*] Auto-discovered edb: {}", found.display());
                    found
                }
            };

            let resolved_passphrase = match &passphrase {
                Some(p) => p.clone(),
                None => resolve_passphrase(process_name.as_deref(), pid)?,
            };

            let tmp_db =
                std::env::temp_dir().join(format!("line-tool-extract-{}.db", std::process::id()));
            crypto::decrypt_sqlite_file(&edb, &tmp_db, &resolved_passphrase)?;
            let con = Connection::open(&tmp_db)?;

            if let Some(query) = lookup {
                let groups = extract::lookup_group_candidates(&con, &query)?;
                let contacts = extract::lookup_contact_candidates(&con, &query)?;
                let _ = std::fs::remove_file(&tmp_db);

                if groups.is_empty() && contacts.is_empty() {
                    println!("[!] No groups or contacts matching '{query}'.");
                    return Ok(());
                }
                if !groups.is_empty() {
                    println!("Group chats:");
                    for (mid, name) in groups {
                        println!("  {mid}  {name}");
                    }
                }
                if !contacts.is_empty() {
                    println!("Contacts:");
                    for (mid, name) in contacts {
                        println!("  {mid}  {name}");
                    }
                }
                return Ok(());
            }

            let chat_id = extract::resolve_chat_id(
                &con,
                chat_id.as_deref(),
                group.as_deref(),
                contact.as_deref(),
            )?;
            let sender_id =
                extract::resolve_sender_id(&con, sender_id.as_deref(), sender.as_deref())?;

            let (start_ms, end_ms) = if let Some(d) = date {
                (
                    Some(extract::to_epoch_ms(&d, false)?),
                    Some(extract::to_epoch_ms(&d, true)?),
                )
            } else if start.is_some() || end.is_some() {
                (
                    start.map(|s| extract::to_epoch_ms(&s, false)).transpose()?,
                    end.map(|e| extract::to_epoch_ms(&e, true)).transpose()?,
                )
            } else {
                let today = extract::today_local_date();
                (
                    Some(extract::to_epoch_ms(&today, false)?),
                    Some(extract::to_epoch_ms(&today, true)?),
                )
            };

            let rows = extract::extract(
                &con,
                &chat_id,
                sender_id.as_deref(),
                start_ms,
                end_ms,
                limit,
                false,
                None,
            )?;
            let _ = std::fs::remove_file(&tmp_db);

            if rows.is_empty() {
                println!("[!] No messages found matching the given filters.");
                return Ok(());
            }
            for row in rows {
                let dt = Local.timestamp_millis_opt(row.created_ms).single().unwrap();
                println!(
                    "[{}] {}: {}",
                    dt.to_rfc3339(),
                    row.from_mid,
                    row.text.unwrap_or_default()
                );
            }
        }
        Some(Command::Serve {
            edb,
            passphrase,
            process_name,
            pid,
            addr,
            port,
        }) => {
            let edb = match edb {
                Some(p) => p,
                None => {
                    let found = discover::discover_edb()?;
                    eprintln!("[*] Auto-discovered edb: {}", found.display());
                    found
                }
            };

            let resolved_passphrase = match &passphrase {
                Some(p) => p.clone(),
                None => resolve_passphrase(process_name.as_deref(), pid)?,
            };

            let tmp_db = std::env::temp_dir().join("line-tool-server.db");
            crypto::decrypt_sqlite_file(&edb, &tmp_db, &resolved_passphrase)?;
            let con = Connection::open(&tmp_db)?;
            let schema = schema::load(&con)?;
            let last_mtime = std::fs::metadata(&edb)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now());

            let config = server::ServerConfig {
                edb_path: edb,
                tmp_db_path: tmp_db,
                passphrase: resolved_passphrase,
                process_name,
                pid,
            };

            let addrs = match addr {
                Some(a) => vec![a],
                None => vec![format!("127.0.0.1:{port}"), format!("[::1]:{port}")],
            };
            server::run(&addrs, config, last_mtime, con, schema)?;
        }
        Some(Command::Openapi {
            edb,
            passphrase,
            process_name,
            pid,
        }) => {
            let edb = match edb {
                Some(p) => p,
                None => {
                    let found = discover::discover_edb()?;
                    eprintln!("[*] Auto-discovered edb: {}", found.display());
                    found
                }
            };

            let resolved_passphrase = match &passphrase {
                Some(p) => p.clone(),
                None => resolve_passphrase(process_name.as_deref(), pid)?,
            };

            let tmp_db =
                std::env::temp_dir().join(format!("line-tool-openapi-{}.db", std::process::id()));
            crypto::decrypt_sqlite_file(&edb, &tmp_db, &resolved_passphrase)?;
            let con = Connection::open(&tmp_db)?;
            let schema = schema::load(&con)?;
            let spec = openapi::generate_openapi_spec(&schema);
            let _ = std::fs::remove_file(&tmp_db);

            println!("{}", serde_json::to_string_pretty(&spec)?);
        }
    }
    Ok(())
}
